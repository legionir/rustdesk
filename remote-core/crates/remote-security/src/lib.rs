//! Experimental compatibility adapter for RustDesk's password challenge.
//!
//! RustDesk computes `SHA256(SHA256(password || salt) || challenge)`. This
//! compatibility scheme is not a modern password-authenticated key exchange:
//! intercepted transcripts permit offline password guessing, and it does not
//! authenticate the server or cryptographically bind itself to a TLS channel.
//! Use only with strong credentials over a separately authenticated, encrypted
//! channel. This crate is not audited and does not implement TLS, rate limiting,
//! persistent replay defense, token management, 2FA, or owner-consent UI.

use remote_session::{Authenticator, Authorizer, Credential, Permissions, Principal, SessionId};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, time::{Duration, Instant}};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Maximum input password length, measured in UTF-8 bytes.
pub const MAX_PASSWORD_BYTES: usize = 1024;
/// Maximum salt length, measured in UTF-8 bytes.
pub const MAX_SALT_BYTES: usize = 256;
/// Maximum number of seconds for a challenge's local validity.
pub const MAX_CHALLENGE_LIFETIME_SECS: u64 = 300;

/// Authentication configuration or randomness failure.
#[derive(Debug)]
pub enum SecurityError {
    /// Password, salt, or challenge data is empty or too long.
    InvalidInput,
    /// Challenge validity period is zero or exceeds the configured ceiling.
    InvalidLifetime,
    /// Operating system random number generation failed.
    RandomUnavailable,
}
impl fmt::Display for SecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => f.write_str("invalid password challenge input"),
            Self::InvalidLifetime => f.write_str("invalid challenge lifetime"),
            Self::RandomUnavailable => f.write_str("secure randomness unavailable"),
        }
    }
}
impl Error for SecurityError {}

/// Public salt and challenge fields for a RustDesk `Hash` message.
/// A challenge is bound to one verifier instance, not to a TLS channel.
#[derive(Clone, Debug)]
pub struct PasswordChallenge {
    /// Salt used by the password's first SHA-256 operation.
    pub salt: String,
    /// Random challenge string used by the second SHA-256 operation.
    pub challenge: String,
}

/// One-time password response. It is never formatted or logged by this crate.
pub struct PasswordResponse(Zeroizing<[u8; 32]>);
impl PasswordResponse {
    /// Borrow the response bytes for a RustDesk login message.
    pub fn as_bytes(&self) -> &[u8] { &self.0[..] }
}

fn validate_password(password: &str) -> Result<(), SecurityError> {
    if password.is_empty() || password.len() > MAX_PASSWORD_BYTES { Err(SecurityError::InvalidInput) } else { Ok(()) }
}
fn validate_public_fields(challenge: &PasswordChallenge) -> Result<(), SecurityError> {
    if challenge.salt.is_empty() || challenge.salt.len() > MAX_SALT_BYTES
        || challenge.challenge.is_empty() || challenge.challenge.len() > 256 {
        Err(SecurityError::InvalidInput)
    } else { Ok(()) }
}
fn first_hash(password: &str, salt: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt.as_bytes());
    Zeroizing::new(hasher.finalize().into())
}
fn second_hash(h1: &[u8; 32], challenge: &str) -> Zeroizing<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(h1);
    hasher.update(challenge.as_bytes());
    Zeroizing::new(hasher.finalize().into())
}

/// Compute the source-compatible response to a host's password challenge.
///
/// The result must travel only over a separately authenticated encrypted
/// transport. Neither the plaintext password nor the intermediate hash is
/// retained by this function. Internal hash implementation temporaries are
/// outside this crate's zeroization guarantees.
pub fn password_response(password: &str, challenge: &PasswordChallenge) -> Result<PasswordResponse, SecurityError> {
    validate_password(password)?;
    validate_public_fields(challenge)?;
    let h1 = first_hash(password, &challenge.salt);
    Ok(PasswordResponse(second_hash(&h1, &challenge.challenge)))
}

/// A single-use, expiring verifier for one externally identified session.
///
/// Successful password verification is only the first step: owner authorization
/// must still be granted by the session's `Authorizer`. Password guessing and
/// concurrent connection limits must be enforced by the surrounding service.
pub struct PasswordVerifier {
    session: SessionId,
    principal: Principal,
    challenge: PasswordChallenge,
    expected_h1: Zeroizing<[u8; 32]>,
    expires: Instant,
    used: bool,
}
impl PasswordVerifier {
    /// Create a verifier with a cryptographically random, single-use challenge.
    ///
    /// The salt must be the same salt as used for the selected password. The
    /// caller must securely provision password and bind the session to the
    /// authenticated transport; this constructor does not do either.
    pub fn new(session: SessionId, principal: Principal, password: &str, salt: &str, lifetime: Duration) -> Result<Self, SecurityError> {
        validate_password(password)?;
        if salt.is_empty() || salt.len() > MAX_SALT_BYTES { return Err(SecurityError::InvalidInput); }
        if lifetime.is_zero() || lifetime > Duration::from_secs(MAX_CHALLENGE_LIFETIME_SECS) { return Err(SecurityError::InvalidLifetime); }
        let mut nonce = [0u8; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| SecurityError::RandomUnavailable)?;
        let mut challenge = String::with_capacity(64);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in nonce { challenge.push(HEX[(byte >> 4) as usize] as char); challenge.push(HEX[(byte & 15) as usize] as char); }
        nonce.zeroize();
        let expires = Instant::now().checked_add(lifetime).ok_or(SecurityError::InvalidLifetime)?;
        Ok(Self {
            session, principal, challenge: PasswordChallenge { salt: salt.to_owned(), challenge },
            expected_h1: first_hash(password, salt), expires, used: false,
        })
    }
    /// Return the public challenge for transmission to the viewer.
    pub fn challenge(&self) -> &PasswordChallenge { &self.challenge }
}
impl Authenticator for PasswordVerifier {
    fn authenticate(&mut self, session: SessionId, evidence: Credential<'_>) -> Result<Option<Principal>, Box<dyn Error + Send + Sync>> {
        if self.used { return Ok(None); }
        // Every attempt consumes the challenge, including malformed and expired
        // evidence. A fresh challenge is required for any subsequent attempt.
        self.used = true;
        if session != self.session || Instant::now() >= self.expires || evidence.as_bytes().len() != 32 { return Ok(None); }
        let expected = second_hash(&self.expected_h1, &self.challenge.challenge);
        if bool::from(expected[..].ct_eq(evidence.as_bytes())) { Ok(Some(self.principal.clone())) } else { Ok(None) }
    }
}

/// One-shot policy decision recorded by the embedding application's owner UI.
///
/// This is not a UI or proof that a human actually approved the connection.
/// Construct it only after a trusted local owner has made the decision.
pub struct OwnerApproval {
    session: SessionId,
    principal: Principal,
    granted: Option<Permissions>,
}
impl OwnerApproval {
    /// Record an approval or refusal for exactly one session and principal.
    pub fn new(session: SessionId, principal: Principal, granted: Option<Permissions>) -> Self {
        Self { session, principal, granted }
    }
}
impl Authorizer for OwnerApproval {
    fn authorize(&mut self, session: SessionId, principal: &Principal, _requested: Permissions) -> Result<Option<Permissions>, Box<dyn Error + Send + Sync>> {
        // Consume the decision even if it was presented for the wrong context.
        let decision = self.granted.take();
        if session != self.session || principal != &self.principal { return Ok(None); }
        Ok(decision)
    }
}
