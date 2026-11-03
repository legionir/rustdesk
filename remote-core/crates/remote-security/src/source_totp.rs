//! Optional reuse of RustDesk's `totp-rs` verifier with the source SHA-1,
//! 30-second step and one-step skew. This is not integrated with login and
//! does not provide enrollment, secret storage, replay protection, shared
//! rate-limiting, trusted devices or channel binding. Call only with a locally
//! provisioned secret; this code is unbuilt, untested and not audited.
use std::{error::Error, fmt, time::{SystemTime, UNIX_EPOCH}};
use totp_rs::{Algorithm, TOTP};
use zeroize::Zeroize;

const MIN_SECRET_BYTES: usize = 16;
const MAX_SECRET_BYTES: usize = 1024;
// The source library's skew subtraction can underflow near the Unix epoch;
// this also keeps its step arithmetic within a locally bounded date range.
const MIN_TIME: u64 = 30;
const MAX_TIME: u64 = 253_402_300_799;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError { InvalidConfiguration, ClockUnavailable }
impl fmt::Display for TotpError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "source TOTP: {self:?}") } }
impl Error for TotpError {}
/// A single locally configured verifier. Does not expose Debug or Clone; source
/// `TOTP` is Debug + Clone and contains raw secret bytes, so never log it.
/// Drop scrubs its current secret Vec only. Caller copies, library temporaries,
/// memory reallocation, core dumps, swap and abrupt exit are not covered.
pub struct SourceTotp { inner: TOTP }
impl SourceTotp {
    /// Raw secret bytes, not a base32/URL string. Source stores and decrypts
    /// configuration separately, which is deliberately not reproduced here.
    /// Input ownership is transferred; invalid locally rejected input is scrubbed.
    pub fn new(mut secret: Vec<u8>, digits: usize) -> Result<Self, TotpError> {
        if !(MIN_SECRET_BYTES..=MAX_SECRET_BYTES).contains(&secret.len()) || !(6..=8).contains(&digits) {
            secret.zeroize(); return Err(TotpError::InvalidConfiguration);
        }
        // Same parameters as `src/auth_2fa.rs::TOTPInfo::new_totp`; issuer and
        // account metadata are irrelevant for verification. The library owns
        // the Vec after this call, including on an unexpected constructor error.
        TOTP::new(Algorithm::SHA1, digits, 1, 30, secret, None, String::new())
            .map(|inner| Self { inner }).map_err(|_| TotpError::InvalidConfiguration)
    }
    /// Check at a caller-supplied trusted Unix second. Time is not a peer claim;
    /// duplicates inside a skew window can succeed and need external replay
    /// prevention. This function deliberately does not generate or log codes.
    pub fn check_at(&self, code: &str, seconds: u64) -> Result<bool, TotpError> {
        if !(MIN_TIME..=MAX_TIME).contains(&seconds) { return Err(TotpError::ClockUnavailable); }
        if code.len() != self.inner.digits || !code.bytes().all(|b| b.is_ascii_digit()) { return Ok(false); }
        Ok(self.inner.check(code, seconds))
    }
    pub fn check_current(&self, code: &str) -> Result<bool, TotpError> {
        let seconds = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| TotpError::ClockUnavailable)?.as_secs();
        self.check_at(code, seconds)
    }
}
impl Drop for SourceTotp { fn drop(&mut self) { self.inner.secret.zeroize(); } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1_vector_and_local_time_bounds() {
        // Public RFC example secret; never use this secret for real sessions.
        let verifier = SourceTotp::new(b"12345678901234567890".to_vec(), 8).unwrap();
        assert_eq!(verifier.check_at("94287082", 59).unwrap(), true);
        // Source skew of one step accepts the same code in the next window;
        // cross-session replay prevention is deliberately external.
        assert_eq!(verifier.check_at("94287082", 89).unwrap(), true);
        assert_eq!(verifier.check_at("00000000", 59).unwrap(), false);
        assert_eq!(verifier.check_at("9428708x", 59).unwrap(), false);
        assert_eq!(verifier.check_at("94287082", 29), Err(TotpError::ClockUnavailable));
        assert_eq!(verifier.check_at("94287082", MAX_TIME + 1), Err(TotpError::ClockUnavailable));
        assert!(SourceTotp::new(vec![1; 15], 6).is_err());
        assert!(SourceTotp::new(vec![1; 16], 9).is_err());
    }
}
