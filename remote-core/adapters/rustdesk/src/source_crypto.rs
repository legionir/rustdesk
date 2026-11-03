//! Experimental strict version-1 RustDesk message encryption adapter.
//!
//! This uses the pinned `hbb_common::tcp::Encrypt` implementation, not a new
//! wire cipher. Version 0 and plaintext fallback are deliberately rejected.
//! A key by itself does not prove peer identity; construct this only after the
//! source-compatible signed exchange in this module. No production use, security
//! review, interoperability testing or adversarial testing is claimed.

use hbb_common::{bytes::BytesMut, sodiumoxide::crypto::secretbox, tcp::Encrypt};
use remote_transport::{NetworkTransport, NetworkTransportError, TransportFuture};
use std::time::Duration;
use zeroize::Zeroize;

/// Maximum plaintext size; ciphertext adds secretbox's authentication tag.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024 - secretbox::MACBYTES;

/// Message encryption state over an existing ordered binary network transport.
/// The underlying transport must enforce its own ciphertext/frame allocation
/// cap and close on interrupted I/O. This wrapper rejects the source's short
/// plaintext keepalive bypass while encrypted and closes on auth/counter errors.
pub struct EncryptedTransport<T: NetworkTransport> {
    inner: Option<T>,
    cipher: Option<Encrypt>,
    max_plaintext: usize,
}
impl<T: NetworkTransport> EncryptedTransport<T> {
    fn new(inner: T, cipher: Encrypt, max_plaintext: usize) -> Self {
        Self { inner: Some(inner), cipher: Some(cipher), max_plaintext }
    }
}
impl EncryptedTransport<crate::direct_tcp::DirectTcp> {
    /// Consume the existing encrypted TCP stream into an opt-in duplex driver.
    /// This must be done only after authorization and after selecting the final
    /// frame limit. It is not a security review or a production transport.
    pub fn into_experimental_duplex(mut self) -> Result<crate::duplex_tcp::DuplexTcp, NetworkTransportError> {
        let cipher = self.cipher.take().ok_or(NetworkTransportError::Closed)?;
        let inner = self.inner.take().ok_or(NetworkTransportError::Closed)?;
        crate::duplex_tcp::DuplexTcp::start(inner, cipher, self.max_plaintext)
    }
}
impl<T: NetworkTransport> NetworkTransport for EncryptedTransport<T> {
    fn send<'a>(&'a mut self, bytes: &'a [u8], deadline: Duration) -> TransportFuture<'a, Result<(), NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() || bytes.len() > self.max_plaintext {
                return Err(NetworkTransportError::InvalidRequest("invalid deadline or plaintext size".into()));
            }
            if self.cipher.as_ref().ok_or(NetworkTransportError::Closed)?.1 == u64::MAX {
                self.close(); return Err(NetworkTransportError::Closed);
            }
            // Remove state before I/O; cancellation cannot leave reusable nonce
            // state. The inner transport must itself close on interrupted I/O.
            let mut cipher = self.cipher.take().ok_or(NetworkTransportError::Closed)?;
            let encrypted = cipher.enc(bytes);
            match self.inner.as_mut().ok_or(NetworkTransportError::Closed)?.send(&encrypted, deadline).await {
                Ok(()) => { self.cipher = Some(cipher); Ok(()) },
                Err(_) => { if let Some(inner) = self.inner.as_mut() { inner.close(); } Err(NetworkTransportError::SendOutcomeUnknown("encrypted send failed".into())) },
            }
        })
    }
    fn receive(&mut self, deadline: Duration) -> TransportFuture<'_, Result<Box<[u8]>, NetworkTransportError>> {
        Box::pin(async move {
            if deadline.is_zero() { return Err(NetworkTransportError::InvalidRequest("invalid deadline".into())); }
            if self.cipher.as_ref().ok_or(NetworkTransportError::Closed)?.2 == u64::MAX {
                self.close(); return Err(NetworkTransportError::Closed);
            }
            let mut cipher = self.cipher.take().ok_or(NetworkTransportError::Closed)?;
            let encrypted = match self.inner.as_mut().ok_or(NetworkTransportError::Closed)?.receive(deadline).await {
                Ok(bytes) => bytes,
                Err(_) => { if let Some(inner) = self.inner.as_mut() { inner.close(); } return Err(NetworkTransportError::ReceiveFailed("encrypted receive failed".into())); },
            };
            if encrypted.len() < secretbox::MACBYTES || encrypted.len() > self.max_plaintext + secretbox::MACBYTES {
                if let Some(inner) = self.inner.as_mut() { inner.close(); } return Err(NetworkTransportError::ReceiveFailed("invalid ciphertext length".into()));
            }
            let mut bytes = BytesMut::from(&encrypted[..]);
            if cipher.dec(&mut bytes).is_err() {
                if let Some(inner) = self.inner.as_mut() { inner.close(); } return Err(NetworkTransportError::ReceiveFailed("ciphertext authentication failed".into()));
            }
            // The returned copy belongs to the caller; clear this wrapper's
            // visible decrypted buffer after copying. The source cipher uses
            // its own temporary allocation, outside this limited guarantee.
            let plain = bytes.to_vec().into_boxed_slice();
            bytes[..].zeroize();
            self.cipher = Some(cipher);
            Ok(plain)
        })
    }
    fn close(&mut self) { self.cipher.take(); if let Some(mut inner) = self.inner.take() { inner.close(); } }
}
impl<T: NetworkTransport> Drop for EncryptedTransport<T> {
    fn drop(&mut self) { self.close(); }
}

use base::message_proto::{message, Message, PublicKey, SignedId};
use hbb_common::{protobuf::Message as ProtobufMessage, rendezvous_proto::IdPk,
    sodiumoxide::{self, crypto::{box_, sign}}, tcp::{KxTranscript, KX_VERSION_LATEST}};
use std::{error::Error, fmt, time::Instant};

const HANDSHAKE_LIMIT: usize = 128 * 1024;
const SIGNED_ID_LIMIT: usize = 4096;

/// A key-exchange failure. No fallback to plaintext or version 0 occurs.
#[derive(Debug)]
pub enum HandshakeError {
    InvalidParameters,
    Deadline,
    InvalidMessage,
    IdentityMismatch,
    SignatureMismatch,
    UnsupportedVersion,
    Crypto,
    Network(NetworkTransportError),
}
impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameters => f.write_str("invalid key exchange parameters"),
            Self::Deadline => f.write_str("key exchange deadline expired"),
            Self::InvalidMessage => f.write_str("invalid key exchange message"),
            Self::IdentityMismatch => f.write_str("signed host identity mismatch"),
            Self::SignatureMismatch => f.write_str("signed host identity verification failed"),
            Self::UnsupportedVersion => f.write_str("peer did not negotiate strict source key exchange version 1"),
            Self::Crypto => f.write_str("source key exchange cryptographic operation failed"),
            Self::Network(error) => write!(f, "key exchange transport: {error}"),
        }
    }
}
impl Error for HandshakeError {}
impl From<NetworkTransportError> for HandshakeError { fn from(e: NetworkTransportError) -> Self { Self::Network(e) } }

// Ensure even a cancelled handshake closes a transport whose own Drop does not.
struct CloseGuard<T: NetworkTransport>(Option<T>);
impl<T: NetworkTransport> CloseGuard<T> {
    fn inner(&mut self) -> &mut T { self.0.as_mut().expect("handshake transport") }
    fn take(&mut self) -> T { self.0.take().expect("handshake transport") }
}
impl<T: NetworkTransport> Drop for CloseGuard<T> {
    fn drop(&mut self) { if let Some(inner) = self.0.as_mut() { inner.close(); } }
}
fn validate(host_id: &str, max_plaintext: usize, deadline: Duration) -> Result<Instant, HandshakeError> {
    if host_id.is_empty() || host_id.len() > 256 || host_id.chars().any(char::is_control)
        || max_plaintext == 0 || max_plaintext > MAX_PLAINTEXT_BYTES
        || deadline.is_zero() || deadline > Duration::from_secs(180) {
        return Err(HandshakeError::InvalidParameters);
    }
    Instant::now().checked_add(deadline).ok_or(HandshakeError::InvalidParameters)
}
fn remaining(end: Instant) -> Result<Duration, HandshakeError> {
    let duration = end.saturating_duration_since(Instant::now());
    if duration.is_zero() { Err(HandshakeError::Deadline) } else { Ok(duration) }
}
fn parse(bytes: &[u8]) -> Result<Message, HandshakeError> {
    if bytes.len() > HANDSHAKE_LIMIT { return Err(HandshakeError::InvalidMessage); }
    Message::parse_from_bytes(bytes).map_err(|_| HandshakeError::InvalidMessage)
}
fn serialize(message: &Message) -> Result<Vec<u8>, HandshakeError> {
    if message.compute_size() > HANDSHAKE_LIMIT as u64 { return Err(HandshakeError::InvalidMessage); }
    message.write_to_bytes().map_err(|_| HandshakeError::InvalidMessage)
}

/// Host side of the source signed ephemeral-key exchange, with strict v1 only.
///
/// `signing_key` and `host_id` must be provisioned securely and the viewer must
/// independently possess the matching trusted public key and expected ID. The
/// host does not authenticate the viewer here: password/owner approval and
/// rate-limiting are separate. The input transport must accept handshake frames
/// up to 128 KiB and encrypted frames up to `max_plaintext + MACBYTES`; configure
/// a lower pre-auth bound at the actual framing layer where feasible. Any error
/// or cancellation closes the owned stream. No WebRTC fingerprint binding,
/// rendezvous-signed identity chain or legacy-v0 negotiation is implemented.
pub async fn accept_pinned_host<T: NetworkTransport>(transport: T, host_id: &str, signing_key: &sign::SecretKey, max_plaintext: usize, deadline: Duration) -> Result<EncryptedTransport<T>, HandshakeError> {
    let mut guard = CloseGuard(Some(transport));
    let end = validate(host_id, max_plaintext, deadline)?;
    sodiumoxide::init().map_err(|_| HandshakeError::Crypto)?;
    if KX_VERSION_LATEST != 1 { return Err(HandshakeError::UnsupportedVersion); }
    let (responder_pk, responder_sk) = box_::gen_keypair();
    let identity = IdPk { id: host_id.to_owned(), pk: responder_pk.0.to_vec().into(),
        dtls_fingerprint: String::new(), kx_version: 1, ..Default::default() };
    let identity = identity.write_to_bytes().map_err(|_| HandshakeError::Crypto)?;
    let signed = sign::sign(&identity, signing_key);
    if signed.len() > SIGNED_ID_LIMIT { return Err(HandshakeError::InvalidMessage); }
    let mut envelope = Message::new(); envelope.set_signed_id(SignedId { id: signed.into(), ..Default::default() });
    guard.inner().send(&serialize(&envelope)?, remaining(end)?).await?;
    let response = guard.inner().receive(remaining(end)?).await?;
    let envelope = parse(&response)?;
    let key = match envelope.union { Some(message::Union::PublicKey(key)) => key, _ => return Err(HandshakeError::InvalidMessage) };
    if key.kx_version != 1 || key.asymmetric_value.len() != box_::PUBLICKEYBYTES
        || key.symmetric_value.len() != secretbox::KEYBYTES + box_::MACBYTES { return Err(HandshakeError::InvalidMessage); }
    let shared = Encrypt::decode(&key.symmetric_value, &key.asymmetric_value, &responder_sk).map_err(|_| HandshakeError::Crypto)?;
    let cipher = Encrypt::new_split(shared, false, &KxTranscript {
        initiator_pk: &key.asymmetric_value, responder_pk: &responder_pk.0, advertised: 1, picked: 1,
    }).map_err(|_| HandshakeError::Crypto)?;
    Ok(EncryptedTransport::new(guard.take(), cipher, max_plaintext))
}

/// Viewer side: verify source SignedId against an explicitly pinned host
/// signing public key and exact host ID, then send the original source PublicKey
/// message and enable split direction keys. A malicious relay cannot replace the
/// host key without failing the pin, but can deny service or observe metadata.
/// The host signing key's distribution, revocation, trust and uniqueness are the
/// caller's responsibility. The signed handshake does not authenticate the
/// viewer to the host. No password, consent, 2FA, or durable replay state is
/// provided. Version-0/unsigned/fallback cases fail closed rather than matching
/// the source's permissive legacy fallback. Untested and not audited.
pub async fn connect_pinned_host<T: NetworkTransport>(transport: T, expected_host_id: &str, pinned_key: &sign::PublicKey, max_plaintext: usize, deadline: Duration) -> Result<EncryptedTransport<T>, HandshakeError> {
    let mut guard = CloseGuard(Some(transport));
    let end = validate(expected_host_id, max_plaintext, deadline)?;
    sodiumoxide::init().map_err(|_| HandshakeError::Crypto)?;
    if KX_VERSION_LATEST != 1 { return Err(HandshakeError::UnsupportedVersion); }
    let raw = guard.inner().receive(remaining(end)?).await?;
    let envelope = parse(&raw)?;
    let signed = match envelope.union { Some(message::Union::SignedId(signed)) => signed.id, _ => return Err(HandshakeError::InvalidMessage) };
    if signed.is_empty() || signed.len() > SIGNED_ID_LIMIT { return Err(HandshakeError::InvalidMessage); }
    let verified = sign::verify(&signed, pinned_key).map_err(|_| HandshakeError::SignatureMismatch)?;
    let identity = IdPk::parse_from_bytes(&verified).map_err(|_| HandshakeError::InvalidMessage)?;
    if identity.id != expected_host_id { return Err(HandshakeError::IdentityMismatch); }
    if identity.kx_version != 1 { return Err(HandshakeError::UnsupportedVersion); }
    // This adapter is for framed TCP/WS streams, not a WebRTC DTLS channel.
    if !identity.dtls_fingerprint.is_empty() || identity.pk.len() != box_::PUBLICKEYBYTES { return Err(HandshakeError::InvalidMessage); }
    let responder_pk = box_::PublicKey::from_slice(&identity.pk).ok_or(HandshakeError::InvalidMessage)?;
    let (initiator_pk, initiator_sk) = box_::gen_keypair();
    let shared = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed = box_::seal(&shared.0, &nonce, &responder_pk, &initiator_sk);
    let mut envelope = Message::new();
    envelope.set_public_key(PublicKey { asymmetric_value: initiator_pk.0.to_vec().into(), symmetric_value: sealed.into(), kx_version: 1, ..Default::default() });
    let cipher = Encrypt::new_split(shared, true, &KxTranscript {
        initiator_pk: &initiator_pk.0, responder_pk: &responder_pk.0, advertised: 1, picked: 1,
    }).map_err(|_| HandshakeError::Crypto)?;
    guard.inner().send(&serialize(&envelope)?, remaining(end)?).await?;
    Ok(EncryptedTransport::new(guard.take(), cipher, max_plaintext))
}

impl<T: remote_transport::AdjustableNetworkTransport> remote_transport::AdjustableNetworkTransport for EncryptedTransport<T> {
    fn set_max_message_size(&mut self, maximum: usize) -> Result<(), NetworkTransportError> {
        if self.cipher.is_none() { return Err(NetworkTransportError::Closed); }
        if maximum == 0 || maximum > MAX_PLAINTEXT_BYTES {
            return Err(NetworkTransportError::InvalidRequest("invalid encrypted plaintext limit".into()));
        }
        // The underlying framed size must include the source secretbox tag.
        self.inner.as_mut().ok_or(NetworkTransportError::Closed)?.set_max_message_size(maximum + secretbox::MACBYTES)?;
        self.max_plaintext = maximum;
        Ok(())
    }
}
