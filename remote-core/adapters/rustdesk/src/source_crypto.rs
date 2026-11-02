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

/// Maximum plaintext size; ciphertext adds secretbox's authentication tag.
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024 - secretbox::MACBYTES;

/// Message encryption state over an existing ordered binary network transport.
/// The underlying transport must enforce its own ciphertext/frame allocation
/// cap and close on interrupted I/O. This wrapper rejects the source's short
/// plaintext keepalive bypass while encrypted and closes on auth/counter errors.
pub struct EncryptedTransport<T: NetworkTransport> {
    inner: T,
    cipher: Option<Encrypt>,
    max_plaintext: usize,
}
impl<T: NetworkTransport> EncryptedTransport<T> {
    fn new(inner: T, cipher: Encrypt, max_plaintext: usize) -> Self {
        Self { inner, cipher: Some(cipher), max_plaintext }
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
            match self.inner.send(&encrypted, deadline).await {
                Ok(()) => { self.cipher = Some(cipher); Ok(()) },
                Err(_) => { self.inner.close(); Err(NetworkTransportError::SendOutcomeUnknown("encrypted send failed".into())) },
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
            let encrypted = match self.inner.receive(deadline).await {
                Ok(bytes) => bytes,
                Err(_) => { self.inner.close(); return Err(NetworkTransportError::ReceiveFailed("encrypted receive failed".into())); },
            };
            if encrypted.len() < secretbox::MACBYTES || encrypted.len() > self.max_plaintext + secretbox::MACBYTES {
                self.inner.close(); return Err(NetworkTransportError::ReceiveFailed("invalid ciphertext length".into()));
            }
            let mut bytes = BytesMut::from(&encrypted[..]);
            if cipher.dec(&mut bytes).is_err() {
                self.inner.close(); return Err(NetworkTransportError::ReceiveFailed("ciphertext authentication failed".into()));
            }
            self.cipher = Some(cipher);
            Ok(bytes.to_vec().into_boxed_slice())
        })
    }
    fn close(&mut self) { self.cipher.take(); self.inner.close(); }
}
impl<T: NetworkTransport> Drop for EncryptedTransport<T> {
    fn drop(&mut self) { self.close(); }
}
