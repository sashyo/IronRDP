//! WASM-compatible TLS upgrade for IronRDP.
//!
//! Uses `rustls` with a manual async adapter over `futures_io::AsyncRead + AsyncWrite`,
//! avoiding any dependency on `tokio` runtime. This allows TLS handshakes to run inside
//! a WebAssembly environment where the underlying transport is a WebRTC DataChannel
//! (or any other ordered, reliable byte stream).

use std::io::{self, Read, Write};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_io::{AsyncRead, AsyncWrite};
use futures_util::{AsyncReadExt, AsyncWriteExt};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use x509_cert::der::Decode as _;

/// A TLS stream wrapping a generic async transport.
///
/// Implements `futures_io::AsyncRead + AsyncWrite` so it can be used
/// directly with `ironrdp-futures::FuturesStream` / `LocalFuturesStream`.
pub struct TlsStream<S> {
    tls: ClientConnection,
    inner: S,
    /// Outgoing TLS ciphertext that hasn't been flushed to the wire yet.
    write_buf: Vec<u8>,
    /// Incoming ciphertext that hasn't been fed to rustls yet.
    read_buf: Vec<u8>,
}

impl<S> TlsStream<S> {
    /// Access the underlying rustls `ClientConnection`.
    pub fn tls_connection(&self) -> &ClientConnection {
        &self.tls
    }
}

/// Perform a TLS upgrade on the given stream.
///
/// This is the WASM-compatible equivalent of `ironrdp_tls::upgrade`.
/// The stream `S` can be any ordered, reliable byte channel — typically a
/// WebRTC DataChannel wrapped as `AsyncRead + AsyncWrite`.
///
/// Returns the TLS-wrapped stream and the server's x509 certificate.
pub async fn upgrade<S>(mut stream: S, server_name: &str) -> io::Result<(TlsStream<S>, x509_cert::Certificate)>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();

    // Disable TLS resumption — CredSSP does not support it.
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c
    config.resumption = rustls::client::Resumption::disabled();

    let domain = ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?;
    let mut tls = ClientConnection::new(Arc::new(config), domain).map_err(io::Error::other)?;

    // Drive the TLS handshake to completion over the async stream.
    handshake(&mut tls, &mut stream).await?;

    // Extract server certificate.
    let tls_cert = {
        let cert = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| io::Error::other("peer certificate is missing"))?;

        x509_cert::Certificate::from_der(cert).map_err(io::Error::other)?
    };

    Ok((TlsStream { tls, inner: stream, write_buf: Vec::new(), read_buf: Vec::new() }, tls_cert))
}

/// Drive the rustls handshake to completion over an async stream.
async fn handshake<S>(tls: &mut ClientConnection, stream: &mut S) -> io::Result<()>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    let mut read_buf = vec![0u8; 16384];

    while tls.is_handshaking() {
        // Write any pending TLS records to the wire.
        while tls.wants_write() {
            let mut outgoing = Vec::new();
            tls.write_tls(&mut outgoing)?;
            if !outgoing.is_empty() {
                stream.write_all(&outgoing).await?;
                stream.flush().await?;
            }
        }

        // If TLS wants to read, pull bytes from the wire.
        if tls.wants_read() {
            let n = stream.read(&mut read_buf).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream closed during TLS handshake",
                ));
            }
            // Feed all received bytes to rustls — may need multiple read_tls calls
            let mut consumed = 0;
            while consumed < n {
                let used = tls.read_tls(&mut &read_buf[consumed..n])?;
                if used == 0 {
                    break;
                }
                consumed += used;
            }
            tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
    }

    Ok(())
}

// ── AsyncRead / AsyncWrite for TlsStream ─────────────────────────

impl<S> AsyncRead for TlsStream<S>
where
    S: Unpin + AsyncRead,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // First, try to read already-decrypted data from rustls.
        match this.tls.reader().read(buf) {
            Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Poll::Ready(Err(e)),
            _ => {}
        }

        // Feed any buffered ciphertext to rustls first
        if !this.read_buf.is_empty() {
            let used = this.tls.read_tls(&mut this.read_buf.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            this.read_buf.drain(..used);

            this.tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            if this.tls.wants_write() {
                let _ = this.tls.write_tls(&mut this.write_buf);
            }

            match this.tls.reader().read(buf) {
                Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
                _ => {}
            }
        }

        // Need more ciphertext from the wire.
        let mut tmp = [0u8; 16384];
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(n)) => {
                // Feed to rustls
                let used = this.tls.read_tls(&mut &tmp[..n])
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                // Buffer any unconsumed bytes for next call
                if used < n {
                    this.read_buf.extend_from_slice(&tmp[used..n]);
                }

                this.tls.process_new_packets()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                if this.tls.wants_write() {
                    let _ = this.tls.write_tls(&mut this.write_buf);
                }

                match this.tls.reader().read(buf) {
                    Ok(n) if n > 0 => Poll::Ready(Ok(n)),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                    _ => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S> AsyncWrite for TlsStream<S>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // First, flush any buffered outgoing TLS data
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Write plaintext into rustls.
        let n = this.tls.writer().write(buf)?;

        // Collect TLS ciphertext into buffer
        this.tls
            .write_tls(&mut this.write_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Try to write as much as possible
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(written)) => {
                    this.write_buf.drain(..written);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break, // will flush on next poll_write or poll_flush
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Collect any remaining TLS output
        this.tls
            .write_tls(&mut this.write_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Flush all buffered data
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.tls.send_close_notify();

        let _ = this.tls.write_tls(&mut this.write_buf);
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => {
                    this.write_buf.drain(..n);
                }
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }

        Pin::new(&mut this.inner).poll_close(cx)
    }
}

pub fn extract_tls_server_public_key(cert: &x509_cert::Certificate) -> Option<&[u8]> {
    cert.tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
}

mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types;
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}
