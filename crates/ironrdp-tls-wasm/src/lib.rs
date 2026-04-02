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
    /// Incoming ciphertext from the wire not yet consumed by rustls.
    incoming: Vec<u8>,
}

impl<S> TlsStream<S> {
    /// Access the underlying rustls `ClientConnection`.
    pub fn tls_connection(&self) -> &ClientConnection {
        &self.tls
    }

    /// Feed as much of `self.incoming` to rustls as it will accept,
    /// then process the new packets. Returns Ok(()) on success.
    fn feed_incoming(&mut self) -> io::Result<()> {
        while !self.incoming.is_empty() {
            let used = self.tls.read_tls(&mut self.incoming.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            if used == 0 {
                break;
            }
            self.incoming.drain(..used);

            let state = self.tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

            // If rustls needs to send data (alerts, etc), buffer it
            if self.tls.wants_write() {
                let _ = self.tls.write_tls(&mut self.write_buf);
            }

            // If plaintext is available, stop feeding and let caller drain first.
            if state.plaintext_bytes_to_read() > 0 {
                break;
            }
        }
        Ok(())
    }
}

/// Perform a TLS upgrade on the given stream.
pub async fn upgrade<S>(mut stream: S, server_name: &str) -> io::Result<(TlsStream<S>, x509_cert::Certificate)>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();

    // Disable TLS resumption — CredSSP does not support it.
    config.resumption = rustls::client::Resumption::disabled();

    let domain = ServerName::try_from(server_name.to_owned()).map_err(io::Error::other)?;
    let mut tls = ClientConnection::new(Arc::new(config), domain).map_err(io::Error::other)?;

    // Drive the TLS handshake to completion.
    handshake(&mut tls, &mut stream).await?;

    // Extract server certificate.
    let tls_cert = {
        let cert = tls
            .peer_certificates()
            .and_then(|certs| certs.first())
            .ok_or_else(|| io::Error::other("peer certificate is missing"))?;
        x509_cert::Certificate::from_der(cert).map_err(io::Error::other)?
    };

    Ok((
        TlsStream {
            tls,
            inner: stream,
            write_buf: Vec::new(),
            incoming: Vec::new(),
        },
        tls_cert,
    ))
}

/// Drive the rustls handshake to completion over an async stream.
async fn handshake<S>(tls: &mut ClientConnection, stream: &mut S) -> io::Result<()>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    let mut buf = vec![0u8; 16384];

    while tls.is_handshaking() {
        // Flush outgoing TLS data.
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)?;
            if !out.is_empty() {
                stream.write_all(&out).await?;
                stream.flush().await?;
            }
        }

        // Read incoming TLS data.
        if tls.wants_read() {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed during handshake"));
            }
            let mut off = 0;
            while off < n {
                let used = tls.read_tls(&mut &buf[off..n])?;
                if used == 0 { break; }
                off += used;
            }
            tls.process_new_packets()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
    }
    Ok(())
}

// ── AsyncRead for TlsStream ──────────────────────────────────────

impl<S> AsyncRead for TlsStream<S>
where
    S: Unpin + AsyncRead,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Try reading already-decrypted plaintext.
        match this.tls.reader().read(buf) {
            Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Poll::Ready(Err(e)),
            _ => {}
        }

        // 2. Feed any buffered incoming ciphertext.
        if !this.incoming.is_empty() {
            this.feed_incoming()?;
            match this.tls.reader().read(buf) {
                Ok(n) if n > 0 => return Poll::Ready(Ok(n)),
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
                _ => {}
            }
        }

        // 3. Read more ciphertext from the wire.
        let mut tmp = [0u8; 16384];
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(n)) => {
                // Append all received bytes to the incoming buffer.
                this.incoming.extend_from_slice(&tmp[..n]);
                // Feed what we can to rustls.
                this.feed_incoming()?;

                match this.tls.reader().read(buf) {
                    Ok(n) if n > 0 => Poll::Ready(Ok(n)),
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(e) => Poll::Ready(Err(e)),
                    _ => {
                        // No plaintext yet but we have buffered ciphertext — wake to retry.
                        if !this.incoming.is_empty() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ── AsyncWrite for TlsStream ─────────────────────────────────────

impl<S> AsyncWrite for TlsStream<S>
where
    S: Unpin + AsyncRead + AsyncWrite,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Flush buffered outgoing data first.
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Write plaintext into rustls.
        let n = this.tls.writer().write(buf)?;

        // Collect ciphertext.
        this.tls.write_tls(&mut this.write_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        // Flush as much as possible.
        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(written)) => { this.write_buf.drain(..written); }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        this.tls.write_tls(&mut this.write_buf)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
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
                Poll::Ready(Ok(n)) => { this.write_buf.drain(..n); }
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
