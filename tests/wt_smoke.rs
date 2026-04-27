//! WebTransport over HTTP/3 — wire-level smoke test.
//!
//! ## What this file actually tests
//!
//! * **W1.2 plumbing** — `h3::server::builder()` accepts the WT settings
//!   chain (`enable_webtransport`, `enable_extended_connect`,
//!   `enable_datagram`, `max_webtransport_sessions`) and the resulting
//!   server completes a QUIC + h3 handshake without erroring out. If the
//!   settings encoding were wrong the handshake would close with
//!   `H3_SETTINGS_ERROR` before the test can assert anything.
//! * **W1.3 negative path** — when the server is built *without* WT
//!   settings, an Extended CONNECT for `:protocol = webtransport` does
//!   not get a 200. (h3 0.0.8 closes the connection with
//!   `H3_SETTINGS_ERROR` because the client offered `enable_extended_connect`
//!   but the server didn't, which is also a valid "gate is off" outcome.)
//!
//! ## Why we don't have a positive 200-OK end-to-end test
//!
//! `h3-webtransport = 0.1.2` ships **server-side APIs only** — there is no
//! WT client crate. `WebTransportSession::accept` requires the peer to
//! have advertised `SETTINGS_ENABLE_WEBTRANSPORT = 1` and
//! `H3_DATAGRAM = 1` in its SETTINGS frame; otherwise it closes the
//! connection with `H3_SETTINGS_ERROR` (server.rs:91-108). The h3 0.0.8
//! client builder does not expose `enable_webtransport`, so a Rust test
//! client can offer `enable_extended_connect` and `enable_datagram` but
//! cannot offer `enable_webtransport`. Real browsers (Chrome, Edge) send
//! the full set, so the positive path is exercised by manual / browser
//! smoke testing.
//!
//! When a Rust WT client crate lands (or we write one over h3 primitives),
//! the right place for a positive 200-OK + bidi/uni/datagram echo
//! verification is this file.

use bytes::Bytes;
use h3::ext::Protocol;
use h3_quinn::quinn;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn install_default_crypto_provider() {
    // Tests can run in any order; the rustls default crypto provider is
    // process-global. `install_default` is idempotent in spirit — the
    // returned `Result` is `Err` when something else already installed
    // it, which we want to ignore.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn build_server_endpoint(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> quinn::Endpoint {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    quinn::Endpoint::server(server_config, bind).unwrap()
}

fn build_client_endpoint(cert: CertificateDer<'static>) -> quinn::Endpoint {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let client_config = quinn::ClientConfig::new(Arc::new(crypto));
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut endpoint = quinn::Endpoint::client(bind).unwrap();
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Verifies that an h3 server built with the WT settings chain (mirrors
/// what `start_http3_proxy` does when `webtransport_enabled = true`)
/// completes a QUIC + h3 handshake successfully against an h3 client.
/// If the SETTINGS frame encoding were wrong, the client would close
/// with `H3_SETTINGS_ERROR` before this test could observe anything.
#[tokio::test]
async fn webtransport_settings_handshake_completes() {
    install_default_crypto_provider();

    let (cert, key) = self_signed();
    let server_ep = build_server_endpoint(cert.clone(), key);
    let server_addr = server_ep.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let conn = server_ep.accept().await?.await.ok()?;
        // This is the same builder chain `start_http3_proxy` uses when
        // `webtransport_enabled = true`. If the encoding were broken, the
        // client would tear down the connection before we got here.
        let mut h3_builder = h3::server::builder();
        h3_builder
            .enable_webtransport(true)
            .enable_extended_connect(true)
            .enable_datagram(true)
            .max_webtransport_sessions(8);
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3_builder.build(h3_quinn::Connection::new(conn)).await.ok()?;
        // Block on accept so the connection stays open long enough for the
        // client to complete its SETTINGS exchange. Result ignored — we
        // only care that the handshake itself didn't error.
        let _ = h3_conn.accept().await;
        Some(())
    });

    let client_ep = build_client_endpoint(cert);
    let connecting = client_ep
        .connect(server_addr, "localhost")
        .expect("client connect setup");
    let quic_conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("client QUIC handshake timed out")
        .expect("client QUIC handshake failed");

    // Build the h3 client. This drives the SETTINGS exchange; if either
    // side rejects the peer's settings it errors here.
    let h3_quinn_client = h3_quinn::Connection::new(quic_conn);
    let build_res = tokio::time::timeout(
        Duration::from_secs(5),
        h3::client::builder()
            .enable_extended_connect(true)
            .enable_datagram(true)
            .build::<_, _, Bytes>(h3_quinn_client),
    )
    .await
    .expect("h3 client build timed out");

    assert!(
        build_res.is_ok(),
        "h3 handshake against WT-enabled server should succeed; got: {:?}",
        build_res.err()
    );

    drop(server_task);
}

/// Verifies the gate-off path: when the server doesn't advertise
/// `SETTINGS_ENABLE_WEBTRANSPORT`, an Extended CONNECT for
/// `:protocol = webtransport` does not get a 200. (Either the client
/// errors out, or the request stream resolves to a non-200 response.)
#[tokio::test]
async fn webtransport_extended_connect_does_not_return_200_when_gate_off() {
    install_default_crypto_provider();

    let (cert, key) = self_signed();
    let server_ep = build_server_endpoint(cert.clone(), key);
    let server_addr = server_ep.local_addr().unwrap();

    let _server_task = tokio::spawn(async move {
        let incoming = match server_ep.accept().await {
            Some(i) => i,
            None => return,
        };
        let conn = match incoming.await {
            Ok(c) => c,
            Err(_) => return,
        };
        // Default builder — WT settings *not* enabled. This is the
        // production behaviour when `webtransport_enabled = false` (the
        // default in `phalanx.conf`).
        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
                Ok(c) => c,
                Err(_) => return,
            };
        let _ = h3_conn.accept().await;
    });

    let client_ep = build_client_endpoint(cert);
    let connecting = client_ep
        .connect(server_addr, "localhost")
        .expect("client connect setup");
    let quic_conn = tokio::time::timeout(Duration::from_secs(5), connecting)
        .await
        .expect("client QUIC handshake timed out")
        .expect("client QUIC handshake failed");

    let h3_quinn_client = h3_quinn::Connection::new(quic_conn);
    let build_res = h3::client::builder()
        .enable_extended_connect(true)
        .build::<_, _, Bytes>(h3_quinn_client)
        .await;

    let (mut driver, mut send_request) = match build_res {
        Ok(p) => p,
        Err(_) => {
            // Client may also reject the peer's settings if there's a
            // mismatch — that is also a valid "gate off" outcome.
            return;
        }
    };

    let _driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let mut req = hyper::Request::builder()
        .method(hyper::Method::CONNECT)
        .uri("https://localhost/echo")
        .body(())
        .unwrap();
    req.extensions_mut().insert(Protocol::WEB_TRANSPORT);

    let send_res = tokio::time::timeout(
        Duration::from_secs(5),
        send_request.send_request(req),
    )
    .await
    .expect("send_request timed out");

    if let Ok(mut req_stream) = send_res {
        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            req_stream.recv_response(),
        )
        .await;
        if let Ok(Ok(resp)) = resp {
            assert_ne!(
                resp.status(),
                hyper::StatusCode::OK,
                "WT request should not return 200 when SETTINGS_ENABLE_WEBTRANSPORT is unset"
            );
        }
    }
}
