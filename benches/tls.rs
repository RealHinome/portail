use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::RwLock;
use tokio_rustls::{
    TlsAcceptor, TlsConnector, TlsStream,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
};

/// Equivalent to the "Before" production State.
pub struct StateBefore {
    pub root_store: Option<Arc<RootCertStore>>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
}

/// Equivalent to the "After" production State.
pub struct StateAfter {
    pub root_store: Option<Arc<RootCertStore>>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
    pub base_client_config: Option<Arc<ClientConfig>>,
}

pub async fn connect_before<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: IO,
    domain: ServerName<'static>,
    state: Arc<RwLock<StateBefore>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let config = {
        let state_guard = state.read().await;
        let mut config = match (
            state_guard.root_store.clone(),
            state_guard.client_cert_resolver.clone(),
        ) {
            (Some(root_store), Some(cert_resolver)) => ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_cert_resolver(cert_resolver),
            (Some(root_store), None) => ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
            (None, Some(_)) => {
                return Err(tokio::io::Error::other("Client auth set without roots"));
            }
            (None, None) => {
                return Err(tokio::io::Error::other("No root store configured"));
            }
        };
        config.alpn_protocols = alpn_protocols;
        config
    };

    let connector = TlsConnector::from(Arc::new(config));
    let tls_stream = connector.connect(domain, stream).await?;
    Ok(TlsStream::Client(tls_stream))
}

pub async fn connect_after<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: IO,
    domain: ServerName<'static>,
    state: Arc<RwLock<StateAfter>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let state_guard = state.read().await;
    let base_config = state_guard
        .base_client_config
        .as_ref()
        .ok_or_else(|| tokio::io::Error::other("Base TLS client configuration is missing"))?;

    let mut local_config = (**base_config).clone();
    drop(state_guard);

    local_config.alpn_protocols = alpn_protocols;

    let connector = TlsConnector::from(Arc::new(local_config));
    let tls_stream = connector.connect(domain, stream).await?;
    Ok(TlsStream::Client(tls_stream))
}

struct TestContext {
    state_before: Arc<RwLock<StateBefore>>,
    /// "After" state without session resumption.
    state_after_no_resumption: Arc<RwLock<StateAfter>>,
    /// "After" state with session resumption.
    state_after_with_resumption: Arc<RwLock<StateAfter>>,
    server_acceptor: TlsAcceptor,
}

fn setup_test_context(num_root_certs: usize) -> TestContext {
    let mut roots = RootCertStore::empty();
    let mut signing_ca_data: Option<(KeyPair, CertificateParams)> = None;

    for i in 0..num_root_certs {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![format!("Root CA {i}")]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();
        if i == 0 {
            signing_ca_data = Some((ca_key, ca_params));
        }
    }

    let roots_arc = Arc::new(roots);
    let (ca_key, ca_params) = signing_ca_data.expect("At least one CA must be generated");
    let ca_issuer = Issuer::from_params(&ca_params, &ca_key);

    let server_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let server_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(server_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(server_key.serialize_der().into()),
        )
        .unwrap();

    let state_before = Arc::new(RwLock::new(StateBefore {
        root_store: Some(roots_arc.clone()),
        client_cert_resolver: None,
    }));

    let base_config_no_resumption = ClientConfig::builder()
        .with_root_certificates((*roots_arc).clone())
        .with_no_client_auth();

    let state_after_no_resumption = Arc::new(RwLock::new(StateAfter {
        root_store: Some(roots_arc.clone()),
        client_cert_resolver: None,
        base_client_config: Some(Arc::new(base_config_no_resumption)),
    }));

    let mut base_config_with_resumption = ClientConfig::builder()
        .with_root_certificates((*roots_arc).clone())
        .with_no_client_auth();
    base_config_with_resumption.resumption =
        tokio_rustls::rustls::client::Resumption::in_memory_sessions(256);

    let state_after_with_resumption = Arc::new(RwLock::new(StateAfter {
        root_store: Some(roots_arc.clone()),
        client_cert_resolver: None,
        base_client_config: Some(Arc::new(base_config_with_resumption)),
    }));

    TestContext {
        state_before,
        state_after_no_resumption,
        state_after_with_resumption,
        server_acceptor: TlsAcceptor::from(Arc::new(server_config)),
    }
}

/// Minimal handshake: no post-handshake I/O.
/// Used for Phase 2 (no resumption), the stream is closed immediately,
/// so no NewSessionTicket is ever received and no session state bleeds
/// between iterations.
async fn run_handshake_no_io<F, Fut>(acceptor: TlsAcceptor, alpn: Vec<Vec<u8>>, connect_fn: F)
where
    F: Fn(DuplexStream, ServerName<'static>, Vec<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = Result<TlsStream<DuplexStream>, tokio::io::Error>>,
{
    let (client_io, server_io) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let _ = acceptor.accept(server_io).await;
    });

    let domain = ServerName::try_from("localhost").unwrap();
    let _ = connect_fn(client_io, domain, alpn).await.unwrap();
}

/// Full post-handshake I/O: server sends a frame and client reads it.
/// This forces rustls to process all post-handshake TLS records,
/// including the NewSessionTicket, so the client session store is populated
/// and subsequent iterations can use PSK resumption.
async fn run_handshake_with_io<F, Fut>(acceptor: TlsAcceptor, alpn: Vec<Vec<u8>>, connect_fn: F)
where
    F: Fn(DuplexStream, ServerName<'static>, Vec<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = Result<TlsStream<DuplexStream>, tokio::io::Error>>,
{
    let (client_io, server_io) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        if let Ok(mut server_stream) = acceptor.accept(server_io).await {
            let _ = server_stream.write_all(b"ping").await;
            let _ = server_stream.flush().await;
        }
    });

    let domain = ServerName::try_from("localhost").unwrap();
    let mut client_stream = connect_fn(client_io, domain, alpn).await.unwrap();

    let mut buf = [0u8; 4];
    let _ = client_stream.read_exact(&mut buf).await;
    let _ = client_stream.shutdown().await;
}

fn bench_config_preparation_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("Phase1_Config_Preparation_Only");

    let stores = [
        ("mTLS_Style_2_Certs", 2usize),
        ("WebPKI_Style_100_Certs", 100),
    ];
    let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    for (store_name, cert_count) in stores {
        let ctx = setup_test_context(cert_count);

        group.bench_function(BenchmarkId::new(store_name, "Before_OnTheFly"), |b| {
            let state = ctx.state_before.clone();
            let alpn = alpn.clone();
            b.iter(|| {
                let state_guard = state.blocking_read();
                let mut config = match (
                    state_guard.root_store.clone(),
                    state_guard.client_cert_resolver.clone(),
                ) {
                    (Some(root_store), Some(cert_resolver)) => ClientConfig::builder()
                        .with_root_certificates((*root_store).clone())
                        .with_client_cert_resolver(cert_resolver),
                    (Some(root_store), None) => ClientConfig::builder()
                        .with_root_certificates((*root_store).clone())
                        .with_no_client_auth(),
                    _ => panic!("Invalid state"),
                };
                config.alpn_protocols = alpn.clone();
                let connector = TlsConnector::from(Arc::new(config));
                std::hint::black_box(connector);
            })
        });

        group.bench_function(BenchmarkId::new(store_name, "After_Cached"), |b| {
            let state = ctx.state_after_no_resumption.clone();
            let alpn = alpn.clone();
            b.iter(|| {
                let state_guard = state.blocking_read();
                let base_config = state_guard.base_client_config.as_ref().unwrap();
                let mut local_config = (**base_config).clone();
                drop(state_guard);
                local_config.alpn_protocols = alpn.clone();
                let connector = TlsConnector::from(Arc::new(local_config));
                std::hint::black_box(connector);
            })
        });
    }

    group.finish();
}

fn bench_handshake_no_resumption(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("Phase2_Handshake_No_Resumption");

    let stores = [
        ("mTLS_Style_2_Certs", 2usize),
        ("WebPKI_Style_100_Certs", 100),
    ];
    let protocols = [
        ("HTTP_1.1", vec![b"http/1.1".to_vec()]),
        ("HTTP_2", vec![b"h2".to_vec()]),
    ];

    for (store_name, cert_count) in &stores {
        let ctx = setup_test_context(*cert_count);

        for (proto_name, alpn) in &protocols {
            let label = format!("{store_name}_{proto_name}");

            group.bench_function(BenchmarkId::new(&label, "Before_OnTheFly"), |b| {
                let state = ctx.state_before.clone();
                let acceptor = ctx.server_acceptor.clone();
                let alpn = alpn.clone();
                b.to_async(&runtime).iter(|| {
                    run_handshake_no_io(acceptor.clone(), alpn.clone(), {
                        let state = state.clone();
                        move |io, domain, alpn| connect_before(io, domain, state.clone(), alpn)
                    })
                });
            });

            group.bench_function(BenchmarkId::new(&label, "After_Cached"), |b| {
                let state = ctx.state_after_no_resumption.clone();
                let acceptor = ctx.server_acceptor.clone();
                let alpn = alpn.clone();
                b.to_async(&runtime).iter(|| {
                    run_handshake_no_io(acceptor.clone(), alpn.clone(), {
                        let state = state.clone();
                        move |io, domain, alpn| connect_after(io, domain, state.clone(), alpn)
                    })
                });
            });
        }
    }

    group.finish();
}

fn bench_handshake_with_resumption(c: &mut Criterion) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group("Phase3_Handshake_With_Resumption");

    let stores = [
        ("mTLS_Style_2_Certs", 2usize),
        ("WebPKI_Style_100_Certs", 100),
    ];
    let protocols = [
        ("HTTP_1.1", vec![b"http/1.1".to_vec()]),
        ("HTTP_2", vec![b"h2".to_vec()]),
    ];

    for (store_name, cert_count) in &stores {
        let ctx = setup_test_context(*cert_count);

        for (proto_name, alpn) in &protocols {
            let label = format!("{store_name}_{proto_name}");

            // "Before" cannot benefit from resumption: every call creates a new
            // ClientConfig with no Resumption store, so the session ticket is
            // never stored. We still run it with post-handshake I/O to keep
            // measurement conditions identical to the "After" case.
            group.bench_function(BenchmarkId::new(&label, "Before_OnTheFly"), |b| {
                let state = ctx.state_before.clone();
                let acceptor = ctx.server_acceptor.clone();
                let alpn = alpn.clone();
                b.to_async(&runtime).iter(|| {
                    run_handshake_with_io(acceptor.clone(), alpn.clone(), {
                        let state = state.clone();
                        move |io, domain, alpn| connect_before(io, domain, state.clone(), alpn)
                    })
                });
            });

            // "After" with resumption: the shared Resumption store accumulates
            // session tickets across iterations. After the first full handshake,
            // all subsequent ones use PSK and skip asymmetric crypto.
            group.bench_function(BenchmarkId::new(&label, "After_Cached"), |b| {
                let state = ctx.state_after_with_resumption.clone();
                let acceptor = ctx.server_acceptor.clone();
                let alpn = alpn.clone();
                b.to_async(&runtime).iter(|| {
                    run_handshake_with_io(acceptor.clone(), alpn.clone(), {
                        let state = state.clone();
                        move |io, domain, alpn| connect_after(io, domain, state.clone(), alpn)
                    })
                });
            });
        }
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_config_preparation_only,
    bench_handshake_no_resumption,
    bench_handshake_with_resumption,
);
criterion_main!(benches);
