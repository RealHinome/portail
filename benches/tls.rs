use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::sync::RwLock;
use tokio_rustls::{
    TlsAcceptor, TlsConnector, TlsStream,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName},
    },
};

const REQUESTS_PER_CONNECTION_VARIANTS: &[usize] = &[1, 5, 20];

pub mod acl {
    #[derive(Clone)]
    pub struct ACLRules;
}

pub struct ServerCertificates<'a> {
    pub cert_chain: Vec<CertificateDer<'a>>,
    pub private_key: PrivateKeyDer<'a>,
}

/// State used by the "Before" strategy.
pub struct StateBefore {
    pub root_store: Arc<RootCertStore>,
    pub client_cert_resolver: Option<Arc<dyn tokio_rustls::rustls::client::ResolvesClientCert>>,
}

/// State used by the "After" strategy.
pub struct StateAfter {
    pub default_backend: Option<String>,
    pub acl_rules: acl::ACLRules,
    pub base_client_config: Arc<ClientConfig>,
}

pub async fn connect_before<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: IO,
    domain: ServerName<'static>,
    state: Arc<RwLock<StateBefore>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let config = {
        let guard = state.read().await;
        // Arc::clone — cheap pointer bump, identical to what production code
        // would do.  No deep clone of RootCertStore.
        let root_store = Arc::clone(&guard.root_store);
        let mut config = match guard.client_cert_resolver.clone() {
            Some(resolver) => ClientConfig::builder()
                .with_root_certificates((*root_store).clone())
                .with_client_cert_resolver(resolver),
            None => ClientConfig::builder()
                .with_root_certificates((*root_store).clone())
                .with_no_client_auth(),
        };
        config.alpn_protocols = alpn_protocols;
        config
    };

    let connector = TlsConnector::from(Arc::new(config));
    Ok(TlsStream::Client(connector.connect(domain, stream).await?))
}

pub async fn connect_after<IO: AsyncRead + AsyncWrite + Unpin>(
    stream: IO,
    domain: ServerName<'static>,
    state: Arc<RwLock<StateAfter>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<TlsStream<IO>, tokio::io::Error> {
    let base = {
        let guard = state.read().await;
        Arc::clone(&guard.base_client_config)
    };

    let mut local_config = (*base).clone();
    local_config.alpn_protocols = alpn_protocols;

    let connector = TlsConnector::from(Arc::new(local_config));
    Ok(TlsStream::Client(connector.connect(domain, stream).await?))
}

/// Builds a ClientConfig with session resumption disabled.
fn make_client_config_no_resumption(roots: &RootCertStore) -> ClientConfig {
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    cfg.resumption = tokio_rustls::rustls::client::Resumption::disabled();
    cfg
}

/// Builds a ClientConfig with in-memory session resumption enabled.
fn make_client_config_with_resumption(roots: &RootCertStore) -> ClientConfig {
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots.clone())
        .with_no_client_auth();
    cfg.resumption = tokio_rustls::rustls::client::Resumption::in_memory_sessions(256);
    cfg
}

/// All state objects needed by one benchmark scenario.
/// Construction is done once per benchmark group, outside the hot loop.
struct TestContext {
    /// "Before" strategy — resumption disabled.
    state_before_no_res: Arc<RwLock<StateBefore>>,
    /// "Before" strategy — resumption enabled.
    state_before_with_res: Arc<RwLock<StateBefore>>,
    /// "After" strategy — resumption disabled.
    state_after_no_res: Arc<RwLock<StateAfter>>,
    /// "After" strategy — resumption enabled.
    state_after_with_res: Arc<RwLock<StateAfter>>,
    /// Server-side acceptor shared across all sub-benchmarks.
    server_acceptor: TlsAcceptor,
}

fn setup_test_context(num_root_certs: usize) -> TestContext {
    // Build the requested number of CA certificates.  The first one is used
    // to sign the server leaf certificate; the rest fill the store so we can
    // measure the impact of store size on config-building time.
    let mut roots = RootCertStore::empty();
    let mut signing_ca: Option<(KeyPair, CertificateParams)> = None;

    for i in 0..num_root_certs {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(vec![format!("Root CA {i}")]).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        roots
            .add(CertificateDer::from(ca_cert.der().to_vec()))
            .unwrap();
        if i == 0 {
            signing_ca = Some((ca_key, ca_params));
        }
    }

    let roots_arc = Arc::new(roots);
    let (ca_key, ca_params) = signing_ca.unwrap();
    let issuer = Issuer::from_params(&ca_params, &ca_key);

    // Server leaf certificate signed by the first CA.
    let srv_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let srv_cert = srv_params.signed_by(&srv_key, &issuer).unwrap();

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(srv_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(srv_key.serialize_der().into()),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    // Build all four state variants from the same root store.
    let cfg_no_res = make_client_config_no_resumption(&roots_arc);
    let cfg_with_res = make_client_config_with_resumption(&roots_arc);

    TestContext {
        state_before_no_res: Arc::new(RwLock::new(StateBefore {
            root_store: Arc::clone(&roots_arc),
            client_cert_resolver: None,
        })),
        state_before_with_res: Arc::new(RwLock::new(StateBefore {
            root_store: Arc::clone(&roots_arc),
            client_cert_resolver: None,
        })),
        state_after_no_res: Arc::new(RwLock::new(StateAfter {
            default_backend: None,
            acl_rules: acl::ACLRules,
            base_client_config: Arc::new(cfg_no_res),
        })),
        state_after_with_res: Arc::new(RwLock::new(StateAfter {
            default_backend: None,
            acl_rules: acl::ACLRules,
            base_client_config: Arc::new(cfg_with_res),
        })),
        server_acceptor: TlsAcceptor::from(Arc::new(server_config)),
    }
}

async fn handle_server_http(stream: tokio_rustls::server::TlsStream<DuplexStream>) {
    let alpn = stream.get_ref().1.alpn_protocol().map(|b| b.to_vec());
    let service = hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async {
        Ok::<_, hyper::Error>(hyper::Response::new(Full::new(Bytes::from("OK"))))
    });
    let io = TokioIo::new(stream);
    if alpn == Some(b"h2".to_vec()) {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, service)
            .await;
    } else {
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .await;
    }
}

/// Runs a complete TLS handshake + HTTP session.
///
/// * `requests` HTTP requests are issued per connection.
/// * For HTTP/2 they are multiplexed concurrently; for HTTP/1.1 they are
///   pipelined sequentially with keep-alive.
/// * All spawned tasks are awaited before returning so that no work leaks
///   across benchmark iterations.
async fn run_http_session<F, Fut>(
    acceptor: TlsAcceptor,
    alpn: Vec<Vec<u8>>,
    is_h2: bool,
    requests: usize,
    connect_fn: F,
) where
    F: Fn(DuplexStream, ServerName<'static>, Vec<Vec<u8>>) -> Fut,
    Fut: std::future::Future<Output = Result<TlsStream<DuplexStream>, tokio::io::Error>>,
{
    // 64 KB duplex buffer: large enough to absorb concurrent H2 frames without
    // back-pressure stalls that would skew timings.
    let (client_io, server_io) = tokio::io::duplex(65536);

    let srv = tokio::spawn(async move {
        if let Ok(s) = acceptor.accept(server_io).await {
            handle_server_http(s).await;
        }
    });

    let domain = ServerName::try_from("localhost").unwrap();
    let tls = connect_fn(client_io, domain, alpn).await.unwrap();
    let io = TokioIo::new(tls);

    if is_h2 {
        let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
            .await
            .unwrap();
        let conn_handle = tokio::spawn(async move {
            let _ = conn.await;
        });

        let mut tasks = Vec::with_capacity(requests);
        for _ in 0..requests {
            let mut s = sender.clone();
            tasks.push(tokio::spawn(async move {
                let req = hyper::Request::builder()
                    .uri("/")
                    .header("host", "localhost")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let res = s.send_request(req).await.unwrap();
                let mut body = res.into_body();
                while let Some(f) = body.frame().await {
                    let _ = f.unwrap();
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        drop(sender);
        let _ = conn_handle.await;
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        let conn_handle = tokio::spawn(async move {
            let _ = conn.await;
        });

        for _ in 0..requests {
            let req = hyper::Request::builder()
                .uri("/")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let res = sender.send_request(req).await.unwrap();
            let mut body = res.into_body();
            while let Some(f) = body.frame().await {
                let _ = f.unwrap();
            }
        }
        drop(sender);
        let _ = conn_handle.await;
    }

    let _ = srv.await;
}

fn bench_config_preparation_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("Phase1_Config_Preparation_Only");
    let scenarios = [("2_Root_Certs", 2usize), ("100_Root_Certs", 100)];
    let alpn = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    for (label, cert_count) in scenarios {
        let ctx = setup_test_context(cert_count);

        // "Before": build ClientConfig from components on every iteration.
        group.bench_function(BenchmarkId::new(label, "Before_OnTheFly"), |b| {
            let state = ctx.state_before_no_res.clone();
            let alpn = alpn.clone();
            b.iter(|| {
                let guard = state.blocking_read();
                // Arc::clone — O(1), same as the async path.
                let root_store = Arc::clone(&guard.root_store);
                let mut config = match guard.client_cert_resolver.clone() {
                    Some(r) => ClientConfig::builder()
                        .with_root_certificates((*root_store).clone())
                        .with_client_cert_resolver(r),
                    None => ClientConfig::builder()
                        .with_root_certificates((*root_store).clone())
                        .with_no_client_auth(),
                };
                config.alpn_protocols = alpn.clone();
                std::hint::black_box(TlsConnector::from(Arc::new(config)));
            })
        });

        // "After": clone the pre-built ClientConfig and patch ALPN.
        group.bench_function(BenchmarkId::new(label, "After_Cached"), |b| {
            let state = ctx.state_after_no_res.clone();
            let alpn = alpn.clone();
            b.iter(|| {
                let base = {
                    let guard = state.blocking_read();
                    Arc::clone(&guard.base_client_config)
                };
                let mut config = (*base).clone();
                config.alpn_protocols = alpn.clone();
                std::hint::black_box(TlsConnector::from(Arc::new(config)));
            })
        });
    }

    group.finish();
}

fn bench_full_handshake(c: &mut Criterion, phase_name: &str, use_resumption: bool) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let mut group = c.benchmark_group(phase_name);

    let store_scenarios = [("2_Root_Certs", 2usize), ("100_Root_Certs", 100)];
    let protocol_scenarios = [
        ("HTTP1.1_Sequential", vec![b"http/1.1".to_vec()], false),
        ("HTTP2_Multiplexed", vec![b"h2".to_vec()], true),
    ];

    for (store_label, cert_count) in &store_scenarios {
        let ctx = setup_test_context(*cert_count);

        for (proto_label, alpn, is_h2) in &protocol_scenarios {
            for &req_count in REQUESTS_PER_CONNECTION_VARIANTS {
                let sub_label = format!("{store_label}_{proto_label}_{req_count}req");

                group.bench_function(BenchmarkId::new(&sub_label, "Before_OnTheFly"), |b| {
                    // Pick the matching resumption-aware state for "Before".
                    let state = if use_resumption {
                        ctx.state_before_with_res.clone()
                    } else {
                        ctx.state_before_no_res.clone()
                    };
                    let acceptor = ctx.server_acceptor.clone();
                    let alpn = alpn.clone();
                    b.to_async(&runtime).iter(|| {
                        run_http_session(acceptor.clone(), alpn.clone(), *is_h2, req_count, {
                            let state = state.clone();
                            move |io, domain, alpn| connect_before(io, domain, state.clone(), alpn)
                        })
                    });
                });

                group.bench_function(BenchmarkId::new(&sub_label, "After_Cached"), |b| {
                    let state = if use_resumption {
                        ctx.state_after_with_res.clone()
                    } else {
                        ctx.state_after_no_res.clone()
                    };
                    let acceptor = ctx.server_acceptor.clone();
                    let alpn = alpn.clone();
                    b.to_async(&runtime).iter(|| {
                        run_http_session(acceptor.clone(), alpn.clone(), *is_h2, req_count, {
                            let state = state.clone();
                            move |io, domain, alpn| connect_after(io, domain, state.clone(), alpn)
                        })
                    });
                });
            }
        }
    }

    group.finish();
}

fn bench_phase2_no_resumption(c: &mut Criterion) {
    bench_full_handshake(c, "Phase2_Full_Handshake_No_Resumption", false);
}

fn bench_phase3_with_resumption(c: &mut Criterion) {
    bench_full_handshake(c, "Phase3_Full_Handshake_With_Resumption", true);
}

criterion_group!(
    benches,
    bench_config_preparation_only,
    bench_phase2_no_resumption,
    bench_phase3_with_resumption,
);
criterion_main!(benches);
