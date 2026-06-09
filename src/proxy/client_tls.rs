/// This connects to a target server using a mTLS mechanism.
/// The roots and client certs are fetched from the state where
/// they are the freshest and cached upon the first connection.
///
/// The state may be reloaded with new material.
///
/// NOTE: Revocation via CRLs are not handled.
pub async fn connect_using_tls_auth<IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: IO,
    domain: tokio_rustls::rustls::pki_types::ServerName<'static>,
    state: std::sync::Arc<tokio::sync::RwLock<crate::state::State>>,
    alpn_protocols: Vec<Vec<u8>>,
) -> Result<tokio_rustls::TlsStream<IO>, tokio::io::Error> {
    let base_config_arc = {
        let state_guard = state.read().await;
        state_guard.base_client_config.clone()
    };

    let mut local_config = (*base_config_arc).clone();
    local_config.alpn_protocols = alpn_protocols;

    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(local_config));

    tracing::debug!("Performing a TLS connection to {domain:?}...");

    let tls_stream = connector.connect(domain, stream).await?;
    Ok(tokio_rustls::TlsStream::Client(tls_stream))
}
