use std::fs::File;
use std::io::{BufReader, Error, ErrorKind};
use std::sync::Arc;
use log::info;
use rustls_pemfile::certs;
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;

/** TLS Configuration */
pub fn setup_tls_acceptor(cert_path : &str,key_path : &str) -> std::io::Result<TlsAcceptor> {
    let certs = load_certs(cert_path)?;
    let key = load_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    info!("Server TLS successfully configured");
    Ok(acceptor)
}

pub async fn setup_tls_connector(domain : String,tcp_stream: TcpStream) -> std::io::Result<TlsStream<TcpStream>> {
    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder().with_root_certificates(root_cert_store).with_no_client_auth();
    //a bad server name or a failed handshake is an outbound-connection error, not a panic: the
    //caller (ipinfo lookup) degrades to the offline mmdb instead of aborting under panic=abort
    let dns_name = ServerName::try_from(domain)
        .map_err(|e| Error::other(format!("Invalid tls server name {e}")))?;
    let connector = TlsConnector::from(Arc::new(config));
    connector.connect(dns_name, tcp_stream).await
}

fn open_file_buf(path : &str,err_msg : &str) -> std::io::Result<File> {
    if let Ok(file) = File::open(path) {
        Ok(file)
    } else {
        Err(Error::other(err_msg))
    }
}

fn load_certs(path: &str) -> std::io::Result<Vec<CertificateDer<'static>>> {
    certs(&mut BufReader::new(open_file_buf(path,"Failed to load tls cert file")?)).collect()
}

fn load_key(path: &str) -> std::io::Result<PrivateKeyDer<'static>> {
    //a file may hold several key blocks (cert chain leftovers, RSA + PKCS8 copies); consolidate
    //.unwrap() here panicked on the first non-matching block (e.g. an encrypted PKCS#8 key,
    //which rustls cannot load), crashing startup instead of reporting a config error
    let key_file = open_file_buf(path,"Failed to load tls key file")?;
    let mut key_reader = BufReader::new(key_file);
    let mut blocks = rustls_pemfile::read_all(&mut key_reader)
        .filter_map(|item| item.ok())
        .filter_map(|item| match item {
            rustls_pemfile::Item::Pkcs1Key(k) => Some(PrivateKeyDer::Pkcs1(k)),
            rustls_pemfile::Item::Pkcs8Key(k) => Some(PrivateKeyDer::Pkcs8(k)),
            rustls_pemfile::Item::Sec1Key(k) => Some(PrivateKeyDer::Sec1(k)),
            _ => None,
        });
    let key = blocks.next().ok_or_else(|| Error::other("Failed to load tls key file"))?;
    if blocks.next().is_some() {
        info!("Multiple private keys in {}, using the first", path);
    }
    Ok(key)
}