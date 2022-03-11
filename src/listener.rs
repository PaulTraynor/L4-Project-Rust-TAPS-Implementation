use crate::connection::*;
use crate::error::TransportServicesError;
use async_trait::async_trait;
use futures_util::StreamExt;
use log::*;
use rcgen;
use rustls_pemfile::{certs, rsa_private_keys};
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::*;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;

#[async_trait]
pub trait Listener {
    async fn next_connection(&mut self) -> Result<Box<dyn Connection>, TransportServicesError>;
}

pub struct TapsTcpListener {
    pub listener: TcpListener,
}

impl TapsTcpListener {
    pub async fn listener(addr: SocketAddr) -> Option<TapsTcpListener> {
        match TcpListener::bind(addr).await {
            Ok(listener) => Some(TapsTcpListener { listener: listener }),
            Err(_) => None,
        }
    }

    async fn accept_connection(&self) -> Option<TcpConnection> {
        let (tcp_stream, addr) = self.listener.accept().await.unwrap();
        Some(TcpConnection { stream: tcp_stream })
    }
}

impl Stream for TapsTcpListener {
    type Item = TcpConnection;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(tcp_conn) = task::block_in_place(move || {
            Handle::current().block_on(async move { self.accept_connection().await })
        }) {
            Poll::Ready(Some(tcp_conn))
        } else {
            Poll::Pending
        }
    }
}

#[async_trait]
impl Listener for TapsTcpListener {
    async fn next_connection(&mut self) -> Result<Box<dyn Connection>, TransportServicesError> {
        if let Some(conn) = self.next().await {
            Ok(Box::new(conn))
        } else {
            Err(TransportServicesError::FailedToReturnConnection)
        }
    }
}

pub struct QuicListener {
    endpoint: quinn::Endpoint,
    incoming: quinn::Incoming,
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

impl QuicListener {
    pub async fn listener(
        addr: SocketAddr,
        cert_path: PathBuf,
        key_path: PathBuf,
        hostname: String,
    ) -> Option<QuicListener> {
        let (cert, key) = match fs::read(&cert_path).and_then(|x| Ok((x, fs::read(&key_path)?))) {
            Ok(x) => x,
            Err(ref e) if e.kind() == io::ErrorKind::NotFound => {
                info!("generating self-signed certificate");
                let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
                let key = cert.serialize_private_key_der();
                let cert = cert.serialize_der().unwrap();
                fs::write(&cert_path, &cert).unwrap();
                fs::write(&key_path, &key).unwrap();
                (cert, key)
            }
            Err(_) => return None,
        };

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        let certs = vec![cert];

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();

        server_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        Arc::get_mut(&mut server_config.transport)
            .unwrap()
            .max_concurrent_uni_streams(0_u8.into());

        let (endpoint, incoming) = match quinn::Endpoint::server(server_config, addr) {
            Ok((endpoint, incoming)) => (endpoint, incoming),
            Err(e) => return None,
        };

        Some(QuicListener {
            endpoint: endpoint,
            incoming: incoming,
        })
    }

    pub async fn accept_connection(&mut self) -> Option<QuicConnection> {
        if let Some(conn) = self.incoming.next().await {
            let quinn::NewConnection {
                connection,
                mut bi_streams,
                ..
            } = conn.await.unwrap();

            if let Some(stream) = bi_streams.next().await {
                let stream = match stream {
                    Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                        info!("connection closed");
                        return None;
                    }
                    Err(e) => {
                        return None;
                    }
                    Ok(s) => s,
                };

                let (send, receive) = stream;

                Some(QuicConnection {
                    conn: connection,
                    send: send,
                    recv: receive,
                })
            } else {
                return None;
            }
        } else {
            return None;
        }
    }
}

impl Stream for QuicListener {
    type Item = QuicConnection;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(quic_conn) = task::block_in_place(move || {
            Handle::current().block_on(async move { self.accept_connection().await })
        }) {
            Poll::Ready(Some(quic_conn))
        } else {
            Poll::Pending
        }
    }
}

#[async_trait]
impl Listener for QuicListener {
    async fn next_connection(&mut self) -> Result<Box<dyn Connection>, TransportServicesError> {
        if let Some(conn) = self.next().await {
            Ok(Box::new(conn))
        } else {
            Err(TransportServicesError::FailedToReturnConnection)
        }
    }
}

fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))
        .map(|mut certs| certs.drain(..).map(Certificate).collect())
}

fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
    rsa_private_keys(&mut BufReader::new(File::open(path)?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
        .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
}

pub struct TlsTcpListener {
    acceptor: TlsAcceptor,
    listener: TcpListener,
}

impl TlsTcpListener {
    pub async fn listener(
        addr: SocketAddr,
        cert_path: PathBuf,
        key_path: PathBuf,
    ) -> Option<TlsTcpListener> {
        let certs = load_certs(Path::new(&cert_path)).unwrap();
        let mut keys = load_keys(Path::new(&key_path)).unwrap();
        println!("here");
        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .unwrap();
        println!("here");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        println!("here");
        let listener = TcpListener::bind(&addr).await.unwrap();
        Some(TlsTcpListener {
            acceptor: acceptor,
            listener: listener,
        })
    }

    pub async fn accept_connection(&self) -> Option<TlsTcpConnection> {
        let (stream, peer_addr) = self.listener.accept().await.unwrap();
        let acceptor = self.acceptor.clone();

        let stream = acceptor.accept(stream).await.unwrap();

        Some(TlsTcpConnection {
            tls_conn: TlsTcpConn::Server(stream),
        })
    }
}

impl Stream for TlsTcpListener {
    type Item = TlsTcpConnection;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(tls_tcp_conn) = task::block_in_place(move || {
            Handle::current().block_on(async move { self.accept_connection().await })
        }) {
            Poll::Ready(Some(tls_tcp_conn))
        } else {
            Poll::Pending
        }
    }
}

#[async_trait]
impl Listener for TlsTcpListener {
    async fn next_connection(&mut self) -> Result<Box<dyn Connection>, TransportServicesError> {
        if let Some(conn) = self.next().await {
            Ok(Box::new(conn))
        } else {
            Err(TransportServicesError::FailedToReturnConnection)
        }
    }
}
