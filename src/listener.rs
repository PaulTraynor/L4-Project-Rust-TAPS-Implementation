use crate::connection::*;
use crate::pre_connection::PreConnection;
use async_stream::stream;
use async_trait::async_trait;
use futures_util::pin_mut;
use futures_util::StreamExt;
use log::*;
use rustls_pemfile::{certs, rsa_private_keys};
use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::*;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::TcpListener;
use tokio::runtime::Handle;
use tokio::task;
use tokio_rustls::rustls::{self, Certificate, PrivateKey};
use tokio_rustls::TlsAcceptor;
use tokio_stream::Stream;

pub struct Listener {
    tcp_listener: Option<TapsTcpListener>,
    tls_tcp_listener: Option<TlsTcpListener>,
    quic_listener: Option<QuicListener>,
}

impl Listener {
    async fn next_connection(&mut self) -> Option<Connection> {
        if let Some(listener) = &mut self.tcp_listener {
            if let Some(a) = listener.next().await {
                return Some(Connection {
                    protocol_impl: Box::new(a),
                });
            }
        } else if let Some(listener) = &mut self.tls_tcp_listener {
            if let Some(a) = listener.next().await {
                return Some(Connection {
                    protocol_impl: Box::new(a),
                });
            }
        } else if let Some(listener) = &mut self.quic_listener {
            if let Some(a) = listener.next().await {
                return Some(Connection {
                    protocol_impl: Box::new(a),
                });
            }
        }
        None
    }
}

pub struct TapsTcpListener {
    listener: TcpListener,
}

impl TapsTcpListener {
    async fn listener(addr: SocketAddr) -> TcpListener {
        TcpListener::bind(addr).await.unwrap()
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

pub struct QuicListener {
    endpoint: quinn::Endpoint,
    incoming: quinn::Incoming,
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

impl QuicListener {
    pub async fn listener(
        addr: SocketAddr,
        pre_connection: PreConnection,
        hostname: String,
    ) -> Option<QuicListener> {
        let security_params = pre_connection.security_parameters.unwrap();
        let (cert_path, key_path) = (
            &security_params.certificate_path.unwrap(),
            &security_params.private_key_path.unwrap(),
        );
        let key = fs::read(key_path).expect("failed to read private key");
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            rustls::PrivateKey(key)
        } else {
            let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                .expect("malformed PKCS #8 private key");
            match pkcs8.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                        .expect("malformed PKCS #1 private key");
                    match rsa.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            panic!("no private keys found");
                        }
                    }
                }
            }
        };

        let cert_chain = fs::read(cert_path).expect("failed to read certificate chain");
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            vec![rustls::Certificate(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .expect("invalid PEM-encoded certificate")
                .into_iter()
                .map(rustls::Certificate)
                .collect()
        };

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
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
    pub async fn listener(addr: SocketAddr) -> TlsTcpListener {
        let certs = load_certs(Path::new("p")).unwrap();
        let mut keys = load_keys(Path::new("p")).unwrap();

        let config = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, keys.remove(0))
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind(&addr).await.unwrap();

        TlsTcpListener {
            acceptor: acceptor,
            listener: listener,
        }
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
