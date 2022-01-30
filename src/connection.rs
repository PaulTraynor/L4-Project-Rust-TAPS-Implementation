use crate::framer::Framer;
use crate::message::Message;
use crate::pre_connection::PreConnection;
use async_trait::async_trait;
use quinn;
use std::convert::TryFrom;
use std::io;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use std::{fs, path::PathBuf};
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;

const HTTP_REQ_STREAM_ID: u64 = 4;

#[async_trait]
pub trait Connection {
    async fn send(&mut self, message: Message);
    async fn recv(&mut self) -> Message;
    async fn close(&mut self);
    //fn add_framer(&mut self, framer:dyn Framer<Message=framer::Message>);
}

pub struct TcpConnection {
    pub stream: tokio::net::TcpStream,
}

impl TcpConnection {
    pub async fn connect(addr: SocketAddr) -> Option<TcpConnection> {
        match tokio::net::TcpStream::connect(addr).await {
            Ok(conn) => Some(TcpConnection { stream: conn }),
            Err(e) => None,
        }
    }
}

#[async_trait]
impl Connection for TcpConnection {
    async fn send(&mut self, message: Message) {
        self.stream.write(&message.content).await.unwrap();
    }

    async fn recv(&mut self) -> Message {
        let mut buffer: [u8; 500] = [0; 500];
        self.stream.read(&mut buffer).await.unwrap();
        println!("{:?}", str::from_utf8(&buffer).unwrap());
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&buffer);
        Message { content: vec }
    }

    async fn close(&mut self) {
        self.stream.shutdown().await;
        //.expect("failed to shutdown");
    }
    //fn add_framer(&mut self){}
}

pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"h3"];

pub fn gen_client_config(cert_path: Option<PathBuf>) -> Option<rustls::ClientConfig> {
    let mut root_cert_store = rustls::RootCertStore::empty();
    match cert_path {
        Some(path) => match fs::read(path) {
            Ok(v) => match root_cert_store.add(&rustls::Certificate(v)) {
                Ok(_) => {
                    println!("ok")
                }
                Err(_) => {
                    println!("error add");
                    return None;
                }
            },
            Err(e) => {
                println!("error read");
                return None;
            }
        },
        None => {
            root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
                |ta| {
                    OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                },
            ));
        }
    }
    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    client_crypto.alpn_protocols = ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    Some(client_crypto)
}

pub struct QuicConnection {
    pub conn: quinn::Connection,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl QuicConnection {
    pub async fn connect(
        addr: SocketAddr,
        local_endpoint: SocketAddr,
        cert_path: Option<PathBuf>,
        hostname: String,
    ) -> Option<QuicConnection> {
        println!(
            "running quic. local address: {}, remote: {}, hostname: {}",
            local_endpoint, addr, hostname
        );

        let client_crypto = gen_client_config(cert_path);

        if let Some(client_crypto) = client_crypto {
            let mut endpoint = quinn::Endpoint::client(local_endpoint).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(client_crypto)));

            match endpoint.connect(addr, &hostname) {
                Ok(v) => match v.await {
                    Ok(new_conn) => {
                        println!("await worked");
                        let quinn::NewConnection {
                            connection: conn, ..
                        } = new_conn;
                        match conn.open_bi().await {
                            Ok((send, recv)) => {
                                println!("open worked");
                                return Some(QuicConnection {
                                    conn: conn,
                                    send: send,
                                    recv: recv,
                                });
                            }
                            Err(e) => return None,
                        }
                    }
                    Err(e) => {
                        println!("await failed: {}", e);
                        return None;
                    }
                },
                Err(e) => {
                    println!("endpoint.connect failed: {}", e);
                    return None;
                }
            }
        } else {
            return None;
        }

        println!("here");
    }
}
#[async_trait]
impl Connection for QuicConnection {
    async fn send(&mut self, message: Message) {
        //self.send.write_all(b"");
        self.send.write_all(&message.content).await.unwrap();
        self.send.finish().await;
    }

    async fn recv(&mut self) -> Message {
        let mut buffer: [u8; 1024] = [0; 1024];
        let resp = self.recv.read(&mut buffer).await;
        println!(
            "recieved {:?} bytes: {:?}",
            resp,
            str::from_utf8(&buffer).unwrap()
        );
        //sleep(Duration::from_millis(30)).await;
        //self.recv.read(&mut buffer).await;
        //println!("{:?}", str::from_utf8(&buffer).unwrap());
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&buffer);
        Message { content: vec }
    }

    async fn close(&mut self) {
        //self.send.finish().await;
        self.conn.close(0u32.into(), b"done");
    }
}
pub enum TlsTcpConn {
    Client(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Server(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

pub struct TlsTcpConnection {
    //stream: tokio::net::TcpStream,
    pub tls_conn: TlsTcpConn, //tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl TlsTcpConnection {
    pub async fn connect(addr: SocketAddr, host: String) -> Option<TlsTcpConnection> {
        let mut root_cert_store = rustls::RootCertStore::empty();
        root_cert_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(
            |ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            },
        ));

        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth(); // i guess this was previously the default?
        let connector = TlsConnector::from(Arc::new(config));

        let stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        let domain = rustls::ServerName::try_from(host.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
            .unwrap();
        let conn = connector.connect(domain, stream).await.unwrap();
        Some(TlsTcpConnection {
            tls_conn: TlsTcpConn::Client(conn),
        })
    }
}

#[async_trait]
impl Connection for TlsTcpConnection {
    async fn send(&mut self, message: Message) {
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => {
                conn.write_all(&message.content).await;
            }
            TlsTcpConn::Server(conn) => {
                conn.write_all(&message.content).await;
            }
        }
    }

    async fn recv(&mut self) -> Message {
        let mut buffer: [u8; 10000] = [0; 10000];
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => {
                conn.read(&mut buffer).await;
            }
            TlsTcpConn::Server(conn) => {
                conn.read(&mut buffer).await;
            }
        }
        let mut vec: Vec<u8> = Vec::new();
        vec.extend_from_slice(&buffer);
        Message { content: vec }
    }

    async fn close(&mut self) {
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => {
                conn.shutdown().await;
            }
            TlsTcpConn::Server(conn) => {
                conn.shutdown().await;
            }
        }
    }
}
