use crate::error::TransportServicesError;
use crate::message::Message;
use async_trait::async_trait;
use quinn;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fs, path::PathBuf};
use tokio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::TlsConnector;

pub enum SuccessEvent {
    SendSuccess,
    RecvSuccess,
}

#[async_trait]
pub trait Connection {
    async fn send(&mut self, message: Box<dyn Message>) -> Result<usize, TransportServicesError>;
    async fn recv(
        &mut self,
        message: Box<dyn Message>,
    ) -> Result<Box<dyn Message>, TransportServicesError>;
    async fn close(&mut self) -> Result<(), TransportServicesError>;
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
    async fn send(&mut self, message: Box<dyn Message>) -> Result<usize, TransportServicesError> {
        let msg = &message.to_bytes();
        match self.stream.write(&msg).await {
            Ok(num_bytes) => Ok(num_bytes),
            Err(_) => Err(TransportServicesError::SendFailed),
        }
    }

    async fn recv(
        &mut self,
        mut message: Box<dyn Message>,
    ) -> Result<Box<dyn Message>, TransportServicesError> {
        let mut buffer: [u8; 500] = [0; 500];
        match self.stream.read(&mut buffer).await {
            Ok(num_bytes) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.extend_from_slice(&buffer);
                message.from_bytes(&buffer);
                Ok(message)
            }
            Err(_) => Err(TransportServicesError::RecvFailed),
        }
        //println!("{:?}", str::from_utf8(&buffer).unwrap());
    }

    async fn close(&mut self) -> Result<(), TransportServicesError> {
        match self.stream.shutdown().await {
            Ok(_) => Ok(()),
            Err(_) => Err(TransportServicesError::ShutdownFailed),
        }
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

//Copyright (c) 2018 The quinn Developers

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

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
    async fn send(&mut self, message: Box<dyn Message>) -> Result<usize, TransportServicesError> {
        match self.send.write(&message.to_bytes()).await {
            Ok(num_bytes) => {
                self.send.finish().await;
                Ok(num_bytes)
            }
            Err(_) => Err(TransportServicesError::SendFailed),
        }
    }

    async fn recv(
        &mut self,
        mut message: Box<dyn Message>,
    ) -> Result<Box<dyn Message>, TransportServicesError> {
        let mut buffer: [u8; 1024] = [0; 1024];
        match self.recv.read(&mut buffer).await {
            Ok(_) => {
                let mut vec: Vec<u8> = Vec::new();
                vec.extend_from_slice(&buffer);
                message.from_bytes(&buffer);
                Ok(message)
            }
            Err(_) => Err(TransportServicesError::RecvFailed),
        }
    }

    async fn close(&mut self) -> Result<(), TransportServicesError> {
        match self.send.finish().await {
            Ok(_) => Ok(()),
            Err(_) => Err(TransportServicesError::ShutdownFailed),
        }
        //self.conn.close(0u32.into(), b"done");
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

/**

Copyright (c) 2017 quininer kel

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

*/

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

        match tokio::net::TcpStream::connect(&addr).await {
            Ok(stream) => {
                let domain = rustls::ServerName::try_from(host.as_str()).unwrap();
                match connector.connect(domain, stream).await {
                    Ok(conn) => Some(TlsTcpConnection {
                        tls_conn: TlsTcpConn::Client(conn),
                    }),
                    Err(_) => None,
                }
            }
            Err(_) => None,
        }
    }
}

#[async_trait]
impl Connection for TlsTcpConnection {
    async fn send(&mut self, message: Box<dyn Message>) -> Result<usize, TransportServicesError> {
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => match conn.write(&message.to_bytes()).await {
                Ok(num_bytes) => Ok(num_bytes),
                Err(_) => Err(TransportServicesError::SendFailed),
            },
            TlsTcpConn::Server(conn) => match conn.write(&message.to_bytes()).await {
                Ok(num_bytes) => Ok(num_bytes),
                Err(_) => Err(TransportServicesError::SendFailed),
            },
        }
    }

    async fn recv(
        &mut self,
        mut message: Box<dyn Message>,
    ) -> Result<Box<dyn Message>, TransportServicesError> {
        let mut buffer: [u8; 10000] = [0; 10000];
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => match conn.read(&mut buffer).await {
                Ok(_) => {
                    let mut vec: Vec<u8> = Vec::new();
                    vec.extend_from_slice(&buffer);
                    message.from_bytes(&buffer);
                    Ok(message)
                }
                Err(_) => Err(TransportServicesError::RecvFailed),
            },
            TlsTcpConn::Server(conn) => match conn.read(&mut buffer).await {
                Ok(_) => {
                    let mut vec: Vec<u8> = Vec::new();
                    vec.extend_from_slice(&buffer);
                    message.from_bytes(&buffer);
                    Ok(message)
                }
                Err(_) => Err(TransportServicesError::RecvFailed),
            },
        }
    }

    async fn close(&mut self) -> Result<(), TransportServicesError> {
        match &mut self.tls_conn {
            TlsTcpConn::Client(conn) => match conn.shutdown().await {
                Ok(_) => Ok(()),
                Err(_) => Err(TransportServicesError::ShutdownFailed),
            },
            TlsTcpConn::Server(conn) => match conn.shutdown().await {
                Ok(_) => Ok(()),
                Err(_) => Err(TransportServicesError::ShutdownFailed),
            },
        }
    }
}
