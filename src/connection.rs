use async_trait::async_trait;
use env_logger;
use mio_quic;
use quiche;
use ring::rand::*;
use std::convert::TryFrom;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use tokio;
use tokio::io::{copy, split, AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls::{self, OwnedTrustAnchor};
use tokio_rustls::{webpki, TlsConnector};

const HTTP_REQ_STREAM_ID: u64 = 4;

#[async_trait]
pub trait ProtocolConnection {
    async fn send(&mut self, buffer: &[u8]);

    async fn recv(&mut self);

    async fn close(&mut self);

    //fn abort();
}

pub struct Connection {
    pub protocol_impl: Box<dyn ProtocolConnection>,
}

impl Connection {
    pub fn send(&mut self, buffer: &[u8]) {
        self.protocol_impl.send(buffer);
    }

    fn recv(&mut self) {
        self.protocol_impl.recv();
    }

    fn close(&mut self) {
        self.protocol_impl.close();
    }
}

pub struct TcpConnection {
    pub stream: tokio::net::TcpStream,
}

impl TcpConnection {
    async fn connect(addr: SocketAddr) -> TcpConnection {
        let tcp_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        TcpConnection { stream: tcp_stream }
    }
}

#[async_trait]
impl ProtocolConnection for TcpConnection {
    async fn send(&mut self, buffer: &[u8]) {
        self.stream.write(buffer).await.unwrap();
    }

    async fn recv(&mut self) {
        let mut buffer: [u8; 1024] = [0; 1024];
        self.stream.read(&mut buffer).await.unwrap();
    }

    async fn close(&mut self) {
        self.stream.shutdown().await;
        //.expect("failed to shutdown");
    }
}

pub struct QuicConnection {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,
}

impl QuicConnection {
    pub async fn connect(
        addr: SocketAddr,
    ) -> tokio::task::JoinHandle<Option<std::pin::Pin<Box<quiche::Connection>>>> {
        const MAX_DATAGRAM_SIZE: usize = 1350;
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
        // Setup the event loop.
        let poll = mio_quic::Poll::new().unwrap();
        let mut events = mio_quic::Events::with_capacity(1024);

        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        println!("{:?}", bind_addr);

        // Create the UDP socket backing the QUIC connection, and register it with
        // the event loop.
        let socket = std::net::UdpSocket::bind(bind_addr).unwrap();
        let socket = mio_quic::net::UdpSocket::from_socket(socket).unwrap();
        poll.register(
            &socket,
            mio_quic::Token(0),
            mio_quic::Ready::readable(),
            mio_quic::PollOpt::edge(),
        )
        .unwrap();

        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(b"\x0ahq-interop\x05hq-29\x05hq-28\x05hq-27\x08http/0.9")
            .unwrap();

        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(None, &scid, addr, &mut config).unwrap();

        println!(
            "connecting to {:} from {:} with scid ...",
            addr,
            socket.local_addr().unwrap(),
            //hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out).expect("initial send failed");
        while let Err(e) = socket.send_to(&out[..write], &send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                println!("send() would block");
                continue;
            }
            panic!("send() failed: {:?}", e);
        }

        println!("written {}", write);
        //let potential_conn =
        return tokio::spawn(async move {
            loop {
                poll.poll(&mut events, conn.timeout()).unwrap();

                // Read incoming UDP packets from the socket and feed them to quiche,
                // until there are no more packets to read.
                'read: loop {
                    // If the event loop reported no events, it means that the timeout
                    // has expired, so handle it without attempting to read packets. We
                    // will then proceed with the send loop.
                    if events.is_empty() {
                        println!("timed out");
                        conn.on_timeout();
                        break 'read;
                    }

                    let (len, from) = match socket.recv_from(&mut buf) {
                        Ok(v) => v,
                        Err(e) => {
                            // There are no more UDP packets to read, so end the read
                            // loop.
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                println!("recv() would block");
                                break 'read;
                            }
                            panic!("recv() failed: {:?}", e);
                        }
                    };

                    println!("got {} bytes", len);

                    let recv_info = quiche::RecvInfo { from };

                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,

                        Err(e) => {
                            println!("recv failed: {:?}", e);
                            continue 'read;
                        }
                    };

                    println!("processed {} bytes", read);
                }

                println!("done reading");

                if conn.is_closed() {
                    println!("connection closed, {:?}", conn.stats());
                    return None;
                }

                if conn.is_established() {
                    return Some(conn);
                }

                // Generate outgoing QUIC packets and send them on the UDP socket, until
                // quiche reports that there are no more packets to be sent.
                loop {
                    let (write, send_info) = match conn.send(&mut out) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            println!("done writing");
                            break;
                        }

                        Err(e) => {
                            println!("send failed: {:?}", e);

                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                    if let Err(e) = socket.send_to(&out[..write], &send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            println!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }

                    println!("written {}", write);
                }
            }
        });
        //let mut out = potential_conn.await.unwrap();
        //return out;
    }
}

#[async_trait]
impl ProtocolConnection for QuicConnection {
    async fn send(&mut self, buffer: &[u8]) {
        self.conn
            .stream_send(HTTP_REQ_STREAM_ID, buffer, false) // TODO, is fin always false?
            .unwrap();
    }

    async fn recv(&mut self) {
        let mut buffer: [u8; 1024] = [0; 1024];
        for s in self.conn.readable() {
            while let Ok((read, fin)) = self.conn.stream_recv(s, &mut buffer) {
                let stream_buf = &buffer[..read];
            }
            //buffer
        }
    }

    async fn close(&mut self) {
        let reason = "connection closed by application";
        self.conn.close(false, 0, &reason.as_bytes()).unwrap();
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
    pub async fn connect(addr: SocketAddr) -> TlsTcpConnection {
        let domain = dns_lookup::lookup_addr(&addr.ip()).unwrap();
        println!("{}", domain.as_str());
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
        let domain = rustls::ServerName::try_from(domain.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid dnsname"))
            .unwrap();
        let conn = connector.connect(domain, stream).await.unwrap();
        TlsTcpConnection {
            tls_conn: TlsTcpConn::Client(conn),
        }
    }
}

#[async_trait]
impl ProtocolConnection for TlsTcpConnection {
    async fn send(&mut self, buf: &[u8]) {
        match self.tls_conn {
            TlsTcpConn::Client(conn) => {
                conn.write_all(buf);
            }
            TlsTcpConn::Server(conn) => {
                conn.write_all(buf);
            }
        };
    }

    async fn recv(&mut self) {
        let mut buffer: Vec<u8> = vec![];

        match self.tls_conn {
            TlsTcpConn::Client(conn) => {
                let (mut reader, mut writer) = split(conn);
                tokio::select! {
                    res = copy(&mut reader, &mut buffer)
                }
            }
            TlsTcpConn::Server(conn) => {
                let (mut reader, mut writer) = split(conn);
                tokio::select! {
                    res = copy(&mut reader, &mut buffer)
                }
            }
        };
    }

    async fn close(&mut self) {
        match self.tls_conn {
            TlsTcpConn::Client(conn) => {
                let (mut reader, mut writer) = split(conn);
                writer.shutdown().await;
            }
            TlsTcpConn::Server(conn) => {
                let (mut reader, mut writer) = split(conn);
                writer.shutdown().await;
            }
        };
    }
}
