use crate::remote_endpoint::RemoteEndpoint;
use quiche;
use ring::rand::*;
use std::io::prelude::*;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;

const HTTP_REQ_STREAM_ID: u64 = 4;

pub trait ProtocolConnection {
    fn send(&mut self, buffer: &[u8]);

    fn recv(&mut self);

    fn close(&mut self);

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
    pub stream: TcpStream,
}

impl TcpConnection {
    fn connect(addr: SocketAddr) -> TcpConnection {
        let tcp_stream = TcpStream::connect(addr).unwrap();
        TcpConnection { stream: tcp_stream }
    }
}

impl ProtocolConnection for TcpConnection {
    fn send(&mut self, buffer: &[u8]) {
        self.stream.write(buffer).unwrap();
    }

    fn recv(&mut self) {
        let mut buffer: [u8; 1024] = [0; 1024];
        self.stream.read(&mut buffer).unwrap();
    }

    fn close(&mut self) {
        self.stream
            .shutdown(Shutdown::Both)
            .expect("failed to shutdown");
    }
}

pub struct QuicConnection {
    pub conn: std::pin::Pin<Box<quiche::Connection>>,
}

impl QuicConnection {
    pub fn connect(addr: SocketAddr) -> Option<std::pin::Pin<Box<quiche::Connection>>> {
        const MAX_DATAGRAM_SIZE: usize = 1350;
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
        // Setup the event loop.
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

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
        let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
        poll.register(
            &socket,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();

        // Create the configuration for the QUIC connection.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);

        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
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
    }
}

impl ProtocolConnection for QuicConnection {
    fn send(&mut self, buffer: &[u8]) {
        self.conn
            .stream_send(HTTP_REQ_STREAM_ID, buffer, false) // TODO, is fin always false?
            .unwrap();
    }

    fn recv(&mut self) {
        let mut buffer: [u8; 1024] = [0; 1024];
        self.conn
            .stream_recv(HTTP_REQ_STREAM_ID, &mut buffer)
            .unwrap();
    }

    fn close(&mut self) {
        let reason = "connection closed by application";
        self.conn.close(false, 0, &reason.as_bytes()).unwrap();
    }
}
