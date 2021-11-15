use crate::connection::*;
use log::*;
use mio;
use quiche;
use ring::rand::*;
use std::collections::HashMap;
use std::net::*;

pub struct Listener {
    //listner - something implementing Stream trait
// so can return a stream of Connection objects
}

impl Listener {
    //fn next_connection -> Connection {
    //listener.poll_next()...etc.
    //}
}

pub struct TapsTcpListener {}

impl TapsTcpListener {
    fn listener(addr: SocketAddr) -> TcpListener {
        TcpListener::bind(addr).unwrap()
    }

    fn accept_connection(listener: TcpListener) -> TcpConnection {
        let (tcp_stream, addr) = listener.accept().unwrap();
        TcpConnection { stream: tcp_stream }
    }
}

const MAX_DATAGRAM_SIZE: usize = 1350;

struct PartialResponse {
    body: Vec<u8>,

    written: usize,
}

struct Client {
    //conn: std::pin::Pin<Box<quiche::Connection>>,
    partial_responses: HashMap<u64, PartialResponse>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

pub struct QuicListener {
    client_map: ClientMap,
    client_id_vec: Vec<quiche::ConnectionId<'static>>,
    poll: mio::Poll,
    events: mio::Events,
    config: quiche::Config,
    conn_id_seed: ring::hmac::Key,
    socket: mio::net::UdpSocket,
}

impl QuicListener {
    pub fn listener(addr: SocketAddr) -> QuicListener {
        // Setup the event loop.
        let poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        // Create the UDP listening socket, and register it with the event loop.
        let socket = UdpSocket::bind(addr).unwrap();

        let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
        poll.register(
            &socket,
            mio::Token(0),
            mio::Ready::readable(),
            mio::PollOpt::edge(),
        )
        .unwrap();

        // Create the configuration for the QUIC connections.
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        config
            .load_cert_chain_from_pem_file("src/cert.crt")
            .unwrap();
        config.load_priv_key_from_pem_file("src/cert.key").unwrap();

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
        config.enable_early_data();

        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let clients = ClientMap::new();
        let client_id_vec = Vec::new();

        QuicListener {
            client_map: clients,
            client_id_vec: client_id_vec,
            poll: poll,
            events: events,
            config: config,
            conn_id_seed: conn_id_seed,
            socket: socket,
        }
    }

    pub fn recv_connection(&mut self) -> std::pin::Pin<Box<quiche::Connection>> {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
        loop {
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                // If the event loop reported no events, it means that the timeout
                // has expired, so handle it without attempting to read packets. We
                // will then proceed with the send loop.
                if self.events.is_empty() {
                    debug!("timed out");

                    break 'read;
                }
                let (len, from) = match self.socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("recv() would block");
                            break 'read;
                        }
                        panic!("recv() failed: {:?}", e);
                    }
                };
                debug!("got {} bytes", len);
                let pkt_buf = &mut buf[..len];
                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    }
                };
                trace!("got packet {:?}", hdr);
                let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();
                // Lookup a connection based on the packet's connection ID. If there
                // is no connection matching, create a new one.
                //let client =
                if !self.client_id_vec.contains(&hdr.dcid) && !self.client_id_vec.contains(&conn_id)
                {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }
                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");
                        let len =
                            quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();
                        let out = &out[..len];
                        if let Err(e) = self.socket.send_to(out, &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }
                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);
                    let scid = quiche::ConnectionId::from_ref(&scid);
                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();
                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");
                        let new_token = mint_token(&hdr, &from);
                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut out,
                        )
                        .unwrap();
                        let out = &out[..len];
                        if let Err(e) = self.socket.send_to(out, &from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }
                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }
                    let odcid = validate_token(&from, token);
                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue 'read;
                    }
                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }
                    // Reuse the source connection ID we sent in the Retry packet,
                    // instead of changing it again.
                    let scid = hdr.dcid.clone();
                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                    let conn =
                        quiche::accept(&scid, odcid.as_ref(), from, &mut self.config).unwrap();
                    //let client = Client {
                    //  conn,
                    //  partial_responses: HashMap::new(),
                    //};
                    self.client_id_vec.push(scid.clone());
                    //self.client_map.get_mut(&scid).unwrap();
                    return conn;
                }
                //else {
                //match self.client_map.get_mut(&hdr.dcid) {
                //  Some(v) => v,
                //None => self.client_map.get_mut(&conn_id).unwrap(),
                //}
                //};
                //return client.conn;
                /*
                let recv_info = quiche::RecvInfo { from };
                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue 'read;
                    }
                };
                debug!("{} processed {} bytes", client.conn.trace_id(), read);
                */
            }
        }
    }
}

/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &std::net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(
    src: &std::net::SocketAddr,
    token: &'a [u8],
) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}
