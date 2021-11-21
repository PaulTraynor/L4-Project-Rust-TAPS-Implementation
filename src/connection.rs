use crate::remote_endpoint::RemoteEndpoint;
use dns_lookup::lookup_addr;
use docopt::Docopt;
use env_logger;
use mio_quic;
use mio_tls;
use quiche;
use ring::rand::*;
use rustls;
use rustls::{OwnedTrustAnchor, RootCertStore};
use serde::Deserialize;
use serde_derive;
use std::collections;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, Read, Write};
use std::net::Shutdown;
use std::net::SocketAddr;
use std::net::TcpListener;
use std::net::TcpStream;
use std::process;
use std::str;
use std::sync::{Arc, Mutex};
use webpki_roots;

//#[macro_use]
//crate serde_derive;

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

const CLIENT: mio_tls::Token = mio_tls::Token(0);

pub struct TlsTcpClientConnection {
    socket: mio_tls::net::TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_conn: rustls::ClientConnection,
}

impl TlsTcpClientConnection {
    fn new(
        sock: mio_tls::net::TcpStream,
        server_name: rustls::ServerName,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsTcpClientConnection {
        TlsTcpClientConnection {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_conn: rustls::ClientConnection::new(cfg, server_name).unwrap(),
        }
    }

    fn connect(addr: SocketAddr) -> TlsTcpClientConnection {
        let version =
            env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

        let port = addr.port();
        let ip = addr.ip();
        let host = lookup_addr(&ip).unwrap();

        let args: Args = Args {
            flag_port: Some(port),
            flag_http: true,
            flag_protover: Vec::new(),
            flag_suite: Vec::new(),
            flag_proto: Vec::new(),
            flag_max_frag_size: None,
            flag_cafile: None,
            flag_cache: None,
            flag_no_tickets: true,
            flag_no_sni: true,
            flag_insecure: false,
            flag_auth_key: None,
            flag_auth_certs: None,
            arg_hostname: host,
        };

        let config = make_config(&args);
        let sock = mio_tls::net::TcpStream::connect(addr).unwrap();
        let server_name = args
            .arg_hostname
            .as_str()
            .try_into()
            .expect("invalid DNS name");
        TlsTcpClientConnection::new(sock, server_name, config)
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn ready(&mut self, ev: &mio_tls::event::Event) -> Option<Vec<u8>> {
        assert_eq!(ev.token(), CLIENT);

        if ev.is_readable() {
            match self.do_read() {
                Some(v) => return Some(v),
                None => return None,
            }
        }

        if ev.is_writable() {
            self.do_write();
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
        None
    }

    fn read_source_to_end(&mut self, rd: &mut dyn io::Read) -> io::Result<usize> {
        let mut buf = Vec::new();
        let len = rd.read_to_end(&mut buf)?;
        self.tls_conn.writer().write_all(&buf).unwrap();
        Ok(len)
    }

    /// We're ready to do a read.
    fn do_read(&mut self) -> Option<Vec<u8>> {
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.
        match self.tls_conn.read_tls(&mut self.socket) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return None;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return None;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return None;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tls_conn.process_new_packets() {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return None;
            }
        };

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        //
        // Read it and then write it to stdout.
        if io_state.plaintext_bytes_to_read() > 0 {
            let mut plaintext = Vec::new();
            plaintext.resize(io_state.plaintext_bytes_to_read(), 0u8);
            self.tls_conn.reader().read(&mut plaintext).unwrap();
            //io::stdout().write_all(&plaintext).unwrap();
            return Some(plaintext);
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
            return None;
        } else {
            return None;
        }
    }

    fn do_write(&mut self) {
        self.tls_conn.write_tls(&mut self.socket).unwrap();
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, registry: &mio_tls::Registry) {
        let interest = self.event_set();
        registry
            .register(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, registry: &mio_tls::Registry) {
        let interest = self.event_set();
        registry
            .reregister(&mut self.socket, CLIENT, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&self) -> mio_tls::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

        if rd && wr {
            mio_tls::Interest::READABLE | mio_tls::Interest::WRITABLE
        } else if wr {
            mio_tls::Interest::WRITABLE
        } else {
            mio_tls::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }
}

impl io::Write for TlsTcpClientConnection {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_conn.writer().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_conn.writer().flush()
    }
}

impl io::Read for TlsTcpClientConnection {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_conn.reader().read(bytes)
    }
}

/// This is an example cache for client session data.
/// It optionally dumps cached data to a file, but otherwise
/// is just in-memory.
///
/// Note that the contents of such a file are extremely sensitive.
/// Don't write this stuff to disk in production code.
struct PersistCache {
    cache: Mutex<collections::HashMap<Vec<u8>, Vec<u8>>>,
    filename: Option<String>,
}

impl PersistCache {
    /// Make a new cache.  If filename is Some, load the cache
    /// from it and flush changes back to that file.
    fn new(filename: &Option<String>) -> Self {
        let cache = PersistCache {
            cache: Mutex::new(collections::HashMap::new()),
            filename: filename.clone(),
        };
        if cache.filename.is_some() {
            cache.load();
        }
        cache
    }

    /// If we have a filename, save the cache contents to it.
    fn save(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::Codec;

        if self.filename.is_none() {
            return;
        }

        let mut file =
            fs::File::create(self.filename.as_ref().unwrap()).expect("cannot open cache file");

        for (key, val) in self.cache.lock().unwrap().iter() {
            let mut item = Vec::new();
            let key_pl = PayloadU16::new(key.clone());
            let val_pl = PayloadU16::new(val.clone());
            key_pl.encode(&mut item);
            val_pl.encode(&mut item);
            file.write_all(&item).unwrap();
        }
    }

    /// We have a filename, so replace the cache contents from it.
    fn load(&self) {
        use rustls::internal::msgs::base::PayloadU16;
        use rustls::internal::msgs::codec::{Codec, Reader};

        let mut file = match fs::File::open(self.filename.as_ref().unwrap()) {
            Ok(f) => f,
            Err(_) => return,
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data).unwrap();

        let mut cache = self.cache.lock().unwrap();
        cache.clear();
        let mut rd = Reader::init(&data);

        while rd.any_left() {
            let key_pl = PayloadU16::read(&mut rd).unwrap();
            let val_pl = PayloadU16::read(&mut rd).unwrap();
            cache.insert(key_pl.0, val_pl.0);
        }
    }
}

impl rustls::client::StoresClientSessions for PersistCache {
    /// put: insert into in-memory cache, and perhaps persist to disk.
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.cache.lock().unwrap().insert(key, value);
        self.save();
        true
    }

    /// get: from in-memory cache
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.cache.lock().unwrap().get(key).cloned()
    }
}

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_http: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_max_frag_size: Option<usize>,
    flag_cafile: Option<String>,
    flag_cache: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
}

// TODO: um, well, it turns out that openssl s_client/s_server
// that we use for testing doesn't do ipv6.  So we can't actually
// test ipv6 and hence kill this.
fn lookup_ipv4(host: &str, port: u16) -> SocketAddr {
    use std::net::ToSocketAddrs;

    let addrs = (host, port).to_socket_addrs().unwrap();
    for addr in addrs {
        if let SocketAddr::V4(_) = addr {
            return addr;
        }
    }

    unreachable!("Cannot lookup address");
}

/// Find a ciphersuite with the given name
fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in rustls::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .unwrap()
        .iter()
        .map(|v| rustls::Certificate(v.clone()))
        .collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

#[cfg(feature = "dangerous_configuration")]
mod danger {
    use super::rustls;

    pub struct NoCertificateVerification {}

    impl rustls::client::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::Certificate,
            _intermediates: &[rustls::Certificate],
            _server_name: &rustls::ServerName,
            _scts: &mut dyn Iterator<Item = &[u8]>,
            _ocsp: &[u8],
            _now: std::time::SystemTime,
        ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}

#[cfg(feature = "dangerous_configuration")]
fn apply_dangerous_options(args: &Args, cfg: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        cfg.dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification {}));
    }
}

#[cfg(not(feature = "dangerous_configuration"))]
fn apply_dangerous_options(args: &Args, _: &mut rustls::ClientConfig) {
    if args.flag_insecure {
        panic!("This build does not support --insecure.");
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(&cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut reader).unwrap());
    } else {
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
    }

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        rustls::DEFAULT_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::DEFAULT_VERSIONS.to_vec()
    };

    let config = rustls::ClientConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store);

    let mut config = match (&args.flag_auth_key, &args.flag_auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_single_cert(certs, key)
                .expect("invalid client auth certs/key")
        }
        (None, None) => config.with_no_client_auth(),
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.flag_no_tickets {
        config.enable_tickets = false;
    }

    if args.flag_no_sni {
        config.enable_sni = false;
    }

    config.session_storage = Arc::new(PersistCache::new(&args.flag_cache));

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    config.max_fragment_size = args.flag_max_frag_size;

    apply_dangerous_options(args, &mut config);

    Arc::new(config)
}

impl ProtocolConnection for TlsTcpClientConnection {
    fn send(&mut self, buf: &[u8]) {
        self.write_all(buf);
    }

    fn recv(&mut self) {
        let mut bytes: Vec<u8> = Vec::new();
        let mut poll = mio_tls::Poll::new().unwrap();
        let mut events = mio_tls::Events::with_capacity(32);
        self.register(poll.registry());

        loop {
            poll.poll(&mut events, None).unwrap();
            if events.iter().peekable().peek().is_none() {
                break;
            }

            for ev in events.iter() {
                match self.ready(&ev) {
                    Some(v) => bytes.extend(v),
                    None => (),
                }
                self.reregister(poll.registry());
            }
        }
    }

    fn close(&mut self) {
        self.socket.shutdown(std::net::Shutdown::Both);
    }
}
