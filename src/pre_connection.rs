use crate::connection::Connection;
use crate::connection::*;
use crate::endpoint;
use crate::endpoint::LocalEndpoint;
use crate::endpoint::RemoteEndpoint;
use crate::listener::*;
use crate::transport_properties;
use crate::transport_properties::Preference::*;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;

type TcpConnRecord = Arc<Mutex<HashMap<String, TcpConnection>>>;
type TlsTcpConnRecord = Arc<Mutex<HashMap<String, TlsTcpConnection>>>;
type QuicConnRecord = Arc<Mutex<HashMap<String, QuicConnection>>>;
type ListenerRecord = Arc<Mutex<HashMap<String, Listener>>>;
type ConnFound = Arc<Mutex<bool>>;

pub struct PreConnection {
    pub local_endpoint: Option<endpoint::LocalEndpoint>,
    pub remote_endpoint: Option<endpoint::RemoteEndpoint>,
    pub transport_properties: transport_properties::TransportProperties,
    pub security_parameters: Option<transport_properties::SecurityParameters>,
}

impl PreConnection {
    pub fn new(
        local_endpoint: Option<endpoint::LocalEndpoint>,
        remote_endpoint: Option<endpoint::RemoteEndpoint>,
        transport_properties: transport_properties::TransportProperties,
        security_parameters: Option<transport_properties::SecurityParameters>,
    ) -> PreConnection {
        PreConnection {
            local_endpoint: local_endpoint,
            remote_endpoint: remote_endpoint,
            transport_properties: transport_properties,
            security_parameters: security_parameters,
        }
    }

    pub async fn initiate(&mut self) -> Option<Box<dyn Connection>> {
        let mut candidate_connections = Vec::new();

        // candidate gathering...
        let candidates = self.gather_candidates(CallerType::Client);

        match &self.remote_endpoint {
            Some(v) => match v {
                RemoteEndpoint::HostnamePort(host, port) => {
                    let dns_ips = match get_ips(&host) {
                        Ok(v) => v,
                        Err(e) => panic!("failed to lookup host"),
                    };
                    for candidate in candidates {
                        //ips.push(SocketAddr::new(ip, *port))
                        for ip in dns_ips.iter() {
                            if candidate == "tcp".to_string() {
                                let tcp_candidate = CandidateConnection::Tcp(TcpCandidate {
                                    addr: SocketAddr::new(*ip, *port),
                                });
                                candidate_connections.push(tcp_candidate);
                            }
                            if candidate == "tls_tcp".to_string() {
                                let tls_candidate = CandidateConnection::TlsTcp(TlsTcpCandidate {
                                    addr: SocketAddr::new(*ip, *port),
                                    host: host.to_string(),
                                });
                                candidate_connections.push(tls_candidate);
                            }
                            if candidate == "quic".to_string() {
                                if let Some(files) = &self.security_parameters {
                                    if let Some(cert_path) = &files.certificate_path {
                                        let local_endpoint = match &self.local_endpoint {
                                            Some(endpoint) => match endpoint {
                                                LocalEndpoint::Ipv4Port(ip, port) => {
                                                    SocketAddr::new(IpAddr::V4(*ip), *port)
                                                }
                                                LocalEndpoint::Ipv6Port(ip, port) => {
                                                    SocketAddr::new(IpAddr::V6(*ip), *port)
                                                }
                                            },
                                            None => SocketAddr::new(
                                                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                                8080,
                                            ),
                                        };
                                        let quic_candidate =
                                            CandidateConnection::Quic(QuicCandidate {
                                                addr: SocketAddr::new(*ip, *port),
                                                local_endpoint: local_endpoint,
                                                host: host.to_string(),
                                                cert_path: cert_path.to_path_buf(),
                                            });
                                        candidate_connections.push(quic_candidate);
                                    }
                                }
                            }
                        }
                    }
                }
                RemoteEndpoint::Ipv4Port(ip, port) => {
                    //ips.push(SocketAddr::new(IpAddr::V4(*ip), *port));
                    let host = match dns_lookup::lookup_addr(&IpAddr::V4(*ip)) {
                        Ok(str) => str,
                        Err(e) => panic!("no host found for ip"),
                    };
                    for candidate in candidates {
                        if candidate == "tcp".to_string() {
                            let tcp_candidate = CandidateConnection::Tcp(TcpCandidate {
                                addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                            });
                            candidate_connections.push(tcp_candidate);
                        }

                        if candidate == "tls_tcp".to_string() {
                            let tls_candidate = CandidateConnection::TlsTcp(TlsTcpCandidate {
                                addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                                host: host.to_string(),
                            });
                            candidate_connections.push(tls_candidate);
                        }

                        if candidate == "quic".to_string() {
                            if let Some(files) = &self.security_parameters {
                                if let Some(cert_path) = &files.certificate_path {
                                    let local_endpoint = match &self.local_endpoint {
                                        Some(endpoint) => match endpoint {
                                            LocalEndpoint::Ipv4Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V4(*ip), *port)
                                            }
                                            LocalEndpoint::Ipv6Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V6(*ip), *port)
                                            }
                                        },
                                        None => SocketAddr::new(
                                            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                            8080,
                                        ),
                                    };
                                    let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                        addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                                        local_endpoint: local_endpoint,
                                        host: host.to_string(),
                                        cert_path: cert_path.to_path_buf(),
                                    });
                                    candidate_connections.push(quic_candidate);
                                }
                            }
                        }
                    }
                }
                RemoteEndpoint::Ipv6Port(ip, port) => {
                    //ips.push(SocketAddr::new(IpAddr::V6(*ip), *port));
                    let host = match dns_lookup::lookup_addr(&IpAddr::V6(*ip)) {
                        Ok(str) => str,
                        Err(e) => panic!("no host found for ip"),
                    };
                    for candidate in candidates {
                        if candidate == "tcp".to_string() {
                            let tcp_candidate = CandidateConnection::Tcp(TcpCandidate {
                                addr: SocketAddr::new(IpAddr::V6(*ip), *port),
                            });
                            candidate_connections.push(tcp_candidate);
                        }

                        if candidate == "tls_tcp".to_string() {
                            let tls_candidate = CandidateConnection::TlsTcp(TlsTcpCandidate {
                                addr: SocketAddr::new(IpAddr::V6(*ip), *port),
                                host: host.to_string(),
                            });
                            candidate_connections.push(tls_candidate);
                        }

                        if candidate == "quic".to_string() {
                            if let Some(files) = &self.security_parameters {
                                if let Some(cert_path) = &files.certificate_path {
                                    let local_endpoint = match &self.local_endpoint {
                                        Some(endpoint) => match endpoint {
                                            LocalEndpoint::Ipv4Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V4(*ip), *port)
                                            }
                                            LocalEndpoint::Ipv6Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V6(*ip), *port)
                                            }
                                        },
                                        None => SocketAddr::new(
                                            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                                            8080,
                                        ),
                                    };
                                    let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                        addr: SocketAddr::new(IpAddr::V6(*ip), *port),
                                        local_endpoint: local_endpoint,
                                        host: host.to_string(),
                                        cert_path: cert_path.to_path_buf(),
                                    });
                                    candidate_connections.push(quic_candidate);
                                }
                            }
                        }
                    }
                }
            },
            None => panic!("no remote endpoint added"),
        }
        let conn = match race_connections(candidate_connections).await {
            (Some(conn), None) => Some(conn),
            _ => None,
        };

        conn

        //let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        //Some(TcpConnection::connect(addr).await.unwrap())
    }

    pub async fn listen(&mut self) -> Option<Listener> {
        let candidates = self.gather_candidates(CallerType::Server);
        let mut candidate_listeners = Vec::new();

        let local_endpoint = match &self.local_endpoint.as_ref().unwrap() {
            LocalEndpoint::Ipv4Port(ip, port) => SocketAddr::new(IpAddr::V4(*ip), *port),
            LocalEndpoint::Ipv6Port(ip, port) => SocketAddr::new(IpAddr::V6(*ip), *port),
        };

        for candidate in candidates {
            if candidate == "tcp".to_string() {
                candidate_listeners.push(CandidateConnection::TcpListener(TcpListenerCandidate {
                    addr: local_endpoint,
                }));
            }
            if candidate == "tls_tcp".to_string() {
                let cert_path = &self
                    .security_parameters
                    .as_ref()
                    .unwrap()
                    .certificate_path
                    .as_ref()
                    .unwrap();
                let key_path = &self
                    .security_parameters
                    .as_ref()
                    .unwrap()
                    .private_key_path
                    .as_ref()
                    .unwrap();
                candidate_listeners.push(CandidateConnection::TlsTcpListener(
                    TlsTcpListenerCandidate {
                        addr: local_endpoint,
                        cert_path: cert_path.to_path_buf(),
                        key_path: key_path.to_path_buf(),
                    },
                ));
            }
            if candidate == "quic".to_string() {
                let cert_path = &self
                    .security_parameters
                    .as_ref()
                    .unwrap()
                    .certificate_path
                    .as_ref()
                    .unwrap();
                let key_path = &self
                    .security_parameters
                    .as_ref()
                    .unwrap()
                    .private_key_path
                    .as_ref()
                    .unwrap();
                let host = match dns_lookup::lookup_addr(&local_endpoint.ip()) {
                    Ok(v) => v,
                    Err(e) => continue,
                };
                candidate_listeners.push(CandidateConnection::QuicListener(
                    QuicListenerCandidate {
                        addr: local_endpoint,
                        cert_path: cert_path.to_path_buf(),
                        key_path: key_path.to_path_buf(),
                        hostname: host,
                    },
                ));
            }
        }
        let listener = match race_connections(candidate_listeners).await {
            (None, Some(listener)) => Some(listener),
            _ => None,
        };

        listener
    }

    fn gather_candidates(&mut self, caller_type: CallerType) -> Vec<String> {
        let mut protocols = HashMap::new();
        protocols.insert("tcp".to_string(), 0);
        protocols.insert("tls_tcp".to_string(), 0);
        protocols.insert("quic".to_string(), 0);
        for preference in &self.transport_properties.selectionProperties {
            match preference {
                Reliability(pref) => match pref {
                    Prefer => {
                        if protocols.contains_key("tcp") {
                            *protocols.get_mut("tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("tls_tcp") {
                            *protocols.get_mut("tls_tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("tcp");
                        protocols.remove("tls_tcp");
                        protocols.remove("quic");
                    }
                    _ => {}
                },
                PreserveMsgBoundaries(pref) => match pref {
                    Prefer => {
                        if protocols.contains_key("tcp") {
                            *protocols.get_mut("tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("tls_tcp") {
                            *protocols.get_mut("tls_tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("tcp");
                        protocols.remove("tls_tcp");
                        protocols.remove("quic");
                    }
                    _ => {}
                },
                PreserveOrder(pref) => match pref {
                    Prefer => {
                        if protocols.contains_key("tcp") {
                            *protocols.get_mut("tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("tls_tcp") {
                            *protocols.get_mut("tls_tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("tcp");
                        protocols.remove("tls_tcp");
                        protocols.remove("quic");
                    }
                    _ => {}
                },
                Multistreaming(pref) => match pref {
                    Require => {
                        protocols.remove("tcp");
                        protocols.remove("tls_tcp");
                    }
                    Prefer => {
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("quic");
                    }
                    _ => {}
                },
                CongestionControl(pref) => match pref {
                    Prefer => {
                        if protocols.contains_key("tcp") {
                            *protocols.get_mut("tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("tls_tcp") {
                            *protocols.get_mut("tls_tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("tcp");
                        protocols.remove("tls_tcp");
                        protocols.remove("quic");
                    }
                    _ => {}
                },
                Secure(pref) => match pref {
                    Require => {
                        protocols.remove("tcp");
                        match caller_type {
                            CallerType::Server => match self.security_parameters {
                                Some(_) => {}
                                None => {
                                    panic!("Security parameters not specified on listener");
                                }
                            },
                            CallerType::Client => {}
                        }
                    }
                    Prefer => {
                        if protocols.contains_key("tls_tcp") {
                            *protocols.get_mut("tls_tcp").unwrap() += 1;
                        }
                        if protocols.contains_key("quic") {
                            *protocols.get_mut("quic").unwrap() += 1;
                        }
                    }
                    Prohibit => {
                        protocols.remove("tls_tcp");
                        protocols.remove("quic");
                    }
                    _ => {}
                },
            };
        }
        if protocols.is_empty() {
            panic!("No procols match selected preferences");
        }
        let mut final_protos: Vec<PreferenceLevel> = Vec::new();
        for (k, v) in protocols.iter() {
            final_protos.push(PreferenceLevel {
                name: k.to_string(),
                preference: *v,
            });
        }
        final_protos.sort_by(|a, b| b.preference.cmp(&a.preference));
        let mut final_protocols = Vec::new();
        for proto in final_protos {
            final_protocols.push(proto.name);
        }
        println!("final protocols: {:?}", final_protocols);
        final_protocols
    }
}

struct PreferenceLevel {
    name: String,
    preference: u32,
}

enum CandidateConnection {
    Tcp(TcpCandidate),
    TlsTcp(TlsTcpCandidate),
    Quic(QuicCandidate),
    TcpListener(TcpListenerCandidate),
    TlsTcpListener(TlsTcpListenerCandidate),
    QuicListener(QuicListenerCandidate),
}

struct TcpCandidate {
    addr: SocketAddr,
}

struct TlsTcpCandidate {
    addr: SocketAddr,
    host: String,
}

struct QuicCandidate {
    addr: SocketAddr,
    local_endpoint: SocketAddr,
    host: String,
    cert_path: PathBuf,
}

struct TcpListenerCandidate {
    addr: SocketAddr,
}

struct TlsTcpListenerCandidate {
    addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
}

struct QuicListenerCandidate {
    addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
    hostname: String,
}

enum CallerType {
    Client,
    Server,
}

async fn race_connections(
    candidate_connections: Vec<CandidateConnection>,
) -> (Option<Box<dyn Connection>>, Option<Listener>) {
    println!("{}", candidate_connections.len());
    let tcp_map = Arc::new(Mutex::new(HashMap::new()));
    let tls_tcp_map = Arc::new(Mutex::new(HashMap::new()));
    let quic_map = Arc::new(Mutex::new(HashMap::new()));
    let listener_map = Arc::new(Mutex::new(HashMap::new()));

    let tcp_map_clone = tcp_map.clone();
    let tls_tcp_map_clone = tls_tcp_map.clone();
    let quic_map_clone = quic_map.clone();
    let listener_map_clone = listener_map.clone();

    let found = false;
    let found = Arc::new(Mutex::new(found));
    let other_found = found.clone();

    tokio::spawn(async move {
        for candidate in candidate_connections {
            let found = found.clone();
            match candidate {
                CandidateConnection::Tcp(data) => {
                    println!("here");
                    let conn_dict = tcp_map.clone();
                    tokio::spawn(async move {
                        println!("run tcp");
                        run_connection_tcp(data, conn_dict, found).await;
                    });
                }
                CandidateConnection::TlsTcp(data) => {
                    let conn_dict = tls_tcp_map.clone();
                    tokio::spawn(async move {
                        run_connection_tls_tcp(data, conn_dict, found).await;
                    });
                }
                CandidateConnection::Quic(data) => {
                    let conn_dict = quic_map.clone();
                    tokio::spawn(async move {
                        run_connection_quic(data, conn_dict, found).await;
                    });
                }
                CandidateConnection::TcpListener(data) => {
                    let conn_dict = listener_map.clone();
                    tokio::spawn(async move {
                        run_listener_tcp(data, conn_dict, found).await;
                    });
                }
                CandidateConnection::TlsTcpListener(data) => {
                    let conn_dict = listener_map.clone();
                    tokio::spawn(async move {
                        run_listener_tls_tcp(data, conn_dict, found).await;
                    });
                }
                CandidateConnection::QuicListener(data) => {
                    let conn_dict = listener_map.clone();
                    tokio::spawn(async move {
                        run_listener_quic(data, conn_dict, found).await;
                    });
                }
            }
            sleep(Duration::from_millis(200)).await;
        }
    });

    if tokio::spawn(async move {
        loop {
            let other_found = other_found.lock().unwrap();
            if *other_found {
                return true;
            }
        }
    })
    .await
    .unwrap()
        == true
    {
        if !tcp_map_clone.lock().unwrap().is_empty() {
            let mut conn = tcp_map_clone.lock().unwrap();
            let conn = conn.remove("conn").unwrap();
            println!("returning");
            return (Some(Box::new(conn)), None);
        } else if !tls_tcp_map_clone.lock().unwrap().is_empty() {
            let mut conn = tls_tcp_map_clone.lock().unwrap();
            let conn = conn.remove("conn").unwrap();
            return (Some(Box::new(conn)), None);
        } else if !quic_map_clone.lock().unwrap().is_empty() {
            let mut conn = quic_map_clone.lock().unwrap();
            let conn = conn.remove("conn").unwrap();
            return (Some(Box::new(conn)), None);
        } else if !listener_map_clone.lock().unwrap().is_empty() {
            let mut listener = listener_map_clone.lock().unwrap();
            let listener = listener.remove("listener").unwrap();
            return (None, Some(listener));
        } else {
            return (None, None);
        }
    } else {
        return (None, None);
    }
}

async fn run_connection_tcp(conn: TcpCandidate, map: TcpConnRecord, found: ConnFound) {
    //let mut found = found.lock().unwrap();
    //if !(*found) {
    println!("trying {}", conn.addr);
    if let Some(tcp_conn) = TcpConnection::connect(conn.addr).await {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            println!("{} won", conn.addr);
            map.insert("conn".to_string(), tcp_conn);
            *found = true;
        }
        //*found = true;
    }
    // }
}

async fn run_connection_tls_tcp(conn: TlsTcpCandidate, map: TlsTcpConnRecord, found: ConnFound) {
    if let Some(tls_tcp_conn) = TlsTcpConnection::connect(conn.addr, conn.host).await {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            map.insert("conn".to_string(), tls_tcp_conn);
            *found = true;
        }
    }
}

async fn run_connection_quic(conn: QuicCandidate, map: QuicConnRecord, found: ConnFound) {
    if let Some(quic_conn) =
        QuicConnection::connect(conn.addr, conn.local_endpoint, conn.cert_path, conn.host).await
    {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            map.insert("conn".to_string(), quic_conn);
            *found = true;
        }
    }
}

async fn run_listener_tcp(listener: TcpListenerCandidate, map: ListenerRecord, found: ConnFound) {
    if let Some(tcp_listener) = TapsTcpListener::listener(listener.addr).await {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            let tcp_listener = Listener {
                tcp_listener: Some(TapsTcpListener {
                    listener: tcp_listener,
                }),
                tls_tcp_listener: None,
                quic_listener: None,
            };
            map.insert("listener".to_string(), tcp_listener);
            *found = true;
        }
    }
}

async fn run_listener_tls_tcp(
    listener: TlsTcpListenerCandidate,
    map: ListenerRecord,
    found: ConnFound,
) {
    if let Some(tls_tcp_listener) =
        TlsTcpListener::listener(listener.addr, listener.cert_path, listener.key_path).await
    {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            let tls_tcp_listener = Listener {
                tcp_listener: None,
                tls_tcp_listener: Some(tls_tcp_listener),
                quic_listener: None,
            };
            map.insert("listener".to_string(), tls_tcp_listener);
            *found = true;
        }
    }
}

async fn run_listener_quic(listener: QuicListenerCandidate, map: ListenerRecord, found: ConnFound) {
    if let Some(quic_listener) = QuicListener::listener(
        listener.addr,
        listener.cert_path,
        listener.key_path,
        listener.hostname,
    )
    .await
    {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            let quic_listener = Listener {
                tcp_listener: None,
                tls_tcp_listener: None,
                quic_listener: Some(quic_listener),
            };
            map.insert("listener".to_string(), quic_listener);
            *found = true;
        }
    }
}

pub fn get_ips(hostname: &str) -> io::Result<Vec<IpAddr>> {
    //let ips: Vec<std::net::IpAddr> =
    lookup_host(hostname)
    //for ip in ips {
    //  println!("{}", ip);
    //}
}
