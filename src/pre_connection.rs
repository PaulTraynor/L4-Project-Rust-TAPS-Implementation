use crate::connection::*;
use crate::endpoint;
//use crate::endpoint::LocalEndpoint::*;
use crate::endpoint::RemoteEndpoint::*;
use crate::transport_properties;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::sleep;

type ConnRecord = Arc<Mutex<HashMap<String, TcpConnection>>>;
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

    pub async fn initiate(&mut self) -> Connection {
        let mut candidate_connections = Vec::new();

        // candidate gathering...
        let candidates = self.gather_candidates(CallerType::Client);

        match &self.remote_endpoint {
            Some(v) => match v {
                HostnamePort(host, port) => {
                    let dns_ips = match dns_lookup::lookup_host(&host) {
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
                                        let quic_candidate =
                                            CandidateConnection::Quic(QuicCandidate {
                                                addr: SocketAddr::new(*ip, *port),
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
                Ipv4Port(ip, port) => {
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
                                    let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                        addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                                        host: host.to_string(),
                                        cert_path: cert_path.to_path_buf(),
                                    });
                                    candidate_connections.push(quic_candidate);
                                }
                            }
                        }
                    }
                }
                Ipv6Port(ip, port) => {
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
                                    let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                        addr: SocketAddr::new(IpAddr::V6(*ip), *port),
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

        /***
        // connection racing...
        let conn_dict = Arc::new(Mutex::new(HashMap::new()));

        let found = false;
        let found = Arc::new(Mutex::new(found));

        tokio::spawn(async move {
            for candidate in candidate_protocols {
                match candidate {
                    CandidateConnection::Tcp(data) => {}
                    CandidateConnection::TlsTcp(data) => {}
                    CandidateConnection::Quic(data) => {}
                }
                sleep(Duration::from_millis(200));
            }
        }).await;
        ***/

        race_connections(candidate_connections).await;

        /***
        for i in 0..candidates_len {
            for j in 0..ips_len {
                if candidates[i].name == "tcp".to_string() {
                    let map = conn_dict.clone();
                    //let found = found.clone();
                    let current_ip = &ips[j];
                    tokio::spawn(async move {
                        run_connection_tcp(*current_ip, map).await;
                    });
                }
            }
        }
        ***/

        let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

        let tcp_connection = Box::new(TcpConnection { stream: stream });
        Connection {
            protocol_impl: tcp_connection,
        }
    }

    //fn listen(&self) -> Listener {}

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
        let final_protocols = Vec::new();
        for proto in final_protos {
            final_protocols.push(proto.name);
        }
        final_protocols
    }
}

struct PreferenceLevel {
    name: String,
    preference: u32,
}

enum CandidateProtocol {
    Tcp,
    TlsTcp,
    Quic,
}

enum CandidateConnection {
    Tcp(TcpCandidate),
    TlsTcp(TlsTcpCandidate),
    Quic(QuicCandidate),
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
    host: String,
    cert_path: PathBuf,
}

enum CallerType {
    Client,
    Server,
}

async fn race_connections(candidate_connections: Vec<CandidateConnection>) {
    let conn_dict = Arc::new(Mutex::new(HashMap::new()));

    let found = false;
    let found = Arc::new(Mutex::new(found));
    let other_found = found.clone();

    tokio::spawn(async move {
        for candidate in candidate_connections {
            let conn_dict = conn_dict.clone();
            let found = found.clone();
            match candidate {
                CandidateConnection::Tcp(data) => {
                    tokio::spawn(async move {
                        run_connection_tcp(data, conn_dict, found);
                    })
                    .await;
                }
                CandidateConnection::TlsTcp(data) => {}
                CandidateConnection::Quic(data) => {}
            }
            sleep(Duration::from_millis(200));
        }
    })
    .await;

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
        return;
    }
}

async fn run_connection_tcp(conn: TcpCandidate, map: ConnRecord, found: ConnFound) {
    //let mut found = found.lock().unwrap();
    //if !(*found) {
    if let Some(tcp_conn) = TcpConnection::connect(conn.addr).await {
        let mut map = map.lock().unwrap();
        let mut found = found.lock().unwrap();
        if *found == false {
            map.insert("conn".to_string(), tcp_conn);
            *found = true;
        }
        //*found = true;
    }
    // }
}

async fn run_connection_tls_tcp(
    conn: TlsTcpCandidate,
    host: String,
    map: ConnRecord,
    found: ConnFound,
) {
}

async fn run_connection_quic(conn: QuicCandidate, host: String, map: ConnRecord, found: ConnFound) {
}

pub fn get_ips(hostname: &str) -> Vec<std::net::IpAddr> {
    //let ips: Vec<std::net::IpAddr> =
    lookup_host(hostname).unwrap()
    //for ip in ips {
    //  println!("{}", ip);
    //}
}
