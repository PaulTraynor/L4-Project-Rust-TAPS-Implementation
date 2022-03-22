use crate::connection::Connection;
use crate::connection::*;
use crate::endpoint;
use crate::endpoint::LocalEndpoint;
use crate::endpoint::RemoteEndpoint;
use crate::error::TransportServicesError;
use crate::listener::*;
use crate::transport_properties;
use crate::transport_properties::Preference::*;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::time::sleep;

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

    pub async fn initiate(&mut self) -> Result<Box<dyn Connection>, TransportServicesError> {
        let mut candidate_connections = Vec::new();

        // candidate gathering...
        let mut candidates = self.gather_candidates(CallerType::Client);
        //candidates.remove(1);

        match &self.remote_endpoint {
            Some(v) => match v {
                RemoteEndpoint::HostnamePort(host, port) => {
                    let dns_ips = match get_ips(&host) {
                        Ok(v) => v,
                        Err(e) => panic!("failed to lookup host"),
                    };

                    //dns_ips.remove(0);
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
                                let tls_port = if *port == 80 { 443 } else { *port };
                                let tls_candidate = CandidateConnection::TlsTcp(TlsTcpCandidate {
                                    addr: SocketAddr::new(*ip, tls_port),
                                    host: host.to_string(),
                                });
                                candidate_connections.push(tls_candidate);
                            }
                            if candidate == "quic".to_string() {
                                let quic_port = if *port == 80 { 443 } else { *port };
                                if let Some(files) = &self.security_parameters {
                                    let local_endpoint = match &self.local_endpoint {
                                        Some(endpoint) => match endpoint {
                                            LocalEndpoint::Ipv4Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V4(*ip), quic_port)
                                            }
                                            LocalEndpoint::Ipv6Port(ip, port) => {
                                                SocketAddr::new(IpAddr::V6(*ip), quic_port)
                                            }
                                        },
                                        None => match ip {
                                            IpAddr::V4(_) => SocketAddr::new(
                                                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                                                0,
                                            ),
                                            IpAddr::V6(_) => SocketAddr::new(
                                                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                                                0,
                                            ),
                                        },
                                    };
                                    //Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
                                    let cert_path = match &files.certificate_path {
                                        Some(cert) => Some(cert.to_path_buf()),
                                        None => None,
                                    };
                                    let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                        addr: SocketAddr::new(*ip, quic_port),
                                        local_endpoint: local_endpoint,
                                        host: host.to_string(),
                                        cert_path: cert_path,
                                    });
                                    candidate_connections.push(quic_candidate);
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
                                let cert_path = match &files.certificate_path {
                                    Some(cert) => Some(cert.to_path_buf()),
                                    None => None,
                                };
                                let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                    addr: SocketAddr::new(IpAddr::V4(*ip), *port),
                                    local_endpoint: local_endpoint,
                                    host: host.to_string(),
                                    cert_path: cert_path,
                                });
                                candidate_connections.push(quic_candidate);
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
                                let cert_path = match &files.certificate_path {
                                    Some(cert) => Some(cert.to_path_buf()),
                                    None => None,
                                };
                                let quic_candidate = CandidateConnection::Quic(QuicCandidate {
                                    addr: SocketAddr::new(IpAddr::V6(*ip), *port),
                                    local_endpoint: local_endpoint,
                                    host: host.to_string(),
                                    cert_path: cert_path,
                                });
                                candidate_connections.push(quic_candidate);
                            }
                        }
                    }
                }
            },
            None => panic!("no remote endpoint added"),
        }
        let conn = match self.race_connections(candidate_connections).await {
            Ok((Some(conn), None)) => Ok(conn),
            _ => Err(TransportServicesError::InitiateFailed),
        };

        conn

        //let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        //Some(TcpConnection::connect(addr).await.unwrap())
    }

    pub async fn listen(&mut self) -> Result<Box<dyn Listener>, TransportServicesError> {
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
        let listener = match self.race_connections(candidate_listeners).await {
            Ok((None, Some(listener))) => Ok(listener),
            _ => Err(TransportServicesError::ListenFailed),
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
                    Ignore => {}
                    Avoid => {
                        *protocols.get_mut("quic").unwrap() -= 1;
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
            panic!("No protocols match selected preferences");
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

    async fn race_connections(
        &mut self,
        candidate_connections: Vec<CandidateConnection>,
    ) -> Result<(Option<Box<dyn Connection>>, Option<Box<dyn Listener>>), TransportServicesError>
    {
        let (tx, mut rx) = mpsc::channel::<CompletedConnection>(64);
        tokio::spawn(async move {
            for candidate in candidate_connections {
                match candidate {
                    CandidateConnection::Tcp(data) => {
                        let tcp_channel = tx.clone();
                        tokio::spawn(async move {
                            run_connection_tcp(data, tcp_channel).await;
                        });
                    }
                    CandidateConnection::TlsTcp(data) => {
                        let tls_channel = tx.clone();
                        tokio::spawn(async move {
                            run_connection_tls_tcp(data, tls_channel).await;
                        });
                    }
                    CandidateConnection::Quic(data) => {
                        let quic_channel = tx.clone();
                        tokio::spawn(async move {
                            run_connection_quic(data, quic_channel).await;
                        });
                    }
                    CandidateConnection::TcpListener(data) => {
                        let tcp_listener_channel = tx.clone();
                        tokio::spawn(async move {
                            run_listener_tcp(data, tcp_listener_channel).await;
                        });
                    }
                    CandidateConnection::TlsTcpListener(data) => {
                        let tls_listener_channel = tx.clone();
                        tokio::spawn(async move {
                            run_listener_tls_tcp(data, tls_listener_channel).await;
                        });
                    }
                    CandidateConnection::QuicListener(data) => {
                        let quic_listener = tx.clone();
                        tokio::spawn(async move {
                            run_listener_quic(data, quic_listener).await;
                        });
                    }
                }
                sleep(Duration::from_millis(30)).await;
            }
        });
        while let Some(conn) = rx.recv().await {
            match conn {
                CompletedConnection::Tcp(conn) => {
                    println!("Connected over TCP");
                    return Ok((Some(Box::new(conn)), None));
                }
                CompletedConnection::TlsTcp(conn) => {
                    println!("Connected over TLS TCP");
                    return Ok((Some(Box::new(conn)), None));
                }
                CompletedConnection::Quic(conn) => {
                    println!("Connected over QUIC");
                    return Ok((Some(Box::new(conn)), None));
                }
                CompletedConnection::TcpListener(conn) => {
                    println!("Listening over TCP");
                    return Ok((None, Some(Box::new(conn))));
                }
                CompletedConnection::TlsTcpListener(conn) => {
                    println!("Listening over TLS TCP");
                    return Ok((None, Some(Box::new(conn))));
                }
                CompletedConnection::QuicListener(conn) => {
                    println!("Listening over QUIC");
                    return Ok((None, Some(Box::new(conn))));
                }
            }
        }
        return Err(TransportServicesError::NoConnectionSucceeded);
    }
}

enum CompletedConnection {
    Tcp(TcpConnection),
    TlsTcp(TlsTcpConnection),
    Quic(QuicConnection),
    TcpListener(TapsTcpListener),
    TlsTcpListener(TlsTcpListener),
    QuicListener(QuicListener),
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
    cert_path: Option<PathBuf>,
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

async fn run_connection_tcp(conn: TcpCandidate, channel: Sender<CompletedConnection>) {
    if let Some(tcp_conn) = TcpConnection::connect(conn.addr).await {
        channel.send(CompletedConnection::Tcp(tcp_conn)).await;
    }
}

async fn run_connection_tls_tcp(conn: TlsTcpCandidate, channel: Sender<CompletedConnection>) {
    if let Some(tls_tcp_conn) = TlsTcpConnection::connect(conn.addr, conn.host).await {
        channel
            .send(CompletedConnection::TlsTcp(tls_tcp_conn))
            .await;
    }
}

async fn run_connection_quic(conn: QuicCandidate, channel: Sender<CompletedConnection>) {
    if let Some(quic_conn) =
        QuicConnection::connect(conn.addr, conn.local_endpoint, conn.cert_path, conn.host).await
    {
        channel.send(CompletedConnection::Quic(quic_conn)).await;
    }
}

async fn run_listener_tcp(listener: TcpListenerCandidate, channel: Sender<CompletedConnection>) {
    if let Some(tcp_listener) = TapsTcpListener::listener(listener.addr).await {
        channel
            .send(CompletedConnection::TcpListener(tcp_listener))
            .await;
    }
}

async fn run_listener_tls_tcp(
    listener: TlsTcpListenerCandidate,
    channel: Sender<CompletedConnection>,
) {
    if let Some(tls_tcp_listener) =
        TlsTcpListener::listener(listener.addr, listener.cert_path, listener.key_path).await
    {
        channel
            .send(CompletedConnection::TlsTcpListener(tls_tcp_listener))
            .await;
    }
}

async fn run_listener_quic(listener: QuicListenerCandidate, channel: Sender<CompletedConnection>) {
    if let Some(quic_listener) = QuicListener::listener(
        listener.addr,
        listener.cert_path,
        listener.key_path,
        listener.hostname,
    )
    .await
    {
        channel
            .send(CompletedConnection::QuicListener(quic_listener))
            .await;
    }
}

pub fn get_ips(hostname: &str) -> io::Result<Vec<IpAddr>> {
    lookup_host(hostname)
}
