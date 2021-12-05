use crate::connection::*;
use crate::endpoint;
//use crate::endpoint::LocalEndpoint::*;
use crate::endpoint::RemoteEndpoint::*;
use crate::transport_properties;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;

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
        let mut ips: Vec<SocketAddr> = Vec::new();
        let host = "host".to_string();

        match &self.remote_endpoint {
            Some(v) => match v {
                HostnamePort(host, port) => {
                    let dns_ips = match dns_lookup::lookup_host(&host) {
                        Ok(v) => v,
                        Err(e) => panic!("failed to lookup host"),
                    };
                    for ip in dns_ips {
                        ips.push(SocketAddr::new(ip, *port))
                    }
                }
                Ipv4Port(ip, port) => {
                    ips.push(SocketAddr::new(IpAddr::V4(*ip), *port));
                    let host = match dns_lookup::lookup_addr(&IpAddr::V4(*ip)) {
                        Ok(str) => str,
                        Err(e) => panic!("no host found for ip"),
                    };
                }
                Ipv6Port(ip, port) => {
                    ips.push(SocketAddr::new(IpAddr::V6(*ip), *port));
                    let host = match dns_lookup::lookup_addr(&IpAddr::V6(*ip)) {
                        Ok(str) => str,
                        Err(e) => panic!("no host found for ip"),
                    };
                }
            },
            None => panic!("no remote endpoint added"),
        }

        // candidate gathering...

        let candidates = self.gather_candidates(CallerType::Client);

        // candidate racing...
        let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

        let tcp_connection = Box::new(TcpConnection { stream: stream });
        Connection {
            protocol_impl: tcp_connection,
        }
    }

    //fn listen(&self) -> Listener {}

    fn gather_candidates(&mut self, caller_type: CallerType) -> Vec<CandidateProtocol> {
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
        let mut final_protocols = Vec::new();
        for (k, v) in protocols.iter() {
            final_protocols.push(CandidateProtocol {
                name: k.to_string(),
                preference: *v,
            });
        }
        final_protocols.sort_by(|a, b| b.preference.cmp(&a.preference));
        final_protocols
    }
}

struct CandidateProtocol {
    name: String,
    preference: u32,
}

enum CallerType {
    Client,
    Server,
}

pub fn get_ips(hostname: &str) -> Vec<std::net::IpAddr> {
    //let ips: Vec<std::net::IpAddr> =
    lookup_host(hostname).unwrap()
    //for ip in ips {
    //  println!("{}", ip);
    //}
}
