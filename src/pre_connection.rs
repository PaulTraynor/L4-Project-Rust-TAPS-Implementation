use crate::connection::*;
use crate::endpoint;
use crate::transport_properties;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
use std::collections::HashMap;
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

    pub async fn initiate(&self) -> Connection {
        // candidate gathering...

        // candidate racing...
        let stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

        let tcp_connection = Box::new(TcpConnection { stream: stream });
        Connection {
            protocol_impl: tcp_connection,
        }
    }

    //fn listen(&self) -> Listener {}
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

fn gather_candidates(
    transport_properties: transport_properties::TransportProperties,
    security_parameters: Option<transport_properties::SecurityParameters>,
    caller_type: CallerType,
) -> Vec<CandidateProtocol> {
    let mut protocols = HashMap::new();
    protocols.insert("tcp".to_string(), 0);
    protocols.insert("tls_tcp".to_string(), 0);
    protocols.insert("quic".to_string(), 0);

    for preference in transport_properties.selectionProperties {
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
                        CallerType::Server => match security_parameters {
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
