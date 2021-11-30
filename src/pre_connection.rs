use crate::connection::*;
use crate::endpoint;
use crate::transport_properties;
use crate::transport_properties::SelectionProperty::*;
use dns_lookup::lookup_host;
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
) -> Vec<String> {
    let protocols = Vec::new();
    protocols.push("tcp".to_string());
    protocols.push("tls_tcp".to_string());
    protocols.push("quic".to_string());

    for preference in transport_properties.selectionProperties {
        match preference {
            Reliability(pref) => {}
            PreserveMsgBoundaries(pref) => {}
            PreserveOrder(pref) => {}
            Multistreaming(pref) => match pref {
                Require => {
                    if protocols.contains(&"tcp".to_string()) {
                        protocols.remove(
                            protocols
                                .iter()
                                .position(|&x| x == "tcp".to_string())
                                .unwrap(),
                        );
                    }
                    if protocols.contains(&"tls_tcp".to_string()) {
                        protocols.remove(
                            protocols
                                .iter()
                                .position(|&x| x == "tls_tcp".to_string())
                                .unwrap(),
                        );
                    }
                }
            },
            CongestionControl(pref) => {}
            Secure(pref) => match pref {
                Require => {
                    if protocols.contains(&"tcp".to_string()) {
                        protocols.remove(
                            protocols
                                .iter()
                                .position(|&x| x == "tcp".to_string())
                                .unwrap(),
                        );
                    }
                    match caller_type {
                        CallerType::Server => match security_parameters {
                            None => {
                                panic!("Security parameters not specified on listener");
                            }
                        },
                    }
                }
                Prohibit => {
                    if protocols.contains(&"tls_tcp".to_string()) {
                        protocols.remove(
                            protocols
                                .iter()
                                .position(|&x| x == "tls_tcp".to_string())
                                .unwrap(),
                        );
                    }
                    if protocols.contains(&"quic".to_string()) {
                        protocols.remove(
                            protocols
                                .iter()
                                .position(|&x| x == "quic".to_string())
                                .unwrap(),
                        );
                    }
                }
            },
        };
    }
    protocols
}
