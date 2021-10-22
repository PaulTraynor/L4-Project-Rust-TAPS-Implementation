use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub struct LocalEndpoint {
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    port: Option<String>,
    interface: Option<String>,
}

impl LocalEndpoint {
    pub fn new() -> LocalEndpoint {
        LocalEndpoint {
            ipv4: None,
            ipv6: None,
            port: None,
            interface: None,
        }
    }
}