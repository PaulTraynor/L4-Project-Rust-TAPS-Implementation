use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub struct RemoteEndpoint {
    pub hostname: Option<String>,
    service: Option<String>,
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
    port: Option<String>,
}

impl RemoteEndpoint {
    pub fn new() -> RemoteEndpoint {
        RemoteEndpoint {
            hostname: None,
            service: None,
            ipv4: None,
            ipv6: None,
            port: None,
        }
    }

    pub fn with_hostname(&mut self, hostname: String) {
        self.hostname = Some(hostname);
    }
}