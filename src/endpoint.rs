use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

pub enum RemoteEndpoint {
    HostnamePort(String, u16),
    Ipv4Port(Ipv4Addr, u16),
    Ipv6Port(Ipv6Addr, u16),
}

pub enum LocalEndpoint {
    Ipv4Port(Ipv4Addr, u16),
    Ipv6Port(Ipv6Addr, u16),
}
