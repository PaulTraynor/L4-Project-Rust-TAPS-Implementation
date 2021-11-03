use crate::local_endpoint;
use crate::remote_endpoint;
use std::net::TcpStream;
use dns_lookup::{lookup_host};
use crate::connection::*;

pub struct PreConnection {
    pub local_endpoint: local_endpoint::LocalEndpoint,
    pub remote_endpoint: remote_endpoint::RemoteEndpoint,

}

impl PreConnection {
    fn initiate(&self) -> Connection {
        // candidate gathering...
        // candidate racing...
        let stream = TcpStream::connect("127.0.0.1:8080").unwrap();
        
        let tcp_connection = Box::new (TcpConnection {stream: stream}) ;
        Connection {protocol_impl: tcp_connection}

    }

    //fn listen(&self) -> Listener {}
} 

pub fn get_ips(hostname: &str) -> Vec<std::net::IpAddr> {
    //let ips: Vec<std::net::IpAddr> = 
    lookup_host(hostname).unwrap()
    //for ip in ips {
      //  println!("{}", ip);
    //}
}