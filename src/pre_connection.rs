use crate::local_endpoint;
use crate::remote_endpoint;
use crate::message::Message;
use std::net;
use dns_lookup::{lookup_host};

pub struct PreConnection {
    pub local_endpoint: local_endpoint::LocalEndpoint,
    pub remote_endpoint: remote_endpoint::RemoteEndpoint,

}

impl PreConnection {
    fn initiate(&self) //-> &impl Connection 
    {
        
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