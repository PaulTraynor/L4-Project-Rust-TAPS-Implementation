mod connection;
mod endpoint;
mod error;
mod framer;
mod listener;
mod pre_connection;
mod transport_properties;
use crate::connection::QuicConnection;
use crate::connection::TlsTcpConnection;
use crate::endpoint::RemoteEndpoint;
use crate::pre_connection::PreConnection;
use crate::transport_properties::{Preference, SelectionProperty};
//use crate::framer::*;
use crate::transport_properties::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use trust_dns_resolver::config::*;
use trust_dns_resolver::Resolver;

#[tokio::main]
async fn main() {
    //let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 4433);
    //let quic_conn = QuicConnection::connect(addr).await;
    //let host = dns_lookup::lookup_host("youtube.com").unwrap()[0];
    //let addr = SocketAddr::new(host, 443);
    //let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default()).unwrap();
    //let response = resolver.lookup_ip("www.google.co.uk").unwrap();

    //for resp in response.iter() {
    //  println!("{}, {:?}", resp, resolver.reverse_lookup(resp));
    //}

    /***

    let mut t_p = transport_properties::TransportProperties::new();

    t_p.add_selection_property(SelectionProperty::Reliability(Preference::Require));
    t_p.add_selection_property(SelectionProperty::Secure(Preference::Prohibit));

    let r_e = RemoteEndpoint::HostnamePort("www.sydney.edu.au".to_string(), 80);
    let mut p_c = PreConnection::new(None, Some(r_e), t_p, None);

    let data = b"hello";

    let mut conn = p_c.initiate().await;
    //conn.send(&data);

    match conn {
        Some(mut conn) => {
            println!("sending");
            conn.send(data).await;
        }
        None => {
            println!("no conn")
        }
    }
    ***/

    //for ip in host {
    //  println!("{}", dns_lookup::lookup_addr(&ip).unwrap())
    //}
    //let mut tls_conn = TlsTcpConnection::connect(addr).await;
    //tls_conn
    //  .tls_conn
    //.write_all(b"GET / HTTP/1.0\r\nHost: www.google.com\r\n\r\n");
    /*
    let res = match quic_conn {
        Some(v) => {
            println!("worked")
        }
        None => (println!("...")),
    };
    println!("{:?}", res);
    */

    //println!("{}", quic_conn.await.unwrap().unwrap().is_established());
}
