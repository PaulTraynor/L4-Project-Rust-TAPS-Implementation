mod connection;
mod framer;
mod local_endpoint;
mod pre_connection;
mod remote_endpoint;
use crate::connection::QuicConnection;
use crate::framer::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn main() {
    let framer = StringFramer {};
    let string = "hello".to_string();
    let bytes = framer.to_bytes(&string);

    println!("original: {}", framer.from_bytes(&bytes[..]));

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let quic_conn = QuicConnection::connect(addr);
    /*
    let res = match quic_conn {
        Some(v) => {
            println!("worked")
        }
        None => (println!("...")),
    };
    println!("{:?}", res);
    */

    println!("{}", quic_conn.unwrap().is_established());
}
