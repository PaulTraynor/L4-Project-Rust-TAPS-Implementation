mod connection;
mod endpoint;
mod error;
mod framer;
mod listener;
mod message;
mod pre_connection;
mod transport_properties;
use crate::connection::Connection;
use crate::connection::QuicConnection;
use crate::connection::TcpConnection;
use crate::connection::TlsTcpConnection;
use crate::endpoint::LocalEndpoint;
use crate::endpoint::RemoteEndpoint;
use crate::framer::Framer;
use crate::framer::*;
use crate::listener::Listener;
use crate::pre_connection::PreConnection;
use crate::transport_properties::*;
use crate::transport_properties::{Preference, SelectionProperty};
use quiche::h3::NameValue;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::sync::mpsc;

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
    let framer = framer::HttpRequestFramer {};
    let request = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
    //let response = b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\n\r\n";
    let parsed_request = framer.from_bytes(request);
    if let Ok(req) = parsed_request {
        //println!("{}", req.version);
        let encoded = framer.to_bytes(req);
        println!("{}", std::str::from_utf8(&encoded[..]).unwrap());
        //assert_eq!(request, &encoded[..]);
    }
    //println!("{}", parsed_request.version);
    let framer = framer::HttpResponseFramer {};
    //let response = b"GET /index.html HTTP/1.1\r\nHost: example.domain\r\n\r\n";
    let response = b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\n\r\n";
    let parsed_request = framer.from_bytes(response);
    if let Ok(req) = parsed_request {
        //println!("{}", req.version);
        let encoded = framer.to_bytes(req);
        println!("{}", std::str::from_utf8(&encoded[..]).unwrap());
        //assert_eq!(request, &encoded[..]);
    }
    ***/

    let (tx, mut rx) = mpsc::channel::<Box<dyn Listener>>(32);
    let tx2 = tx.clone();

    /***

    let (tx, mut rx) = mpsc::channel(32);
    let tx2 = tx.clone();

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
    let conn = Some(TcpConnection::connect(addr).await.unwrap());

    let conn_2 = Some(
        TlsTcpConnection::connect(addr, "goole.vom".to_string())
            .await
            .unwrap(),
    );

    tokio::spawn(async move {
        tx.send(conn).await;
    });

    tokio::spawn(async move {
        tx2.send(conn_2).await;
    });

    while let Some(message) = rx.recv().await {
        println!("GOT");
    }
    ***/
    let (tx, mut rx) = mpsc::channel::<Box<dyn Connection>>(32);
    let tx2 = tx.clone();

    let mut t_p = transport_properties::TransportProperties::new();

    t_p.add_selection_property(SelectionProperty::Reliability(Preference::Require));
    t_p.add_selection_property(SelectionProperty::Secure(Preference::Require));
    //t_p.add_selection_property(SelectionProperty::Multistreaming(Preference::Require));

    let r_e = RemoteEndpoint::HostnamePort("www.google.co.uk".to_string(), 443);
    let l_e = LocalEndpoint::Ipv4Port(Ipv4Addr::new(127, 0, 0, 1), 8080);

    let cert_path = Path::new("src/my.der");
    let key_path = Path::new("src/key.der");
    let sec = transport_properties::SecurityParameters::new(
        //Some(cert_path.to_path_buf()),
        //Some(key_path.to_path_buf()),
    );
    //println!("{:?}", path.to_path_buf());

    let mut p_c = PreConnection::new(None, Some(r_e), t_p, Some(sec));

    let mut conn = p_c.initiate().await;
    let request = b"GET / HTTP/1.1\r\nHost: www.google.co.uk\r\n\r\n";

    //conn.send(&data);

    match conn {
        Some(mut conn) => {
            println!("sending");
            //conn.send(request).await;
            //println!("about to listen for connections");
            //let mut conn = conn.next_connection().await.unwrap();
            //println!("received a conn");
            let data = conn.recv().await;
            //println!("{}", data.content.len());
            //conn.send(b"hi to you too").await;
        }
        None => {
            println!("no conn")
        }
    }
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
