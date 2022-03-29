use rust_taps_api::{
    connection::Connection,
    endpoint,
    error::TransportServicesError,
    framer::{Framer, FramerError},
    message::{HttpHeader, HttpRequest, Message},
    pre_connection, transport_properties,
    transport_properties::{Preference, SelectionProperty},
};
use std::net::Ipv4Addr;

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn preconn_initiate_test() -> Result<(), TransportServicesError> {
    let transport_properties = transport_properties::TransportProperties::default();
    let remote_endpoint = endpoint::RemoteEndpoint::HostnamePort("www.google.com".to_string(), 443);
    let mut pre_conn =
        pre_connection::PreConnection::new(None, Some(remote_endpoint), transport_properties, None);
    match pre_conn.initiate().await {
        Ok(_) => {
            println!("returned ok");
            Ok(())
        }
        Err(_) => Err(TransportServicesError::InitiateFailed),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn send_recv_test() -> Result<(), TransportServicesError> {
    let transport_properties = transport_properties::TransportProperties::default();
    let remote_endpoint =
        endpoint::RemoteEndpoint::HostnamePort("www.google.co.uk".to_string(), 443);
    let mut pre_conn =
        pre_connection::PreConnection::new(None, Some(remote_endpoint), transport_properties, None);
    let request = b"GET /index.html HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    let mut headers = Vec::new();
    headers.push(HttpHeader {
        name: "Host".to_string(),
        value: "www.google.co.uk".to_string(),
    });
    let request = HttpRequest {
        headers: headers,
        method: "GET".to_string(),
        path: "/index.html".to_string(),
        version: 1,
    };
    match pre_conn.initiate().await {
        Ok(mut conn) => {
            match conn.send(&request).await {
                Ok(_) => {
                    println!("ALL GOOD");
                    return Ok(());
                    //let data = conn.recv().await.unwrap();
                    //let resp = resp_framer.from_bytes(&data.content);
                    //match resp {
                    //  Ok(_) => {
                    //    println!("message received");
                    //  Ok(())
                    //}
                    //Err(FramerError::Incomplete(s)) => {
                    //  println!("Incomplete message: reading again");
                    // Err(TransportServicesError::RecvFailed)
                    //}
                    //Err(FramerError::ParseError(s)) => panic!("parse error"),
                    //}
                }
                Err(_) => Err(TransportServicesError::SendFailed),
            }
        }
        Err(_) => Err(TransportServicesError::InitiateFailed),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 10)]
async fn listener_test() -> Result<(), TransportServicesError> {
    let mut transport_properties = transport_properties::TransportProperties::default();
    transport_properties.selectionProperties.remove(5);
    transport_properties
        .selectionProperties
        .push(SelectionProperty::Secure(Preference::Prohibit));
    let local_endpoint = endpoint::LocalEndpoint::Ipv4Port(Ipv4Addr::new(127, 0, 0, 1), 8080);
    let mut pre_conn =
        pre_connection::PreConnection::new(Some(local_endpoint), None, transport_properties, None);
    match pre_conn.listen().await {
        Ok(_) => {
            println!("returned ok");
            Ok(())
        }
        Err(_) => Err(TransportServicesError::InitiateFailed),
    }
}
