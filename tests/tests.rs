//mod pre_connection;
use rust_taps_api::{
    connection::Connection, endpoint, error::TransportServicesError, pre_connection,
    transport_properties,
};

#[tokio::test]
async fn preconn_initiate_test() {
    let transport_properties = transport_properties::TransportProperties::default();
    let remote_endpoint =
        endpoint::RemoteEndpoint::HostnamePort("www.google.co.uk".to_string(), 80);
    let mut pre_conn =
        pre_connection::PreConnection::new(None, Some(remote_endpoint), transport_properties, None);
    pre_conn.initiate();
}
