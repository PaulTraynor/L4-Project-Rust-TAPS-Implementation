mod local_endpoint;
mod remote_endpoint;
mod pre_connection;
mod message;
mod connection;

fn main() {
    println!("Hello, world!");
    let mut local_endpoint = local_endpoint::LocalEndpoint::new();
    let mut remote_endpoint = remote_endpoint::RemoteEndpoint::new();
    let pre_connection = pre_connection::PreConnection { local_endpoint, remote_endpoint };
    
    let message = message::Message{content: &[1,1,1]};
    let tcp_conn = connection::TcpConnection {};
    let conn = connection::Connection {protocol_impl: tcp_conn};

    conn.send(&message);
}
