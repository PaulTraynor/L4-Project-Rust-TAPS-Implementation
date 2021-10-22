mod local_endpoint;
mod remote_endpoint;
mod pre_connection;

fn main() {
    println!("Hello, world!");
    let mut local_endpoint = local_endpoint::LocalEndpoint::new();
    let mut remote_endpoint = remote_endpoint::RemoteEndpoint::new();
    let pre_connection = pre_connection::PreConnection { local_endpoint, remote_endpoint };
    
}
