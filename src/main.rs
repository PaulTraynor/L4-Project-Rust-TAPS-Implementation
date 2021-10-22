mod remote_endpoint;
mod local_endpoint;

fn main() {
    println!("Hello, world!");
    let mut remote_endpoint = remote_endpoint::RemoteEndpoint::new();
    let mut local_endpoint = local_endpoint::LocalEndpoint::new();
    
}
