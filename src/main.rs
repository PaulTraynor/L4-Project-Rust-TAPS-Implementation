mod remote_endpoint;

fn main() {
    println!("Hello, world!");
    let mut remote_endpoint = remote_endpoint::RemoteEndpoint::new();
    remote_endpoint.with_hostname("www.google.com".to_string());
    
}
