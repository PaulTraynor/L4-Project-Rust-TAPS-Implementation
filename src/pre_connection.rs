use crate::local_endpoint;
use crate::remote_endpoint;

pub struct PreConnection {
    pub local_endpoint: local_endpoint::LocalEndpoint,
    pub remote_endpoint: remote_endpoint::RemoteEndpoint,

}

impl PreConnection {
    fn initiate(&self) -> &impl Connection {
        //
    }

    //fn listen(&self) -> Listener {}
} 

pub trait Connection {
    fn send();

    fn recv();
}