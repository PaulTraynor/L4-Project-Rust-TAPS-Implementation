use crate::message::Message;
use crate::remote_endpoint::RemoteEndpoint;
use std::net::TcpStream;
use std::net::Shutdown;
use std::net::SocketAddr;
use std::io::prelude::*;

pub trait ProtocolConnection {

    fn send(&mut self, buffer: &[u8]);

    fn recv(&mut self);

    fn close(&self);

    //fn abort();

}

pub struct Connection {
    pub protocol_impl: Box<dyn ProtocolConnection>,
}

impl Connection{

    pub fn send(&mut self, buffer: &[u8]) {
        self.protocol_impl.send(buffer);
    }

    fn recv(&mut self) {
        self.protocol_impl.recv();
    }

    fn close(&self) {
        self.protocol_impl.close();
    }
}

pub struct TcpConnection {  
    pub stream: TcpStream,
}

impl TcpConnection {
    fn new(addr:SocketAddr) -> TcpConnection {
        if let Ok(stream) = TcpStream::connect(addr) {
            TcpConnection {stream}
        }
    }
}

impl ProtocolConnection for TcpConnection {

    fn send(&mut self, buffer: &[u8]) {
        self.stream.write(buffer).unwrap();
    }

    fn recv(&mut self) {
        let mut buffer: [u8; 1000] = [0; 1000];
        self.stream.read(&mut buffer).unwrap();
    }

    fn close(&self) {
        self.stream.shutdown(Shutdown::Both).expect("failed to shutdown");
    }
}

