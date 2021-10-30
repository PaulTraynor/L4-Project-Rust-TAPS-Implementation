use crate::message::Message;
use std::net::TcpStream;
use std::net::SocketAddr;

pub trait ProtocolConnection {
    fn send(&self, message: &Message);

    //fn recv();

    //fn close();

    //fn abort();
}

pub struct Connection {
    pub protocol_impl: Box<dyn ProtocolConnection>,
}

impl Connection{
    pub fn send(&self, message: &Message) {
        self.protocol_impl.send(message);
    }
}

pub struct TcpConnection {
    pub stream: TcpStream,
}

impl ProtocolConnection for TcpConnection {
    fn send(&self, message: &Message) {
        println!("hello");
    }
}

