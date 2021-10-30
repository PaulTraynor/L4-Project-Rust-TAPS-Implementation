use crate::message::Message;

pub trait ProtocolConnection {
    fn send(&self, message: &Message);

    //fn recv();

    //fn close();

    //fn abort();
}

pub struct Connection<T: ProtocolConnection> {
    pub protocol_impl: T,
}

impl<T> Connection<T> where T: ProtocolConnection {
    pub fn send(&self, message: &Message) {
        self.protocol_impl.send(message);
    }
}

pub struct TcpConnection {
    
}

impl ProtocolConnection for TcpConnection {
    fn send(&self, message: &Message) {
        println!("hello");
    }
}