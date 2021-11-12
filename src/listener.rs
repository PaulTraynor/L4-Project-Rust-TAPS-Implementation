use crate::connnection::*;

pub struct Listener {
    //listner - something implementing Stream trait
// so can return a stream of Connection objects
}

impl Listener {
    //fn next_connection -> Connection {
    //listener.poll_next()...etc.
    //}
}

pub struct TapsTcpListener {}

impl TapsTcpListener {
    fn listener(addr: SocketAddr) -> TcpListener {
        TcpListener::bind(addr).unwrap()
    }

    fn accept_connection(listener: TcpListener) -> TcpConnection {
        let (tcp_stream, addr) = listener.accept().unwrap();
        TcpConnection { stream: tcp_stream }
    }
}

pub struct QuicListener {}

impl QuicListener {}
