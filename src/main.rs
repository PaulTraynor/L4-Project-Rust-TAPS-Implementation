mod local_endpoint;
mod remote_endpoint;
mod pre_connection;
mod connection;
mod framer;
use crate::framer::*;

fn main() {
    let framer = StringFramer {};
    let string = "hello".to_string();
    let bytes = framer.to_bytes(&string);

    println!("original: {}", framer.from_bytes(&bytes[..]));

}
