pub trait Framer {
    type Message;

    fn from_bytes(&self, raw_bytes: &[u8]) -> Self::Message;
    fn to_bytes<'a>(&self, message: &'a Self::Message) -> &'a [u8];
}

pub struct StringFramer {

}

impl Framer for StringFramer {
    type Message = String;

    fn from_bytes(&self, raw_bytes: &[u8]) -> Self::Message {
        String::from_utf8_lossy(raw_bytes).to_string()
    }

    fn to_bytes<'a>(&self, message: &'a Self::Message) -> &'a [u8] {
        message.as_bytes()//.clone()
    }
}
