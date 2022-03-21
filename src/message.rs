use crate::error::TransportServicesError;
use crate::framer::Framer;
use async_trait::async_trait;
//fn from_btyes(&self, raw_bytes: &[u8]) -> Result<Self, TransportServicesError> where Self:Sized;

pub trait Message {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(&self);
}

pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

pub struct HttpRequest {
    pub headers: Vec<HttpHeader>,
    pub method: String,
    pub path: String,
    pub version: u8,
}

pub struct HttpRequestMessage {
    pub request: HttpRequest,
}

impl Message for HttpRequestMessage {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.request.method.as_bytes());
        bytes.extend_from_slice(self.request.path.as_bytes());
        bytes.extend_from_slice(b" HTTP/");
        bytes.extend_from_slice(self.request.version.to_string().as_bytes());
        bytes.extend_from_slice(b"\r\n");
        for header in &self.request.headers {
            bytes.extend_from_slice(header.name.as_bytes());
            bytes.extend_from_slice(b" ");
            bytes.extend_from_slice(header.value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
    fn from_bytes(&self) {}
}
