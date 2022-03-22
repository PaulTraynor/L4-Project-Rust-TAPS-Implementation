use crate::error::TransportServicesError;
use crate::framer::Framer;
use async_trait::async_trait;
use httparse;
use std::str;

pub trait Message: Send + Sync {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(&mut self, raw_bytes: &[u8]);
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
    fn from_bytes(&mut self, raw_bytes: &[u8]) {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut req = httparse::Request::new(&mut headers);

        let res = req.parse(raw_bytes);

        match res {
            Ok(status) => {
                if status.is_complete() {
                    let mut header_vec = Vec::new();
                    for header in req.headers {
                        let (header_name, header_value) = (
                            header.name.to_string(),
                            str::from_utf8(header.value).unwrap().to_string(),
                        );
                        //println!("{}: {}", header_name, header_value);
                        header_vec.push(HttpHeader {
                            name: header_name,
                            value: header_value,
                        });
                    }
                    self.request.headers = header_vec;
                    self.request.method = req.method.unwrap().to_string();
                    self.request.path = req.path.unwrap().to_string();
                    self.request.version = req.version.unwrap();
                } else {
                    //return Err(FramerError::Incomplete(
                    //  "Error: incomplete request".to_string(),
                    //));
                }
            }
            _ => {
                //return Err(FramerError::ParseError("Error parsing request".to_string()));
            }
        }
    }
}
