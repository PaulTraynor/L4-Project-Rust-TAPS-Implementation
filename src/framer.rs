use http_muncher::{Parser, ParserHandler};
use httparse;
use httparse::Header;
use std::str;

pub enum FramerError {
    Incomplete(String),
    ParseError(String),
}

pub trait Framer {
    type Message;

    fn from_bytes(&self, raw_bytes: &[u8]) -> Result<Self::Message, FramerError>;
    fn to_bytes(&self, message: Self::Message) -> &[u8];
}

pub struct HttpHeader {
    name: String,
    value: String,
}

pub struct HttpRequest {
    headers: Vec<HttpHeader>,
    method: String,
    path: String,
    version: u8,
}

pub struct HttpRequestFramer {}

impl ParserHandler for HttpRequestFramer {}

impl Framer for HttpRequestFramer {
    type Message = HttpRequest;

    fn from_bytes(&self, raw_bytes: &[u8]) -> Result<HttpRequest, FramerError> {
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
                        header_vec.push(HttpHeader {
                            name: header_name,
                            value: header_value,
                        });
                    }
                    return Ok(HttpRequest {
                        headers: header_vec,
                        method: req.method.unwrap().to_string(),
                        path: req.path.unwrap().to_string(),
                        version: req.version.unwrap(),
                    });
                } else {
                    return Err(FramerError::Incomplete(
                        "Error: incomplete request".to_string(),
                    ));
                }
            }
            _ => {
                return Err(FramerError::Incomplete("Error parsing request".to_string()));
            }
        }
    }

    fn to_bytes(&self, message: Self::Message) -> &[u8] {
        b"hi"
    }
}
