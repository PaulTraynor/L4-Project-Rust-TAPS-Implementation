use httparse;
use std::str;

pub trait Message: Send + Sync {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<(), FramingError>;
}

pub enum FramingError {
    Incomplete(String),
    ParseError(String),
}

#[derive(Debug)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

impl HttpHeader {
    pub fn new(name: String, value: String) -> HttpHeader {
        HttpHeader {
            name: name,
            value: value,
        }
    }

    pub fn new_single(name: String, value: String) -> Vec<HttpHeader> {
        let header = HttpHeader {
            name: name,
            value: value,
        };
        let mut headers = Vec::new();
        headers.push(header);
        headers
    }
}

#[derive(Debug)]
pub struct HttpRequest {
    pub headers: Vec<HttpHeader>,
    pub method: String,
    pub path: String,
    pub version: f32,
}

impl HttpRequest {
    pub fn new(
        headers: Vec<HttpHeader>,
        method: String,
        path: String,
        version: f32,
    ) -> HttpRequest {
        HttpRequest {
            headers: headers,
            method: method,
            path: path,
            version: version,
        }
    }

    pub fn new_empty() -> HttpRequest {
        HttpRequest {
            headers: Vec::new(),
            method: "".to_string(),
            path: "".to_string(),
            version: 1.1,
        }
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    pub headers: Vec<HttpHeader>,
    pub version: u8,
    pub code: u16,
    pub reason: String,
}

impl HttpResponse {
    pub fn new(headers: Vec<HttpHeader>, version: u8, code: u16, reason: String) -> HttpResponse {
        HttpResponse {
            headers: headers,
            version: version,
            code: code,
            reason: reason,
        }
    }

    pub fn new_empty() -> HttpResponse {
        HttpResponse {
            headers: Vec::new(),
            version: 0,
            code: 0,
            reason: "".to_string(),
        }
    }
}

impl Message for HttpRequest {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.method.as_bytes());
        bytes.extend_from_slice(b" ");
        bytes.extend_from_slice(self.path.as_bytes());
        bytes.extend_from_slice(b" HTTP/");
        bytes.extend_from_slice(self.version.to_string().as_bytes());
        bytes.extend_from_slice(b"\r\n");
        for header in &self.headers {
            bytes.extend_from_slice(header.name.as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(header.value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }
    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<(), FramingError> {
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
                    self.headers = header_vec;
                    self.method = req.method.unwrap().to_string();
                    self.path = req.path.unwrap().to_string();
                    self.version = req.version.unwrap().into();
                    Ok(())
                } else {
                    return Err(FramingError::Incomplete(
                        "Error: incomplete request".to_string(),
                    ));
                }
            }
            _ => {
                return Err(FramingError::ParseError(
                    "Error parsing request".to_string(),
                ));
            }
        }
    }
}

impl Message for HttpResponse {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"HTTP");
        bytes.extend_from_slice(b"/");
        bytes.extend_from_slice(self.version.to_string().as_bytes());
        bytes.extend_from_slice(b" ");
        bytes.extend_from_slice(self.code.to_string().as_bytes());
        bytes.extend_from_slice(b" ");
        bytes.extend_from_slice(self.reason.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        for header in &self.headers {
            bytes.extend_from_slice(header.name.as_bytes());
            bytes.extend_from_slice(b": ");
            bytes.extend_from_slice(header.value.as_bytes());
            bytes.extend_from_slice(b"\r\n");
        }
        bytes.extend_from_slice(b"\r\n");
        bytes
    }

    fn from_bytes(&mut self, raw_bytes: &[u8]) -> Result<(), FramingError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);

        let res = response.parse(raw_bytes);

        match res {
            Ok(status) => {
                if status.is_complete() {
                    let mut header_vec = Vec::new();
                    for header in response.headers {
                        let (header_name, header_value) = (
                            header.name.to_string(),
                            str::from_utf8(header.value).unwrap().to_string(),
                        );
                        header_vec.push(HttpHeader {
                            name: header_name,
                            value: header_value,
                        });
                    }
                    self.headers = header_vec;
                    self.version = response.version.unwrap();
                    self.code = response.code.unwrap();
                    self.reason = response.reason.unwrap().to_string();
                    Ok(())
                } else {
                    return Err(FramingError::Incomplete(
                        "Error: incomplete request".to_string(),
                    ));
                }
            }
            _ => {
                return Err(FramingError::ParseError(
                    "Error parsing request".to_string(),
                ));
            }
        }
    }
}
