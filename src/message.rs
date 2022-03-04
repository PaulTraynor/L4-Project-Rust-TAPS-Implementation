pub struct Message {
    pub content: Vec<u8>,
}

impl Message {
    pub fn new(content: Vec<u8>) -> Message {
        Message { content: content }
    }
}
