#[derive(Debug)]
pub enum TransportServicesError {
    SendFailed,
    RecvFailed,
    ShutdownFailed,
    NoConnectionSucceeded,
    ListenFailed,
    InitiateFailed,
    FailedToReturnConnection,
}
