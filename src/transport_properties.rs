struct TransportProperties {
    selectionProperties: Vec<SelectionProperty>,
    connectionProperties: Vec<ConnectionProperty>,
    securityParameters: SecurityParameters,
}

enum SelectionProperty {

}

enum ConnectionProperty {

}

struct SecurityParameters {
    identity: Option<String>,
    key_pair: Option<(String, String)>,
    supported_group: Option<String>,
    ciphersuite: Option<String>,
    signature_algorithm: Option<String>,
    pre_shared_key: Option<String>,
    max_cached_sessions: Option<u32>,
    cached_session_liefetime_seconds: Option<u32>,
}

enum Preference {
    Require,
    Prefer,
    Ignore,
    Avoid,
    Prohibit,
}