struct TransportProperties {
    selectionProperties: Vec<SelectionProperty>,
    connectionProperties: Vec<ConnectionProperty>,
    securityParameters: SecurityParameters,
}

enum SelectionProperty {
    Reliability(Preference),
    PreserveMsgBoundaries(Preference),
    PreserveOrder(Preference),
    Multistreaming(Preference),
    CongestionControl(Preference),
}

enum ConnectionProperty {}

struct SecurityParameters {
    certificate: Option<String>,
    private_key: Option<String>,
}

enum Preference {
    Require,
    Prefer,
    Ignore,
    Avoid,
    Prohibit,
}
