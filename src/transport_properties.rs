pub struct TransportProperties {
    pub selectionProperties: Vec<SelectionProperty>,
    connectionProperties: Vec<ConnectionProperty>,
}

impl TransportProperties {
    pub fn new() -> TransportProperties {
        TransportProperties {
            selectionProperties: Vec::new(),
            connectionProperties: Vec::new(),
        }
    }

    pub fn add_selection_property(&mut self, selectionProperty: SelectionProperty) {
        self.selectionProperties.push(selectionProperty);
    }
}

pub enum SelectionProperty {
    Reliability(Preference),
    PreserveMsgBoundaries(Preference),
    PreserveOrder(Preference),
    Multistreaming(Preference),
    CongestionControl(Preference),
    Secure(Preference),
}

enum ConnectionProperty {}

pub struct SecurityParameters {
    certificate_path: String,
    private_key_path: String,
}

impl SecurityParameters {
    pub fn new(path_1: String, path_2: String) -> SecurityParameters {
        SecurityParameters {
            certificate_path: path_1,
            private_key_path: path_2,
        }
    }
}

pub enum Preference {
    Require,
    Prefer,
    Ignore,
    Avoid,
    Prohibit,
}
