use std::path::PathBuf;

pub struct TransportProperties {
    pub selectionProperties: Vec<SelectionProperty>,
    pub connectionProperties: Vec<ConnectionProperty>,
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

    pub fn default() -> TransportProperties {
        let mut selectionProperties = Vec::new();
        let connectionProperties = Vec::new();
        selectionProperties.push(SelectionProperty::Reliability(Preference::Require));
        selectionProperties.push(SelectionProperty::PreserveMsgBoundaries(Preference::Ignore));
        selectionProperties.push(SelectionProperty::PreserveOrder(Preference::Require));
        selectionProperties.push(SelectionProperty::Multistreaming(Preference::Ignore));
        selectionProperties.push(SelectionProperty::CongestionControl(Preference::Require));
        selectionProperties.push(SelectionProperty::Secure(Preference::Require));
        TransportProperties {
            selectionProperties: selectionProperties,
            connectionProperties: connectionProperties,
        }
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

pub enum ConnectionProperty {}

pub struct SecurityParameters {
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
}

impl SecurityParameters {
    pub fn new() -> SecurityParameters {
        SecurityParameters {
            certificate_path: None,
            private_key_path: None,
        }
    }

    pub fn add_key(&mut self, key_path: PathBuf) {
        self.private_key_path = Some(key_path);
    }

    pub fn add_cert(&mut self, cert_path: PathBuf) {
        self.certificate_path = Some(cert_path);
    }
}

pub enum Preference {
    Require,
    Prefer,
    Ignore,
    Avoid,
    Prohibit,
}
