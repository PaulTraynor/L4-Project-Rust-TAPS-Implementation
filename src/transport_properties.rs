use std::path::{Path, PathBuf};

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

    pub fn default() -> TransportProperties {
        let mut selectionProperties = Vec::new();
        let connectionProperties = Vec::new();
        selectionProperties.push(SelectionProperty::Reliability(Preference::Require));
        selectionProperties.push(SelectionProperty::PreserveMsgBoundaries(
            Preference::Require,
        ));
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

enum ConnectionProperty {}

pub struct SecurityParameters {
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
}

impl SecurityParameters {
    pub fn new(path_1: Option<PathBuf>, path_2: Option<PathBuf>) -> SecurityParameters {
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
