/*
 * kraken
 *
 * The core component of kraken-project
 *
 * The version of the OpenAPI document: 0.1.0
 * Contact: git@omikron.dev
 * Generated by: https://openapi-generator.tech
 */

/// PortProtocol : A protocol of a port

/// A protocol of a port
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub enum PortProtocol {
    #[serde(rename = "Unknown")]
    Unknown,
    #[serde(rename = "Tcp")]
    Tcp,
    #[serde(rename = "Udp")]
    Udp,

}

impl ToString for PortProtocol {
    fn to_string(&self) -> String {
        match self {
            Self::Unknown => String::from("Unknown"),
            Self::Tcp => String::from("Tcp"),
            Self::Udp => String::from("Udp"),
        }
    }
}

impl Default for PortProtocol {
    fn default() -> PortProtocol {
        Self::Unknown
    }
}




