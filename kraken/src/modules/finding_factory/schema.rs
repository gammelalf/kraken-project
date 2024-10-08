//! Schemas for finding factory shared between API handler and internal code

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

/// Enum identifying specific kinds of issues the finding factory might detect and create findings for.
///
/// The frontend displays them seperated into sections / categories.
/// This separation should also be respected by the backend code using the variant.
/// It is achieved by prefixing all variants with the categories "name".
///
/// For example, all identifiers produced by the service detection attack start with `ServiceDetection`.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd)] //
#[derive(Serialize, Deserialize, ToSchema)]
pub enum FindingFactoryIdentifier {
    /// Finding generated by service detection, if it detected postgres
    ServiceDetectionPostgres,
    /// Finding generated by service detection, if it detected mariadb
    ServiceDetectionMariaDb,
    /// Finding generated by service detection, if it detected ssh
    ServiceDetectionSsh,
    /// Finding generated by service detection, if it detected snmp
    ServiceDetectionSnmp,
}

impl FromStr for FindingFactoryIdentifier {
    type Err = serde::de::value::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::deserialize(serde::de::value::StrDeserializer::new(s))
    }
}

impl fmt::Display for FindingFactoryIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.serialize(f)
    }
}
