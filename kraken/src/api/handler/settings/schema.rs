use chrono::DateTime;
use chrono::Utc;
use schemars::JsonSchema;
use serde::Deserialize;
use serde::Serialize;

use crate::models::UserPermission;

/// The live settings of kraken
#[derive(Serialize, Deserialize, JsonSchema, Debug, Clone)]
pub struct SettingsFull {
    /// Require mfa for local users
    pub mfa_required: bool,

    /// The default permission a user from oidc is set to
    pub oidc_initial_permission_level: UserPermission,

    /// The email for the dehashed account
    // TODO #[schema(example = "foo@example.com")]
    pub dehashed_email: Option<String>,

    /// The api key for the dehashed account
    // TODO #[schema(example = "1231kb3kkb51kj31kjb231kj3b1jk23bkj123")]
    pub dehashed_api_key: Option<String>,

    /// The point in time the settings were created
    pub created_at: DateTime<Utc>,
}

/// The request to update the settings
#[derive(Deserialize, Serialize, JsonSchema, Debug, Clone)]
pub struct UpdateSettingsRequest {
    /// Require mfa for local users
    pub mfa_required: bool,

    /// The default permission a user from oidc is set to
    pub oidc_initial_permission_level: UserPermission,

    /// The email for the dehashed account
    // TODO #[schema(example = "foo@example.com")]
    pub dehashed_email: Option<String>,

    /// The api key for the dehashed account
    // TODO #[schema(example = "1231kb3kkb51kj31kjb231kj3b1jk23bkj123")]
    pub dehashed_api_key: Option<String>,
}
