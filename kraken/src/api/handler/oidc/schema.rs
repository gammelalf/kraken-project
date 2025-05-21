use openidconnect::AuthorizationCode;
use openidconnect::CsrfToken;
use serde::Deserialize;
use serde::Serialize;
use utoipa::ToSchema;

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FinishOidcLoginRequest {
    #[schema(value_type = String)]
    pub code: AuthorizationCode,
    #[schema(value_type = String)]
    pub state: CsrfToken,
}
