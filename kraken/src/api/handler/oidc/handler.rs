use actix_toolbox::tb_middleware::Session;
use actix_web::get;
use actix_web::web::Query;
use actix_web::web::Redirect;
use chrono::Utc;
use log::debug;
use log::error;
use log::info;
use rorm::model::Identifiable;
use rorm::query;
use rorm::update;
use rorm::FieldAccess;
use rorm::Model;

use crate::api::handler::common::error::ApiError;
use crate::api::handler::common::error::ApiResult;
use crate::api::handler::oidc::schema::FinishOidcLoginRequest;
use crate::chan::global::GLOBAL;
use crate::chan::oidc::OidcRequestState;
use crate::models::OidcUser;
use crate::models::User;
use crate::models::UserPermission;

/// Starts the open id connect login flow
#[utoipa::path(
    tag = "OpenId Connect",
    context_path = "/api/v1/oidc",
    responses(
        (status = 307, description = "Redirect to oidc provider"),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse)
    ),
)]
#[get("/login")]
pub async fn begin_oidc_login(session: Session) -> ApiResult<Redirect> {
    let (auth_url, session_state) = GLOBAL.oidc.begin_login();
    session.insert(SESSION_KEY, session_state)?;
    Ok(Redirect::to(auth_url.as_str().to_string()).temporary())
}

/// Finishes the open id connect login flow
#[utoipa::path(
    tag = "OpenId Connect",
    context_path = "/api/v1/oidc",
    responses(
        (status = 307, description = "Redirect to \"/\""),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse)
    ),
)]
#[get("/finish_login")]
pub async fn finish_oidc_login(
    session: Session,
    Query(request): Query<FinishOidcLoginRequest>,
) -> ApiResult<Redirect> {
    let claims = GLOBAL
        .oidc
        .finish_login(
            session
                .remove_as(SESSION_KEY)
                .ok_or_else(|| {
                    info!("Called finish_oidc_login before calling begin_oidc_login");
                    ApiError::LoginFailed
                })?
                .map_err(|_| {
                    error!("Failed to deserialize session value");
                    ApiError::InternalServerError
                })?,
            OidcRequestState {
                code: request.code,
                state: request.state,
            },
        )
        .await?;

    debug!("Got claims: {claims:#?}");

    let subject = claims.subject();

    let Some(username) = claims.preferred_username().map(|x| x.to_string()) else {
        error!("Missing `preferred_username` claim");
        return Err(ApiError::InternalServerError);
    };

    let Some(claim_name) = claims.name() else {
        error!("Missing `name` claim");
        return Err(ApiError::InternalServerError);
    };

    let Some(display_name) = claim_name.get(None).map(|x| x.to_string()) else {
        error!("Missing localization for `name` claim");
        return Err(ApiError::InternalServerError);
    };

    let mut tx = GLOBAL.db.start_transaction().await?;

    let user_uuid = if let Some((user,)) = query!(&mut tx, (OidcUser::F.user as User,))
        .condition(OidcUser::F.subject.equals(subject.as_str()))
        .optional()
        .await?
    {
        let mut update = update!(&mut tx, User).set(User::F.last_login, Some(Utc::now()));
        if user.username != username {
            update = update.set(User::F.username, username);
        }
        if user.display_name != display_name {
            update = update.set(User::F.display_name, display_name);
        }
        update.condition(user.as_condition()).await?;

        user.uuid
    } else {
        User::insert_oidc_user(
            &mut tx,
            subject.to_string(),
            username,
            display_name,
            UserPermission::Default,
        )
        .await?
    };

    tx.commit().await?;

    session.insert("uuid", user_uuid)?;
    session.insert("logged_in", true)?;

    Ok(Redirect::to("/"))
}

const SESSION_KEY: &str = "begin_oidc_login";
