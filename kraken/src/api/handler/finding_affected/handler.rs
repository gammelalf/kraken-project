use actix_web::delete;
use actix_web::get;
use actix_web::post;
use actix_web::put;
use actix_web::web::Json;
use actix_web::web::Path;
use actix_web::HttpResponse;
use futures::TryStreamExt;
use rorm::prelude::*;
use rorm::query;
use rorm::update;

use crate::api::extractors::SessionUser;
use crate::api::handler::common::error::ApiError;
use crate::api::handler::common::error::ApiResult;
use crate::api::handler::common::schema::SimpleTag;
use crate::api::handler::domains::schema::SimpleDomain;
use crate::api::handler::finding_affected::schema::CreateFindingAffectedRequest;
use crate::api::handler::finding_affected::schema::FindingAffectedObject;
use crate::api::handler::finding_affected::schema::FullFindingAffected;
use crate::api::handler::finding_affected::schema::PathFindingAffected;
use crate::api::handler::finding_affected::schema::UpdateFindingAffectedRequest;
use crate::api::handler::finding_affected::utils::query_finding_affected;
use crate::api::handler::finding_categories::schema::SimpleFindingCategory;
use crate::api::handler::finding_definitions::schema::SimpleFindingDefinition;
use crate::api::handler::findings::schema::FullFinding;
use crate::api::handler::findings::schema::PathFinding;
use crate::api::handler::findings::utils::finding_affected_into_simple;
use crate::api::handler::hosts::schema::SimpleHost;
use crate::api::handler::http_services::schema::SimpleHttpService;
use crate::api::handler::ports::schema::SimplePort;
use crate::api::handler::services::schema::SimpleService;
use crate::chan::global::GLOBAL;
use crate::chan::ws_manager::schema::WsMessage;
use crate::models::convert::FromDb;
use crate::models::Domain;
use crate::models::DomainGlobalTag;
use crate::models::DomainWorkspaceTag;
use crate::models::Finding;
use crate::models::FindingAffected;
use crate::models::FindingDefinitionCategoryRelation;
use crate::models::FindingDetails;
use crate::models::FindingFindingCategoryRelation;
use crate::models::GlobalTag;
use crate::models::Host;
use crate::models::HostGlobalTag;
use crate::models::HostWorkspaceTag;
use crate::models::HttpService;
use crate::models::HttpServiceGlobalTag;
use crate::models::HttpServiceWorkspaceTag;
use crate::models::Port;
use crate::models::PortGlobalTag;
use crate::models::PortWorkspaceTag;
use crate::models::Service;
use crate::models::ServiceGlobalTag;
use crate::models::ServiceWorkspaceTag;
use crate::models::Workspace;
use crate::models::WorkspaceTag;

/// Add a new affected object to a finding
#[utoipa::path(
    tag = "Findings",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Affected object was added successfully"),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    request_body = CreateFindingAffectedRequest,
    params(PathFinding),
    security(("api_key" = []))
)]
#[post("/workspace/{w_uuid}/findings/{f_uuid}/affected")]
pub async fn create_finding_affected(
    path: Path<PathFinding>,
    Json(request): Json<CreateFindingAffectedRequest>,
    SessionUser(u_uuid): SessionUser,
) -> ApiResult<HttpResponse> {
    let PathFinding { w_uuid, f_uuid } = path.into_inner();

    let mut tx = GLOBAL.db.start_transaction().await?;
    if !Workspace::is_user_member_or_owner(&mut tx, w_uuid, u_uuid).await? {
        return Err(ApiError::NotFound);
    }

    query!(&mut tx, (Finding::F.uuid,))
        .condition(Finding::F.uuid.equals(f_uuid))
        .optional()
        .await?
        .ok_or(ApiError::NotFound)?;

    let already_exists =
        query_finding_affected(&mut tx, (FindingAffected::F.uuid,), f_uuid, request.uuid)
            .await?
            .is_some();
    if already_exists {
        return Err(ApiError::InvalidUuid);
    }

    FindingAffected::insert(
        &mut tx,
        f_uuid,
        request.uuid,
        request.r#type,
        w_uuid,
        request.export_details,
        request.user_details,
        None,
        request.screenshot,
        request.log_file,
    )
    .await?;

    tx.commit().await?;
    GLOBAL
        .ws
        .message_workspace(
            w_uuid,
            WsMessage::AddedFindingAffected {
                workspace: w_uuid,
                finding: f_uuid,
                affected_uuid: request.uuid,
                affected_type: request.r#type,
            },
        )
        .await;
    Ok(HttpResponse::Ok().finish())
}

/// Get an object affected by a finding
#[utoipa::path(
    tag = "Findings",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "A full finding and the affected object", body = FullFindingAffected),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    params(PathFindingAffected),
    security(("api_key" = []))
)]
#[get("/workspace/{w_uuid}/findings/{f_uuid}/affected/{a_uuid}")]
pub async fn get_finding_affected(
    path: Path<PathFindingAffected>,
    SessionUser(u_uuid): SessionUser,
) -> ApiResult<Json<FullFindingAffected>> {
    #[rustfmt::skip]
    let PathFindingAffected { w_uuid, f_uuid, a_uuid, } = path.into_inner();

    let mut tx = GLOBAL.db.start_transaction().await?;
    if !Workspace::is_user_member_or_owner(&mut tx, w_uuid, u_uuid).await? {
        return Err(ApiError::NotFound);
    }

    let (
        finding,
        finding_details,
        finding_definition_uuid,
        finding_definition_name,
        finding_definition_cve,
        finding_definition_severity,
        finding_definition_summary,
        finding_definition_created_at,
        domain,
        host,
        port,
        service,
        http_service,
        details,
        created_at,
    ) = query_finding_affected(
        &mut tx,
        (
            FindingAffected::F.finding.select_as::<Finding>(),
            FindingAffected::F
                .finding
                .details
                .select_as::<FindingDetails>(),
            FindingAffected::F.finding.definition.uuid,
            FindingAffected::F.finding.definition.name,
            FindingAffected::F.finding.definition.cve,
            FindingAffected::F.finding.definition.severity,
            FindingAffected::F.finding.definition.summary,
            FindingAffected::F.finding.definition.created_at,
            FindingAffected::F.domain,
            FindingAffected::F.host,
            FindingAffected::F.port,
            FindingAffected::F.service,
            FindingAffected::F.http_service,
            FindingAffected::F.details,
            FindingAffected::F.created_at,
        ),
        f_uuid,
        a_uuid,
    )
    .await?
    .ok_or(ApiError::NotFound)?;

    let mut details = if let Some(details) = details {
        Some(
            query!(&mut tx, FindingDetails)
                .condition(FindingDetails::F.uuid.equals(*details.key()))
                .one()
                .await?,
        )
    } else {
        None
    };

    let finding_affected = query!(&mut tx, FindingAffected)
        .condition(FindingAffected::F.finding.equals(f_uuid))
        .stream()
        .map_err(ApiError::DatabaseError)
        .and_then(|x| std::future::ready(finding_affected_into_simple(x)))
        .try_collect()
        .await?;

    let (affected, affected_tags) = match (domain, host, port, service, http_service) {
        (Some(fm), None, None, None, None) => {
            let domain = query!(&mut tx, Domain)
                .condition(Domain::F.uuid.equals(*fm.key()))
                .one()
                .await?;

            let mut tags: Vec<_> = query!(&mut tx, (DomainGlobalTag::F.global_tag as GlobalTag,))
                .condition(DomainGlobalTag::F.domain.equals(domain.uuid))
                .stream()
                .map_ok(|(tag,)| SimpleTag::from(tag))
                .try_collect()
                .await?;

            let global_tags: Vec<_> = query!(
                &mut tx,
                (DomainWorkspaceTag::F.workspace_tag as WorkspaceTag,)
            )
            .condition(DomainWorkspaceTag::F.domain.equals(domain.uuid))
            .stream()
            .map_ok(|(tag,)| SimpleTag::from(tag))
            .try_collect()
            .await?;

            tags.extend(global_tags);

            (
                FindingAffectedObject::Domain(SimpleDomain {
                    uuid: domain.uuid,
                    domain: domain.domain,
                    comment: domain.comment,
                    workspace: *domain.workspace.key(),
                    created_at: domain.created_at,
                    certainty: FromDb::from_db(domain.certainty),
                }),
                tags,
            )
        }
        (None, Some(fm), None, None, None) => {
            let host = query!(&mut tx, Host)
                .condition(Host::F.uuid.equals(*fm.key()))
                .one()
                .await?;

            let mut tags: Vec<_> = query!(&mut tx, (HostGlobalTag::F.global_tag as GlobalTag,))
                .condition(HostGlobalTag::F.host.equals(host.uuid))
                .stream()
                .map_ok(|(tag,)| SimpleTag::from(tag))
                .try_collect()
                .await?;

            let global_tags: Vec<_> = query!(
                &mut tx,
                (HostWorkspaceTag::F.workspace_tag as WorkspaceTag,)
            )
            .condition(HostWorkspaceTag::F.host.equals(host.uuid))
            .stream()
            .map_ok(|(tag,)| SimpleTag::from(tag))
            .try_collect()
            .await?;

            tags.extend(global_tags);

            (
                FindingAffectedObject::Host(SimpleHost {
                    uuid: host.uuid,
                    ip_addr: host.ip_addr.ip(),
                    os_type: FromDb::from_db(host.os_type),
                    response_time: host.response_time,
                    comment: host.comment,
                    workspace: *host.workspace.key(),
                    created_at: host.created_at,
                    certainty: FromDb::from_db(host.certainty),
                }),
                tags,
            )
        }
        (None, None, Some(fm), None, None) => {
            let port = query!(&mut tx, Port)
                .condition(Port::F.uuid.equals(*fm.key()))
                .one()
                .await?;

            let mut tags: Vec<_> = query!(&mut tx, (PortGlobalTag::F.global_tag as GlobalTag,))
                .condition(PortGlobalTag::F.port.equals(port.uuid))
                .stream()
                .map_ok(|(tag,)| SimpleTag::from(tag))
                .try_collect()
                .await?;

            let global_tags: Vec<_> = query!(
                &mut tx,
                (PortWorkspaceTag::F.workspace_tag as WorkspaceTag,)
            )
            .condition(PortWorkspaceTag::F.port.equals(port.uuid))
            .stream()
            .map_ok(|(tag,)| SimpleTag::from(tag))
            .try_collect()
            .await?;

            tags.extend(global_tags);

            (
                FindingAffectedObject::Port(SimplePort {
                    uuid: port.uuid,
                    port: port.port as u16,
                    protocol: FromDb::from_db(port.protocol),
                    certainty: FromDb::from_db(port.certainty),
                    host: *port.host.key(),
                    comment: port.comment,
                    workspace: *port.workspace.key(),
                    created_at: port.created_at,
                }),
                tags,
            )
        }
        (None, None, None, Some(fm), None) => {
            let service = query!(&mut tx, Service)
                .condition(Service::F.uuid.equals(*fm.key()))
                .one()
                .await?;

            let mut tags: Vec<_> = query!(&mut tx, (ServiceGlobalTag::F.global_tag as GlobalTag,))
                .condition(ServiceGlobalTag::F.service.equals(service.uuid))
                .stream()
                .map_ok(|(tag,)| SimpleTag::from(tag))
                .try_collect()
                .await?;

            let global_tags: Vec<_> = query!(
                &mut tx,
                (ServiceWorkspaceTag::F.workspace_tag as WorkspaceTag,)
            )
            .condition(ServiceWorkspaceTag::F.service.equals(service.uuid))
            .stream()
            .map_ok(|(tag,)| SimpleTag::from(tag))
            .try_collect()
            .await?;

            tags.extend(global_tags);

            (
                FindingAffectedObject::Service(SimpleService {
                    uuid: service.uuid,
                    name: service.name,
                    version: service.version,
                    certainty: FromDb::from_db(service.certainty),
                    host: *service.host.key(),
                    port: service.port.map(|fm| *fm.key()),
                    comment: service.comment,
                    workspace: *service.workspace.key(),
                    created_at: service.created_at,
                }),
                tags,
            )
        }
        (None, None, None, None, Some(fm)) => {
            let http_service = query!(&mut tx, HttpService)
                .condition(HttpService::F.uuid.equals(*fm.key()))
                .one()
                .await?;

            let global_tags: Vec<_> =
                query!(&mut tx, (HttpServiceGlobalTag::F.global_tag as GlobalTag,))
                    .condition(
                        HttpServiceGlobalTag::F
                            .http_service
                            .equals(http_service.uuid),
                    )
                    .stream()
                    .map_ok(|(tag,)| SimpleTag::from(tag))
                    .try_collect()
                    .await?;

            let mut tags: Vec<_> = query!(
                &mut tx,
                (HttpServiceWorkspaceTag::F.workspace_tag as WorkspaceTag,)
            )
            .condition(
                HttpServiceWorkspaceTag::F
                    .http_service
                    .equals(http_service.uuid),
            )
            .stream()
            .map_ok(|(tag,)| SimpleTag::from(tag))
            .try_collect()
            .await?;

            tags.extend(global_tags);

            (
                FindingAffectedObject::HttpService(SimpleHttpService {
                    uuid: http_service.uuid,
                    name: http_service.name,
                    version: http_service.version,
                    domain: http_service.domain.map(|fm| *fm.key()),
                    host: *http_service.host.key(),
                    port: *http_service.port.key(),
                    base_path: http_service.base_path,
                    tls: http_service.tls,
                    sni_required: http_service.sni_required,
                    comment: http_service.comment,
                    certainty: FromDb::from_db(http_service.certainty),
                    workspace: *http_service.workspace.key(),
                    created_at: http_service.created_at,
                }),
                tags,
            )
        }
        _ => return Err(ApiError::InternalServerError),
    };

    let categories = SimpleFindingCategory::query_for_single(
        &mut tx,
        FindingFindingCategoryRelation::F.category,
        FindingFindingCategoryRelation::F.finding,
        finding.uuid,
    )
    .await?;

    let finding_definition_categories = SimpleFindingCategory::query_for_single(
        &mut tx,
        FindingDefinitionCategoryRelation::F.category,
        FindingDefinitionCategoryRelation::F.definition,
        finding_definition_uuid,
    )
    .await?;

    tx.commit().await?;
    Ok(Json(FullFindingAffected {
        finding: FullFinding {
            uuid: finding.uuid,
            definition: SimpleFindingDefinition {
                uuid: finding_definition_uuid,
                name: finding_definition_name,
                cve: finding_definition_cve,
                severity: FromDb::from_db(finding_definition_severity),
                summary: finding_definition_summary,
                created_at: finding_definition_created_at,
                categories: finding_definition_categories,
            },
            severity: FromDb::from_db(finding.severity),
            affected: finding_affected,
            #[rustfmt::skip]
            export_details: GLOBAL.editor_cache.finding_export_details.get(finding.uuid).await?.unwrap_or_default().0,
            #[rustfmt::skip]
            user_details: GLOBAL.editor_cache.finding_user_details.get(finding.uuid).await?.unwrap_or_default().0,
            tool_details: finding_details.tool_details,
            screenshot: finding_details.screenshot.map(|fm| *fm.key()),
            log_file: finding_details.log_file.map(|fm| *fm.key()),
            created_at: finding.created_at,
            categories,
        },
        affected,
        affected_tags,
        #[rustfmt::skip]
        export_details: GLOBAL.editor_cache.finding_affected_export_details.get((f_uuid, a_uuid)).await?.unwrap_or_default().0,
        #[rustfmt::skip]
        user_details: GLOBAL.editor_cache.finding_affected_user_details.get((f_uuid, a_uuid)).await?.unwrap_or_default().0,
        tool_details: details.as_mut().and_then(|d| d.tool_details.take()),
        screenshot: details
            .as_mut()
            .and_then(|d| d.screenshot.take().map(|fm| *fm.key())),
        log_file: details
            .as_mut()
            .and_then(|d| d.log_file.take().map(|fm| *fm.key())),
        created_at,
    }))
}

/// Update the details of an affected object
#[utoipa::path(
    tag = "Findings",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Affected object has been updated"),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    request_body = UpdateFindingAffectedRequest,
    params(PathFindingAffected),
    security(("api_key" = []))
)]
#[put("/workspace/{w_uuid}/findings/{f_uuid}/affected/{a_uuid}")]
pub async fn update_finding_affected(
    path: Path<PathFindingAffected>,
    Json(request): Json<UpdateFindingAffectedRequest>,
    SessionUser(u_uuid): SessionUser,
) -> ApiResult<HttpResponse> {
    #[rustfmt::skip]
    let PathFindingAffected { w_uuid, f_uuid, a_uuid, } = path.into_inner();

    if matches!(
        &request,
        UpdateFindingAffectedRequest {
            screenshot: None,
            log_file: None
        }
    ) {
        return Err(ApiError::EmptyJson);
    }

    let mut tx = GLOBAL.db.start_transaction().await?;
    if !Workspace::is_user_member_or_owner(&mut tx, w_uuid, u_uuid).await? {
        return Err(ApiError::NotFound);
    }

    let (details,) = query_finding_affected(&mut tx, (FindingAffected::F.details,), f_uuid, a_uuid)
        .await?
        .ok_or(ApiError::NotFound)?;

    if let Some(details) = details {
        FindingDetails::update(
            &mut tx,
            *details.key(),
            None,
            request.screenshot,
            request.log_file,
        )
        .await?;
    } else {
        let screenshot = request.screenshot.flatten();
        let log_file = request.log_file.flatten();
        if screenshot.is_some() || log_file.is_some() {
            let uuid = FindingDetails::insert(
                &mut tx,
                String::new(),
                String::new(),
                None,
                screenshot,
                log_file,
            )
            .await?;
            update!(&mut tx, FindingAffected)
                .set(
                    FindingAffected::F.details,
                    Some(ForeignModelByField::Key(uuid)),
                )
                .await?;
        }
    };

    tx.commit().await?;
    GLOBAL
        .ws
        .message_workspace(
            w_uuid,
            WsMessage::UpdatedFindingAffected {
                workspace: w_uuid,
                finding: f_uuid,
                affected_uuid: a_uuid,
                update: request,
            },
        )
        .await;
    Ok(HttpResponse::Ok().finish())
}

/// Remove an affected object from a finding
#[utoipa::path(
    tag = "Findings",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Affected object has been removed"),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    params(PathFindingAffected),
    security(("api_key" = []))
)]
#[delete("/workspace/{w_uuid}/findings/{f_uuid}/affected/{a_uuid}")]
pub async fn delete_finding_affected(
    path: Path<PathFindingAffected>,
    SessionUser(u_uuid): SessionUser,
) -> ApiResult<HttpResponse> {
    #[rustfmt::skip]
    let PathFindingAffected { w_uuid, f_uuid, a_uuid, } = path.into_inner();

    let mut tx = GLOBAL.db.start_transaction().await?;
    if !Workspace::is_user_member_or_owner(&mut tx, w_uuid, u_uuid).await? {
        return Err(ApiError::NotFound);
    }

    let (uuid,) = query_finding_affected(&mut tx, (FindingAffected::F.uuid,), f_uuid, a_uuid)
        .await?
        .ok_or(ApiError::NotFound)?;
    FindingAffected::delete(&mut tx, uuid).await?;
    GLOBAL
        .editor_cache
        .finding_affected_export_details
        .delete((f_uuid, a_uuid));
    GLOBAL
        .editor_cache
        .finding_affected_user_details
        .delete((f_uuid, a_uuid));

    tx.commit().await?;
    GLOBAL
        .ws
        .message_workspace(
            w_uuid,
            WsMessage::RemovedFindingAffected {
                workspace: w_uuid,
                finding: f_uuid,
                affected_uuid: a_uuid,
            },
        )
        .await;
    Ok(HttpResponse::Ok().finish())
}
