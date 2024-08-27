use std::collections::HashMap;

use actix_web::get;
use actix_web::post;
use actix_web::put;
use actix_web::web::Json;
use actix_web::web::Path;
use actix_web::HttpResponse;
use futures::TryStreamExt;
use rorm::and;
use rorm::insert;
use rorm::prelude::ForeignModelByField;
use rorm::query;
use rorm::update;
use rorm::FieldAccess;
use rorm::Model;
use uuid::Uuid;

use crate::api::handler::common::error::ApiError;
use crate::api::handler::common::error::ApiResult;
use crate::api::handler::common::schema::PathUuid;
use crate::api::handler::common::schema::UuidResponse;
use crate::api::handler::finding_categories::schema::SimpleFindingCategory;
use crate::api::handler::finding_definitions::schema::CreateFindingDefinitionRequest;
use crate::api::handler::finding_definitions::schema::FullFindingDefinition;
use crate::api::handler::finding_definitions::schema::ListFindingDefinitions;
use crate::api::handler::finding_definitions::schema::SimpleFindingDefinition;
use crate::api::handler::finding_definitions::schema::UpdateFindingDefinitionRequest;
use crate::chan::global::GLOBAL;
use crate::chan::ws_manager::schema::WsMessage;
use crate::models::convert::FromDb;
use crate::models::convert::IntoDb;
use crate::models::FindingCategory;
use crate::models::FindingDefinition;
use crate::models::FindingDefinitionCategoryRelation;
use crate::models::InsertFindingDefinition;

/// Add a definition for a finding
///
/// These definition serve as reference and knowledge base in kraken.
/// They can be used to create a finding that references a definition and links it to one or
/// multiple aggregations.
#[utoipa::path(
    tag = "Knowledge Base",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Finding definition was created", body = UuidResponse),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    request_body = CreateFindingDefinitionRequest,
    security(("api_key" = []))
)]
#[post("/findingDefinitions")]
pub async fn create_finding_definition(
    req: Json<CreateFindingDefinitionRequest>,
) -> ApiResult<Json<UuidResponse>> {
    let CreateFindingDefinitionRequest {
        name,
        summary,
        severity,
        cve,
        description,
        impact,
        remediation,
        references,
        categories,
    } = req.into_inner();

    if name.is_empty() {
        return Err(ApiError::InvalidName);
    }

    let mut tx = GLOBAL.db.start_transaction().await?;

    FindingCategory::exist_all(&mut tx, categories.iter().copied())
        .await?
        .ok_or(ApiError::InvalidUuid)?;

    let uuid = Uuid::new_v4();
    insert!(&mut tx, FindingDefinition)
        .single(&InsertFindingDefinition {
            uuid,
            name,
            summary,
            severity: severity.into_db(),
            cve,
            description,
            impact,
            remediation,
            references,
        })
        .await?;

    insert!(&mut tx, FindingDefinitionCategoryRelation)
        .return_nothing()
        .bulk(
            categories
                .into_iter()
                .map(|cat| FindingDefinitionCategoryRelation {
                    uuid: Uuid::new_v4(),
                    definition: ForeignModelByField::Key(uuid),
                    category: ForeignModelByField::Key(cat),
                }),
        )
        .await?;

    tx.commit().await?;

    GLOBAL.editor_cache.fd_summary.invalidate_not_found();
    GLOBAL.editor_cache.fd_description.invalidate_not_found();
    GLOBAL.editor_cache.fd_impact.invalidate_not_found();
    GLOBAL.editor_cache.fd_remediation.invalidate_not_found();
    GLOBAL.editor_cache.fd_references.invalidate_not_found();

    Ok(Json(UuidResponse { uuid }))
}

/// Retrieve a specific finding definition
#[utoipa::path(
    tag = "Knowledge Base",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Retrieved a specific finding definition", body = FullFindingDefinition),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    params(PathUuid),
    security(("api_key" = []))
)]
#[get("/findingDefinitions/{uuid}")]
pub async fn get_finding_definition(
    path: Path<PathUuid>,
) -> ApiResult<Json<FullFindingDefinition>> {
    let uuid = path.into_inner().uuid;

    let mut tx = GLOBAL.db.start_transaction().await?;

    let finding_definition = query!(&mut tx, FindingDefinition)
        .condition(FindingDefinition::F.uuid.equals(uuid))
        .optional()
        .await?
        .ok_or(ApiError::InvalidUuid)?;

    let categories = query!(
        &mut tx,
        (
            FindingDefinitionCategoryRelation::F.category.uuid,
            FindingDefinitionCategoryRelation::F.category.name,
            FindingDefinitionCategoryRelation::F.category.color,
        )
    )
    .condition(FindingDefinitionCategoryRelation::F.definition.equals(uuid))
    .stream()
    .map_ok(|(uuid, name, color)| SimpleFindingCategory {
        uuid,
        name,
        color: FromDb::from_db(color),
    })
    .try_collect()
    .await?;

    tx.commit().await?;

    Ok(Json(FullFindingDefinition {
        uuid: finding_definition.uuid,
        name: finding_definition.name,
        #[rustfmt::skip]
        summary: GLOBAL.editor_cache.fd_summary.get(uuid).await?.ok_or(ApiError::InvalidUuid)?.0,
        severity: FromDb::from_db(finding_definition.severity),
        cve: finding_definition.cve,
        #[rustfmt::skip]
        description: GLOBAL.editor_cache.fd_description.get(uuid).await?.ok_or(ApiError::InvalidUuid)?.0,
        #[rustfmt::skip]
        impact: GLOBAL.editor_cache.fd_impact.get(uuid).await?.ok_or(ApiError::InvalidUuid)?.0,
        #[rustfmt::skip]
        remediation: GLOBAL.editor_cache.fd_remediation.get(uuid).await?.ok_or(ApiError::InvalidUuid)?.0,
        #[rustfmt::skip]
        references: GLOBAL.editor_cache.fd_references.get(uuid).await?.ok_or(ApiError::InvalidUuid)?.0,
        created_at: finding_definition.created_at,
        categories,
    }))
}

/// Retrieve all finding definitions
#[utoipa::path(
    tag = "Knowledge Base",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Retrieved a list of all finding definitions", body = ListFindingDefinitions),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    security(("api_key" = []))
)]
#[get("/findingDefinitions")]
pub async fn get_all_finding_definitions() -> ApiResult<Json<ListFindingDefinitions>> {
    let mut tx = GLOBAL.db.start_transaction().await?;

    let mut categories: HashMap<_, Vec<_>> = HashMap::new();
    let mut stream = query!(
        &mut tx,
        (
            FindingDefinitionCategoryRelation::F.definition.uuid,
            FindingDefinitionCategoryRelation::F.category.uuid,
            FindingDefinitionCategoryRelation::F.category.name,
            FindingDefinitionCategoryRelation::F.category.color,
        )
    )
    .stream();
    while let Some((finding_definition, uuid, name, color)) = stream.try_next().await? {
        categories
            .entry(finding_definition)
            .or_default()
            .push(SimpleFindingCategory {
                uuid,
                name,
                color: FromDb::from_db(color),
            });
    }
    drop(stream);

    let mut finding_definitions: Vec<SimpleFindingDefinition> = query!(&mut tx, FindingDefinition)
        .stream()
        .map_ok(|fd| SimpleFindingDefinition {
            uuid: fd.uuid,
            name: fd.name,
            cve: fd.cve,
            summary: fd.summary,
            severity: FromDb::from_db(fd.severity),
            created_at: fd.created_at,
            categories: categories.remove(&fd.uuid).unwrap_or_default(),
        })
        .try_collect()
        .await?;

    for fd in &mut finding_definitions {
        fd.summary = GLOBAL
            .editor_cache
            .fd_summary
            .get(fd.uuid)
            .await?
            .ok_or(ApiError::InternalServerError)?
            .0;
    }

    Ok(Json(ListFindingDefinitions {
        finding_definitions,
    }))
}

/// Update a finding definition
///
/// This endpoint only allows updating the `name`, `severity` and `cve`.
/// The other values have to be updated through the websocket as part of a live editor.
#[utoipa::path(
    tag = "Knowledge Base",
    context_path = "/api/v1",
    responses(
        (status = 200, description = "Updated a finding definition"),
        (status = 400, description = "Client error", body = ApiErrorResponse),
        (status = 500, description = "Server error", body = ApiErrorResponse),
    ),
    params(PathUuid),
    request_body = UpdateFindingDefinitionRequest,
    security(("api_key" = []))
)]
#[put("/findingDefinitions/{uuid}")]
pub async fn update_finding_definition(
    path: Path<PathUuid>,
    Json(request): Json<UpdateFindingDefinitionRequest>,
) -> ApiResult<HttpResponse> {
    let PathUuid { uuid } = path.into_inner();

    if matches!(
        &request,
        UpdateFindingDefinitionRequest {
            name: None,
            severity: None,
            cve: None,
            categories: None,
        }
    ) {
        return Err(ApiError::EmptyJson);
    }

    let mut tx = GLOBAL.db.start_transaction().await?;

    query!(&mut tx, (FindingDefinition::F.uuid,))
        .condition(FindingDefinition::F.uuid.equals(uuid))
        .optional()
        .await?
        .ok_or(ApiError::InvalidUuid)?;

    if let Some(new_name) = request.name.as_deref() {
        if query!(&mut tx, (FindingDefinition::F.uuid,))
            .condition(and![
                FindingDefinition::F.uuid.not_equals(uuid),
                FindingDefinition::F.name.equals(new_name)
            ])
            .optional()
            .await?
            .is_some()
        {
            return Err(ApiError::NameAlreadyExists);
        }
    }

    if let Ok(update) = update!(&mut tx, FindingDefinition)
        .begin_dyn_set()
        .condition(FindingDefinition::F.uuid.equals(uuid))
        .set_if(FindingDefinition::F.name, request.name.clone())
        .set_if(FindingDefinition::F.cve, request.cve.clone())
        .set_if(
            FindingDefinition::F.severity,
            request.severity.map(IntoDb::into_db),
        )
        .finish_dyn_set()
    {
        update.exec().await?;
    }

    if let Some(categories) = request.categories.clone() {
        FindingCategory::exist_all(&mut tx, categories.iter().copied())
            .await?
            .ok_or(ApiError::InvalidUuid)?;

        rorm::delete!(&mut tx, FindingDefinitionCategoryRelation)
            .condition(FindingDefinitionCategoryRelation::F.definition.equals(uuid))
            .await?;

        insert!(&mut tx, FindingDefinitionCategoryRelation)
            .return_nothing()
            .bulk(
                categories
                    .into_iter()
                    .map(|cat| FindingDefinitionCategoryRelation {
                        uuid: Uuid::new_v4(),
                        definition: ForeignModelByField::Key(uuid),
                        category: ForeignModelByField::Key(cat),
                    }),
            )
            .await?;
    }

    tx.commit().await?;

    GLOBAL
        .ws
        .message_all(WsMessage::UpdatedFindingDefinition {
            uuid,
            update: request,
        })
        .await;
    Ok(HttpResponse::Ok().finish())
}
