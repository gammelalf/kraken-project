use rorm::conditions::DynamicCollection;
use rorm::db::Executor;
use rorm::delete;
use rorm::insert;
use rorm::prelude::ForeignModel;
use rorm::prelude::ForeignModelByField;
use rorm::query;
use rorm::update;
use rorm::FieldAccess;
use rorm::Model;
use rorm::Patch;
use thiserror::Error;
use uuid::Uuid;

use crate::api::handler::common::error::ApiError;
use crate::chan::ws_manager::schema::AggregationType;
use crate::models::Domain;
use crate::models::Finding;
use crate::models::FindingAffected;
use crate::models::FindingCategory;
use crate::models::FindingDefinition;
use crate::models::FindingDetails;
use crate::models::FindingSeverity;
use crate::models::Host;
use crate::models::HttpService;
use crate::models::MediaFile;
use crate::models::Port;
use crate::models::Service;
use crate::models::Workspace;

impl Finding {
    /// Insert a new [`Finding`]
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn insert(
        executor: impl Executor<'_>,
        workspace: Uuid,
        definition: Uuid,
        severity: FindingSeverity,
        export_details: String,
        user_details: String,
        tool_details: Option<String>,
        screenshot: Option<Uuid>,
        log_file: Option<Uuid>,
    ) -> Result<Uuid, InsertFindingDetailsError> {
        let uuid = Uuid::new_v4();

        let mut guard = executor.ensure_transaction().await?;

        let details_uuid = FindingDetails::insert(
            guard.get_transaction(),
            export_details,
            user_details,
            tool_details,
            screenshot,
            log_file,
        )
        .await?;

        insert!(guard.get_transaction(), InsertFinding)
            .return_nothing()
            .single(&InsertFinding {
                uuid,
                definition: ForeignModelByField::Key(definition),
                severity,
                details: ForeignModelByField::Key(details_uuid),
                workspace: ForeignModelByField::Key(workspace),
            })
            .await?;

        guard.commit().await?;

        Ok(uuid)
    }

    /// Deletes a [`Finding`]
    ///
    /// Returns `false` if the `Finding` didn't existed in the first place.
    pub(crate) async fn delete(
        executor: impl Executor<'_>,
        uuid: Uuid,
    ) -> Result<bool, rorm::Error> {
        let mut guard = executor.ensure_transaction().await?;
        let Some((details,)) = query!(guard.get_transaction(), (Finding::F.details,))
            .condition(Finding::F.uuid.equals(uuid))
            .optional()
            .await?
        else {
            return Ok(false);
        };
        delete!(guard.get_transaction(), Finding)
            .condition(Finding::F.uuid.equals(uuid))
            .await?;
        delete!(guard.get_transaction(), FindingDetails)
            .condition(FindingDetails::F.uuid.equals(*details.key()))
            .await?;
        guard.commit().await?;
        Ok(true)
    }
}

impl FindingAffected {
    /// Insert a new [`FindingAffected`]
    #[allow(clippy::too_many_arguments)]
    pub async fn insert(
        executor: impl Executor<'_>,
        finding: Uuid,
        object_uuid: Uuid,
        object_type: AggregationType,
        workspace: Uuid,
        export_details: String,
        user_details: String,
        tool_details: Option<String>,
        screenshot: Option<Uuid>,
        log_file: Option<Uuid>,
    ) -> Result<Uuid, InsertFindingDetailsError> {
        let mut guard = executor.ensure_transaction().await?;
        let uuid = Uuid::new_v4();

        let details = if !export_details.is_empty()
            || !user_details.is_empty()
            || tool_details.is_some()
            || screenshot.is_some()
            || log_file.is_some()
        {
            Some(ForeignModelByField::Key(
                FindingDetails::insert(
                    guard.get_transaction(),
                    export_details,
                    user_details,
                    tool_details,
                    screenshot,
                    log_file,
                )
                .await?,
            ))
        } else {
            None
        };

        let mut patch = InsertFindingAffected {
            uuid,
            finding: ForeignModelByField::Key(finding),
            domain: None,
            host: None,
            port: None,
            service: None,
            http_service: None,
            details,
            workspace: ForeignModelByField::Key(workspace),
        };
        match object_type {
            AggregationType::Domain => patch.domain = Some(ForeignModelByField::Key(object_uuid)),
            AggregationType::Host => patch.host = Some(ForeignModelByField::Key(object_uuid)),
            AggregationType::Service => patch.service = Some(ForeignModelByField::Key(object_uuid)),
            AggregationType::Port => patch.port = Some(ForeignModelByField::Key(object_uuid)),
            AggregationType::HttpService => {
                patch.http_service = Some(ForeignModelByField::Key(object_uuid))
            }
        }

        insert!(guard.get_transaction(), FindingAffected)
            .single(&patch)
            .await?;

        guard.commit().await?;
        Ok(uuid)
    }

    /// Deletes a [`FindingAffected`]
    ///
    /// Returns `false` if the `FindingAffected` didn't exist in the first place.
    pub async fn delete(executor: impl Executor<'_>, uuid: Uuid) -> Result<bool, rorm::Error> {
        let mut guard = executor.ensure_transaction().await?;
        let Some((details,)) = query!(guard.get_transaction(), (FindingAffected::F.details,))
            .condition(FindingAffected::F.uuid.equals(uuid))
            .optional()
            .await?
        else {
            return Ok(false);
        };
        delete!(guard.get_transaction(), FindingAffected)
            .condition(FindingAffected::F.uuid.equals(uuid))
            .await?;
        if let Some(details) = details {
            delete!(guard.get_transaction(), FindingDetails)
                .condition(FindingDetails::F.uuid.equals(*details.key()))
                .await?;
        }
        guard.commit().await?;
        Ok(true)
    }
}

impl FindingDetails {
    /// Insert a new [`FindingDetails`]
    pub(crate) async fn insert(
        executor: impl Executor<'_>,
        export_details: String,
        user_details: String,
        tool_details: Option<String>,
        screenshot: Option<Uuid>,
        log_file: Option<Uuid>,
    ) -> Result<Uuid, InsertFindingDetailsError> {
        let uuid = Uuid::new_v4();

        let mut guard = executor.ensure_transaction().await?;

        if let Some(uuid) = screenshot {
            if !MediaFile::is_image(guard.get_transaction(), uuid).await? {
                return Err(InsertFindingDetailsError::InvalidScreenshot);
            }
        }

        if let Some(uuid) = log_file {
            if !MediaFile::exists(guard.get_transaction(), uuid).await? {
                return Err(InsertFindingDetailsError::InvalidLogFile);
            }
        }

        insert!(guard.get_transaction(), Self)
            .return_nothing()
            .single(&Self {
                uuid,
                export_details,
                user_details,
                tool_details,
                log_file: log_file.map(ForeignModelByField::Key),
                screenshot: screenshot.map(ForeignModelByField::Key),
            })
            .await?;

        guard.commit().await?;

        Ok(uuid)
    }

    /// Update an existing [`FindingDetails`]
    pub(crate) async fn update(
        executor: impl Executor<'_>,
        uuid: Uuid,
        tool_details: Option<Option<String>>,
        screenshot: Option<Option<Uuid>>,
        log_file: Option<Option<Uuid>>,
    ) -> Result<(), UpdateFindingDetailsError> {
        let mut guard = executor.ensure_transaction().await?;

        query!(guard.get_transaction(), (FindingDetails::F.uuid,))
            .condition(Self::F.uuid.equals(uuid))
            .optional()
            .await?
            .ok_or(UpdateFindingDetailsError::InvalidDetails)?;

        if let Some(Some(uuid)) = screenshot {
            if !MediaFile::is_image(guard.get_transaction(), uuid).await? {
                return Err(UpdateFindingDetailsError::InvalidScreenshot);
            }
        }

        if let Some(Some(uuid)) = log_file {
            if !MediaFile::exists(guard.get_transaction(), uuid).await? {
                return Err(UpdateFindingDetailsError::InvalidLogFile);
            }
        }

        if let Ok(update) = update!(guard.get_transaction(), Self)
            .condition(Self::F.uuid.equals(uuid))
            .begin_dyn_set()
            .set_if(Self::F.tool_details, tool_details)
            .set_if(
                Self::F.screenshot,
                screenshot.map(|opt| opt.map(ForeignModelByField::Key)),
            )
            .set_if(
                Self::F.log_file,
                log_file.map(|opt| opt.map(ForeignModelByField::Key)),
            )
            .finish_dyn_set()
        {
            update.await?;
        }

        guard.commit().await?;
        Ok(())
    }
}

impl FindingCategory {
    /// Check whether all categories in a list exist by quering their uuids
    ///
    /// This function returns a `Option<()>` instead of a `bool` to allow easier error propagation:
    /// ```norun
    /// fn example(db: &Database, finding_categories: Vec<Uuid>) -> Result<(), ApiError> {
    ///     FindingCategory::exist_all(db, finding_categories.iter().copied())
    ///         .await?
    ///         .ok_or(ApiError::InvalidUuid)?;
    ///     Ok(())
    /// }
    /// ```
    pub async fn exist_all(
        executor: impl Executor<'_>,
        uuids: impl IntoIterator<Item = Uuid>,
    ) -> Result<Option<()>, rorm::Error> {
        let tags: Vec<_> = uuids
            .into_iter()
            .map(|uuid| FindingCategory::F.uuid.equals(uuid))
            .collect();

        // Short circuit if the there are no uuids to check
        if tags.is_empty() {
            return Ok(Some(()));
        }

        let search = tags.len();
        let (found,) = query!(executor, (FindingCategory::F.uuid.count(),))
            .condition(DynamicCollection::or(tags))
            .one()
            .await?;
        Ok((found == search as i64).then_some(()))
    }
}

#[derive(Error, Debug)]
pub enum InsertFindingDetailsError {
    #[error("{0}")]
    Database(#[from] rorm::Error),
    #[error("The log file doesn't exist")]
    InvalidLogFile,
    #[error("The screenshot doesn't exist or is not an image")]
    InvalidScreenshot,
}

impl From<InsertFindingDetailsError> for ApiError {
    fn from(value: InsertFindingDetailsError) -> Self {
        match value {
            InsertFindingDetailsError::Database(error) => ApiError::DatabaseError(error),
            InsertFindingDetailsError::InvalidLogFile => ApiError::InvalidUuid,
            InsertFindingDetailsError::InvalidScreenshot => ApiError::InvalidUuid,
        }
    }
}

#[derive(Error, Debug)]
pub enum UpdateFindingDetailsError {
    #[error("{0}")]
    Database(#[from] rorm::Error),
    #[error("The details to update don't exist")]
    InvalidDetails,
    #[error("The log file doesn't exist")]
    InvalidLogFile,
    #[error("The screenshot doesn't exist or is not an image")]
    InvalidScreenshot,
}

impl From<UpdateFindingDetailsError> for ApiError {
    fn from(value: UpdateFindingDetailsError) -> Self {
        match value {
            UpdateFindingDetailsError::Database(error) => ApiError::DatabaseError(error),
            UpdateFindingDetailsError::InvalidDetails => ApiError::NotFound,
            UpdateFindingDetailsError::InvalidLogFile => ApiError::InvalidUuid,
            UpdateFindingDetailsError::InvalidScreenshot => ApiError::InvalidUuid,
        }
    }
}

#[derive(Patch)]
#[rorm(model = "Finding")]
struct InsertFinding {
    uuid: Uuid,
    definition: ForeignModel<FindingDefinition>,
    severity: FindingSeverity,
    details: ForeignModel<FindingDetails>,
    workspace: ForeignModel<Workspace>,
}

#[derive(Patch)]
#[rorm(model = "FindingAffected")]
struct InsertFindingAffected {
    uuid: Uuid,
    finding: ForeignModel<Finding>,
    domain: Option<ForeignModel<Domain>>,
    host: Option<ForeignModel<Host>>,
    port: Option<ForeignModel<Port>>,
    service: Option<ForeignModel<Service>>,
    http_service: Option<ForeignModel<HttpService>>,
    details: Option<ForeignModel<FindingDetails>>,
    workspace: ForeignModel<Workspace>,
}
