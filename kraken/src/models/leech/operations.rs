use rand::distributions::Alphanumeric;
use rand::distributions::DistString;
use rand::thread_rng;
use rorm::db::Executor;
use rorm::insert;
use rorm::prelude::*;
use rorm::query;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::api::handler::common::error::ApiError;
use crate::models::Leech;
use crate::modules::uri::check_leech_address;

#[derive(Patch)]
#[rorm(model = "Leech")]
struct LeechInsert {
    uuid: Uuid,
    name: String,
    address: String,
    description: Option<String>,
    secret: String,
}

/// The errors that can occur while creating a leech
#[derive(Error, Debug)]
pub enum InsertLeechError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(#[from] rorm::Error),
    /// Address already exists
    #[error("The address exists already")]
    AddressAlreadyExists,
    /// Name already exists
    #[error("The name exists already")]
    NameAlreadyExists,
    /// The address is invalid
    #[error("The address is invalid")]
    InvalidAddress,
}

impl From<InsertLeechError> for ApiError {
    fn from(value: InsertLeechError) -> Self {
        match value {
            InsertLeechError::DatabaseError(x) => ApiError::DatabaseError(x),
            InsertLeechError::AddressAlreadyExists => ApiError::AddressAlreadyExists,
            InsertLeechError::NameAlreadyExists => ApiError::NameAlreadyExists,
            InsertLeechError::InvalidAddress => ApiError::InvalidAddress,
        }
    }
}

impl Leech {
    /// Insert a [Leech]
    pub async fn insert(
        executor: impl Executor<'_>,
        name: String,
        address: Url,
        description: Option<String>,
    ) -> Result<Uuid, InsertLeechError> {
        let mut guard = executor.ensure_transaction().await?;

        let uuid = Uuid::new_v4();

        if !check_leech_address(&address) {
            return Err(InsertLeechError::InvalidAddress);
        }

        // Convert address to string
        let address = address.to_string();

        if query!(guard.get_transaction(), Leech)
            .condition(Leech::F.address.equals(&address))
            .optional()
            .await?
            .is_some()
        {
            return Err(InsertLeechError::AddressAlreadyExists);
        }

        if query!(guard.get_transaction(), Leech)
            .condition(Leech::F.name.equals(&name))
            .optional()
            .await?
            .is_some()
        {
            return Err(InsertLeechError::NameAlreadyExists);
        }

        let uuid = insert!(guard.get_transaction(), LeechInsert)
            .return_primary_key()
            .single(&LeechInsert {
                uuid,
                name,
                address,
                description,
                secret: Alphanumeric.sample_string(&mut thread_rng(), 255),
            })
            .await?;

        guard.commit().await?;

        Ok(uuid)
    }
}
