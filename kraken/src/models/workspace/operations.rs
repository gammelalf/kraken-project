use chrono::{DateTime, Utc};
use rorm::db::Executor;
use rorm::prelude::*;
use rorm::{and, insert, query};
use thiserror::Error;
use uuid::Uuid;

use crate::api::handler::ApiError;
use crate::models::{
    OauthClient, User, Workspace, WorkspaceAccessToken, WorkspaceInvitation, WorkspaceMember,
};

#[derive(Patch)]
#[rorm(model = "WorkspaceMember")]
struct WorkspaceMemberInsert {
    member: ForeignModel<User>,
    workspace: ForeignModel<Workspace>,
}

#[derive(Patch)]
#[rorm(model = "Workspace")]
struct WorkspaceInsert {
    uuid: Uuid,
    name: String,
    description: Option<String>,
    owner: ForeignModel<User>,
}

#[derive(Patch)]
#[rorm(model = "WorkspaceAccessToken")]
struct WorkspaceAccessTokenInsert {
    token: String,
    user: ForeignModel<User>,
    workspace: ForeignModel<Workspace>,
    expires_at: DateTime<Utc>,
    application: ForeignModel<OauthClient>,
}

/// The errors can occur while inserting a new workspace
#[derive(Error, Debug)]
pub enum InsertWorkspaceError {
    #[error("An database error occurred")]
    DatabaseError(#[from] rorm::Error),
    #[error("An empty name was given")]
    EmptyName,
}

impl From<InsertWorkspaceError> for ApiError {
    fn from(value: InsertWorkspaceError) -> Self {
        match value {
            InsertWorkspaceError::DatabaseError(x) => ApiError::DatabaseError(x),
            InsertWorkspaceError::EmptyName => ApiError::InvalidName,
        }
    }
}

impl Workspace {
    /// Check if a user is owner or member of a workspace
    pub async fn is_user_member_or_owner(
        executor: impl Executor<'_>,
        workspace: Uuid,
        user: Uuid,
    ) -> Result<bool, rorm::Error> {
        let mut guard = executor.ensure_transaction().await?;

        // Check existence of workspace
        let Some((owner,)) = query!(guard.get_transaction(), (Workspace::F.owner,))
            .condition(Workspace::F.uuid.equals(workspace))
            .optional()
            .await?
        else {
            return Ok(false);
        };

        // Check if user is owner or member
        if *owner.key() != user {
            let existent = query!(guard.get_transaction(), (WorkspaceMember::F.id,))
                .condition(and!(
                    WorkspaceMember::F.member.equals(user),
                    WorkspaceMember::F.workspace.equals(workspace)
                ))
                .optional()
                .await?;

            if existent.is_none() {
                return Ok(false);
            }
        }

        guard.commit().await?;

        Ok(true)
    }

    /// Checks whether a user is owner of a specific workspace
    pub async fn is_owner(
        executor: impl Executor<'_>,
        workspace: Uuid,
        user: Uuid,
    ) -> Result<bool, rorm::Error> {
        Ok(query!(executor, (Workspace::F.owner,))
            .condition(and!(
                Workspace::F.uuid.equals(workspace),
                Workspace::F.owner.equals(user)
            ))
            .optional()
            .await?
            .is_some())
    }

    /// Check whether a workspace exists
    pub async fn exists(executor: impl Executor<'_>, uuid: Uuid) -> Result<bool, rorm::Error> {
        Ok(query!(executor, (Workspace::F.uuid,))
            .condition(Workspace::F.uuid.equals(uuid))
            .optional()
            .await?
            .is_some())
    }

    /// Insert a new workspace for an user
    pub async fn insert(
        executor: impl Executor<'_>,
        name: String,
        description: Option<String>,
        owner: Uuid,
    ) -> Result<Uuid, InsertWorkspaceError> {
        let uuid = Uuid::new_v4();

        if name.is_empty() {
            return Err(InsertWorkspaceError::EmptyName);
        }

        insert!(executor, WorkspaceInsert)
            .return_nothing()
            .single(&WorkspaceInsert {
                uuid,
                name,
                description,
                owner: ForeignModelByField::Key(owner),
            })
            .await?;

        Ok(uuid)
    }
}

impl WorkspaceAccessToken {
    /// Insert a workspace access token
    pub async fn insert(
        executor: impl Executor<'_>,
        token: String,
        expires_at: DateTime<Utc>,
        user: Uuid,
        workspace: Uuid,
        application: Uuid,
    ) -> Result<i64, rorm::Error> {
        insert!(executor, WorkspaceAccessTokenInsert)
            .return_primary_key()
            .single(&WorkspaceAccessTokenInsert {
                token,
                expires_at,
                user: ForeignModelByField::Key(user),
                workspace: ForeignModelByField::Key(workspace),
                application: ForeignModelByField::Key(application),
            })
            .await
    }
}

impl WorkspaceInvitation {
    /// Insert a new invitation for the workspace
    pub async fn insert(
        executor: impl Executor<'_>,
        workspace: Uuid,
        from: Uuid,
        target: Uuid,
    ) -> Result<(), InsertWorkspaceInvitationError> {
        if from == target {
            return Err(InsertWorkspaceInvitationError::InvalidTarget);
        }

        let mut guard = executor.ensure_transaction().await?;

        if !Workspace::exists(guard.get_transaction(), workspace).await? {
            return Err(InsertWorkspaceInvitationError::InvalidWorkspace);
        }

        if !Workspace::is_owner(guard.get_transaction(), workspace, from).await? {
            return Err(InsertWorkspaceInvitationError::MissingPrivileges);
        }

        if !User::exists(guard.get_transaction(), target).await? {
            return Err(InsertWorkspaceInvitationError::InvalidTarget);
        }

        // Check if target is already part of the workspace
        if query!(guard.get_transaction(), (WorkspaceMember::F.id,))
            .condition(and!(
                WorkspaceMember::F.workspace.equals(workspace),
                WorkspaceMember::F.member.equals(target)
            ))
            .optional()
            .await?
            .is_some()
        {
            return Err(InsertWorkspaceInvitationError::AlreadyInWorkspace);
        }

        // Check if the user was already invited
        if query!(guard.get_transaction(), (WorkspaceInvitation::F.uuid,))
            .condition(and!(
                WorkspaceInvitation::F.workspace.equals(workspace),
                WorkspaceInvitation::F.target.equals(target),
                WorkspaceInvitation::F.from.equals(from)
            ))
            .optional()
            .await?
            .is_some()
        {
            return Err(InsertWorkspaceInvitationError::InvalidTarget);
        }

        guard.commit().await?;

        Ok(())
    }
}

/// The errors that can occur when inserting an invitation to an workspace
#[derive(Debug, Error)]
pub enum InsertWorkspaceInvitationError {
    /// A database error
    #[error("Database error occurred: {0}")]
    Database(#[from] rorm::Error),
    /// Invalid workspace
    #[error("Invalid workspace")]
    InvalidWorkspace,
    /// Missing privileges
    #[error("Missing privileges")]
    MissingPrivileges,
    /// Invalid target user
    #[error("Invalid target user")]
    InvalidTarget,
    /// The target is already part of the workspace
    #[error("The target is already part of the workspace")]
    AlreadyInWorkspace,
    /// The user was already invited
    #[error("The user was already invited")]
    AlreadyInvited,
}

impl From<InsertWorkspaceInvitationError> for ApiError {
    fn from(value: InsertWorkspaceInvitationError) -> Self {
        match value {
            InsertWorkspaceInvitationError::Database(x) => ApiError::DatabaseError(x),
            InsertWorkspaceInvitationError::InvalidWorkspace => ApiError::InvalidWorkspace,
            InsertWorkspaceInvitationError::MissingPrivileges => ApiError::MissingPrivileges,
            InsertWorkspaceInvitationError::InvalidTarget => ApiError::InvalidTarget,
            InsertWorkspaceInvitationError::AlreadyInWorkspace => ApiError::AlreadyMember,
            InsertWorkspaceInvitationError::AlreadyInvited => ApiError::AlreadyInvited,
        }
    }
}
