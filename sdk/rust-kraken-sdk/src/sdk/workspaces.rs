use kraken::api::handler::workspaces::schema::FullWorkspace;
use kraken::api::handler::workspaces::schema::ListWorkspaces;
use uuid::Uuid;

use crate::KrakenClient;
use crate::KrakenResult;

impl KrakenClient {
    /// Retrieve all workspaces the user has access to
    pub async fn get_all_workspaces(&self) -> KrakenResult<ListWorkspaces> {
        self.get("api/v1/workspaces").send().await
    }

    /// Retrieve a workspace by its uuid
    pub async fn get_workspace(&self, workspace: Uuid) -> KrakenResult<FullWorkspace> {
        self.get(&format!("api/v1/workspaces/{workspace}"))
            .send()
            .await
    }
}
