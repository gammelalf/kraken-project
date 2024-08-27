use std::net::IpAddr;

use ipnetwork::IpNetwork;
use kraken::api::handler::common::schema::HostResultsPage;
use kraken::api::handler::common::schema::UuidsResponse;
use kraken::api::handler::findings::schema::ListFindings;
use kraken::api::handler::findings::schema::SimpleFinding;
use kraken::api::handler::hosts::schema::CreateHostRequest;
use kraken::api::handler::hosts::schema::FullHost;
use kraken::api::handler::hosts::schema::GetAllHostsQuery;
use kraken::api::handler::hosts::schema::HostRelations;
use kraken::api::handler::hosts::schema::ManualHostCertainty;
use kraken::api::handler::hosts::schema::UpdateHostRequest;
use uuid::Uuid;

use crate::error::KrakenError;
use crate::KrakenClient;
use crate::KrakenResult;

impl KrakenClient {
    /// Add a host
    pub async fn add_host(
        &self,
        workspace: Uuid,
        ip_addr: IpAddr,
        certainty: ManualHostCertainty,
    ) -> KrakenResult<Uuid> {
        match &self
            .add_hosts(workspace, IpNetwork::from(ip_addr), certainty)
            .await?[..]
        {
            [] => Err(KrakenError::DeserializeError(
                "Body contains no uuid".to_string(),
            )),
            [uuid] => Ok(*uuid),
            _ => Err(KrakenError::DeserializeError(
                "Body contains multiple uuids".to_string(),
            )),
        }
    }

    /// Add an entire CIDR as hosts
    pub async fn add_hosts(
        &self,
        workspace: Uuid,
        ip_addr: IpNetwork,
        certainty: ManualHostCertainty,
    ) -> KrakenResult<Vec<Uuid>> {
        let uuids: UuidsResponse = self
            .post(&format!("api/v1/workspaces/{workspace}/hosts"))
            .body(CreateHostRequest { ip_addr, certainty })
            .send()
            .await?;

        Ok(uuids.uuids)
    }

    /// Get all hosts of a workspace
    pub async fn get_all_hosts(
        &self,
        workspace: Uuid,
        query: GetAllHostsQuery,
    ) -> KrakenResult<HostResultsPage> {
        self.post(&format!("api/v1/workspaces/{workspace}/hosts/all"))
            .body(query)
            .send()
            .await
    }

    /// Retrieve a single host
    pub async fn get_host(&self, workspace: Uuid, host: Uuid) -> KrakenResult<FullHost> {
        self.get(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .send()
            .await
    }

    /// Update a host
    ///
    /// At least one field in `update` must be not None
    pub async fn update_host(
        &self,
        workspace: Uuid,
        host: Uuid,
        update: UpdateHostRequest,
    ) -> KrakenResult<()> {
        self.put(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .body(update)
            .send()
            .await
    }

    /// Delete a host
    pub async fn delete_host(&self, workspace: Uuid, host: Uuid) -> KrakenResult<()> {
        self.delete(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .send()
            .await
    }

    /// Get the direct relations of a host
    pub async fn get_host_relations(
        &self,
        workspace: Uuid,
        host: Uuid,
    ) -> KrakenResult<HostRelations> {
        self.get(&format!(
            "api/v1/workspaces/{workspace}/hosts/{host}/relations"
        ))
        .send()
        .await
    }

    /// List all findings affecting the host
    pub async fn get_host_findings(
        &self,
        workspace: Uuid,
        host: Uuid,
    ) -> KrakenResult<Vec<SimpleFinding>> {
        let list: ListFindings = self
            .get(&format!(
                "api/v1/workspaces/{workspace}/hosts/{host}/findings"
            ))
            .send()
            .await?;
        Ok(list.findings)
    }
}
