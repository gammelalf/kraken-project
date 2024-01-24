use std::net::IpAddr;

use ipnetwork::IpNetwork;
use kraken::api::handler::common::schema::{HostResultsPage, PageParams, UuidResponse};
use kraken::api::handler::domains::schema::GetAllDomainsQuery;
use kraken::api::handler::hosts::schema::{
    CreateHostRequest, FullHost, HostRelations, UpdateHostRequest,
};
use kraken::models::ManualHostCertainty;
use uuid::Uuid;

use crate::sdk::utils::KrakenRequest;
use crate::{KrakenClient, KrakenResult};

impl KrakenClient {
    /// Add a host
    pub async fn add_host(
        &self,
        workspace: Uuid,
        ip_addr: IpAddr,
        certainty: ManualHostCertainty,
    ) -> KrakenResult<Uuid> {
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!("api/v1/{workspace}/hosts"))
            .expect("Valid url");

        let uuid: UuidResponse = self
            .make_request(
                KrakenRequest::post(url)
                    .body(CreateHostRequest {
                        ip_addr: IpNetwork::from(ip_addr),
                        certainty,
                    })
                    .build(),
            )
            .await?;

        Ok(uuid.uuid)
    }

    /// Get all hosts of a workspace
    pub async fn get_all_hosts(
        &self,
        workspace: Uuid,
        page: PageParams,
    ) -> KrakenResult<HostResultsPage> {
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!("api/v1/workspaces/{workspace}/hosts/all"))
            .expect("Valid url");

        self.make_request(
            KrakenRequest::post(url)
                .body(GetAllDomainsQuery {
                    page,
                    host: None,
                    global_filter: None,
                    domain_filter: None,
                })
                .build(),
        )
        .await
    }

    /// Retrieve a single host
    pub async fn get_host(&self, workspace: Uuid, host: Uuid) -> KrakenResult<FullHost> {
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .expect("Valid url");

        self.make_request(KrakenRequest::get(url).build()).await
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
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .expect("Valid url");

        self.make_request(KrakenRequest::put(url).body(update).build())
            .await?;

        Ok(())
    }

    /// Delete a host
    pub async fn delete_host(&self, workspace: Uuid, host: Uuid) -> KrakenResult<()> {
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!("api/v1/workspaces/{workspace}/hosts/{host}"))
            .expect("Valid url");

        self.make_request(KrakenRequest::delete(url).build())
            .await?;

        Ok(())
    }

    /// Get the direct relations of a host
    pub async fn get_host_relations(
        &self,
        workspace: Uuid,
        host: Uuid,
    ) -> KrakenResult<HostRelations> {
        #[allow(clippy::expect_used)]
        let url = self
            .base_url
            .join(&format!(
                "api/v1/workspaces/{workspace}/hosts/{host}/relations"
            ))
            .expect("Valid url");

        self.make_request(KrakenRequest::get(url).build()).await
    }
}
