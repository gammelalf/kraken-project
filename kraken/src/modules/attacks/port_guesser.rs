use std::net::IpAddr;

use ipnetwork::IpNetwork;
use rorm::insert;
use rorm::prelude::ForeignModelByField;
use uuid::Uuid;

use crate::api::handler::attacks::schema::DomainOrNetwork;
use crate::chan::global::GLOBAL;
use crate::chan::leech_manager::LeechClient;
use crate::models::{
    AggregationSource, AggregationTable, HostCertainty, PortCertainty, PortGuesserResultInsert,
    PortProtocol, SourceType,
};
use crate::modules::attacks::{
    AttackContext, AttackError, HandleAttackResponse, PortGuesserParams,
};
use crate::rpc::rpc_definitions::{PortGuesserRequest, PortGuesserResponse};

impl AttackContext {
    pub async fn port_guesser(
        &self,
        mut leech: LeechClient,
        params: PortGuesserParams,
    ) -> Result<(), AttackError> {
        let targets =
            DomainOrNetwork::resolve(self.workspace.uuid, self.user.uuid, &leech, &params.targets)
                .await?;

        self.handle_streamed_response(leech.port_guesser(PortGuesserRequest {
            attack_uuid: self.attack_uuid.to_string(),
            targets: targets.into_iter().map(From::from).collect(),
            num_ports: params.num_ports,
        }))
        .await
    }
}

impl HandleAttackResponse<PortGuesserResponse> for AttackContext {
    async fn handle_response(&self, response: PortGuesserResponse) -> Result<(), AttackError> {
        let PortGuesserResponse {
            host: Some(host),
            port,
        } = response
        else {
            return Err(AttackError::Malformed("Missing `host`"));
        };
        let host = IpNetwork::from(IpAddr::try_from(host)?);

        let source_uuid = insert!(&GLOBAL.db, PortGuesserResultInsert)
            .return_primary_key()
            .single(&PortGuesserResultInsert {
                uuid: Uuid::new_v4(),
                attack: ForeignModelByField::Key(self.attack_uuid),
                host,
                port: port as i32,
            })
            .await?;

        let host_uuid = GLOBAL
            .aggregator
            .aggregate_host(self.workspace.uuid, host, HostCertainty::SupposedTo)
            .await?;
        let port_uuid = GLOBAL
            .aggregator
            .aggregate_port(
                self.workspace.uuid,
                host_uuid,
                port as u16,
                PortProtocol::Tcp,
                PortCertainty::SupposedTo,
            )
            .await?;

        insert!(&GLOBAL.db, AggregationSource)
            .return_nothing()
            .bulk([
                AggregationSource {
                    uuid: Uuid::new_v4(),
                    workspace: ForeignModelByField::Key(self.workspace.uuid),
                    source_type: SourceType::PortGuesser,
                    source_uuid,
                    aggregated_table: AggregationTable::Host,
                    aggregated_uuid: host_uuid,
                },
                AggregationSource {
                    uuid: Uuid::new_v4(),
                    workspace: ForeignModelByField::Key(self.workspace.uuid),
                    source_type: SourceType::PortGuesser,
                    source_uuid,
                    aggregated_table: AggregationTable::Port,
                    aggregated_uuid: port_uuid,
                },
            ])
            .await?;

        Ok(())
    }
}
