use std::net::IpAddr;

use ipnetwork::IpNetwork;
use rand::prelude::*;
use tokio::sync::mpsc;

pub struct PortGuesserSettings {
    pub addresses: Vec<IpNetwork>,
    pub num_ports: u32,
}
pub struct PortGuesserResult {
    pub host: IpAddr,
    pub port: u16,
}

pub async fn port_guesser(
    settings: PortGuesserSettings,
    tx: mpsc::Sender<PortGuesserResult>,
) -> Result<(), mpsc::error::SendError<PortGuesserResult>> {
    let mut rng = StdRng::from_entropy();
    for network in settings.addresses {
        for addr in network.iter() {
            for _ in 0..settings.num_ports {
                tx.send(PortGuesserResult {
                    host: addr,
                    port: rng.gen_range(1..=u16::MAX),
                })
                .await?;
            }
        }
    }
    Ok(())
}
