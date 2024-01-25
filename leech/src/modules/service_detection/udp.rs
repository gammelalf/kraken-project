use std::net::{IpAddr, SocketAddr};
use std::ops::RangeInclusive;
use std::time::Duration;

use futures::{stream, TryStreamExt};
use kraken_proto::any_attack_response::Response;
use kraken_proto::shared::Address;
use kraken_proto::{
    any_attack_response, push_attack_request, RepeatedUdpServiceDetectionResponse,
    ServiceCertainty, UdpServiceDetectionRequest, UdpServiceDetectionResponse,
};
use log::{debug, info};
use probe_config::generated::Match;
use tokio::net::UdpSocket;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tonic::Status;

use super::error::UdpServiceScanError;
use super::Service;
use crate::modules::service_detection::generated;
use crate::modules::StreamedAttack;

pub struct UdpServiceDetection;
#[tonic::async_trait]
impl StreamedAttack for UdpServiceDetection {
    type Settings = UdpServiceDetectionSettings;
    type Output = UdpServiceDetectionResult;
    type Error = UdpServiceScanError;
    async fn execute(
        settings: Self::Settings,
        sender: Sender<Self::Output>,
    ) -> Result<(), Self::Error> {
        start_udp_service_detection(settings, sender).await
    }

    type Request = UdpServiceDetectionRequest;
    fn get_attack_uuid(request: &Self::Request) -> &str {
        &request.attack_uuid
    }
    fn decode_settings(request: Self::Request) -> Result<Self::Settings, Status> {
        let mut ports = request
            .ports
            .into_iter()
            .map(RangeInclusive::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if ports.is_empty() {
            ports.push(1..=u16::MAX);
        }

        Ok(UdpServiceDetectionSettings {
            ip: IpAddr::try_from(
                request
                    .address
                    .clone()
                    .ok_or(Status::invalid_argument("Missing address"))?,
            )?,
            ports,
            concurrent_limit: request.concurrent_limit,
            max_retries: request.max_retries,
            retry_interval: Duration::from_millis(request.retry_interval),
            timeout: Duration::from_millis(request.timeout),
        })
    }

    type Response = UdpServiceDetectionResponse;
    fn encode_output(output: Self::Output) -> Self::Response {
        UdpServiceDetectionResponse {
            address: Some(Address::from(output.ip)),
            port: output.port as u32,
            certainty: match output.service {
                Service::Unknown => ServiceCertainty::Unknown as _,
                Service::Maybe(_) => ServiceCertainty::Maybe as _,
                Service::Definitely(_) => ServiceCertainty::Definitely as _,
            },
            services: match output.service {
                Service::Unknown => Vec::new(),
                Service::Maybe(services) => services.iter().map(|s| s.to_string()).collect(),
                Service::Definitely(service) => vec![service.to_string()],
            },
        }
    }

    fn print_output(output: &Self::Output) {
        info!(
            "detected service on {}:{}: {:?}",
            output.ip, output.port, output.service
        );
    }

    fn wrap_for_backlog(response: Self::Response) -> Response {
        any_attack_response::Response::UdpServiceDetection(response)
    }

    fn wrap_for_push(responses: Vec<Self::Response>) -> push_attack_request::Response {
        push_attack_request::Response::UdpServiceDetection(RepeatedUdpServiceDetectionResponse {
            responses,
        })
    }
}

/// Settings for a service detection
#[derive(Debug)]
pub struct UdpServiceDetectionSettings {
    /// IP address to scan
    pub ip: IpAddr,

    /// Ports to scan
    pub ports: Vec<RangeInclusive<u16>>,

    /// Number of times packet sending should be retried if no response was received within the `timeout`
    ///
    /// Set to 0 to only try once.
    pub max_retries: u32,

    /// How much time to wait between sending probe payloads (independent of
    /// timeout, aka it can send while another pending probe did not yet receive
    /// data within the timeout interval).
    pub retry_interval: Duration,

    /// The timeout for receiving data on a single sent probe.
    pub timeout: Duration,

    /// Maximum of concurrent tasks that should be spawned
    ///
    /// 0 means, that there should be no limit.
    pub concurrent_limit: u32,
}

impl UdpServiceDetectionSettings {
    async fn probe_udp(
        &self,
        port: u16,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, UdpServiceScanError> {
        let addr = SocketAddr::new(self.ip, port);

        let mut set = JoinSet::new();

        for i in 0..=self.max_retries {
            let offset = self.retry_interval.saturating_mul(i);
            set.spawn(timeout(
                self.timeout.saturating_add(offset),
                single_probe_udp(offset, addr, payload.to_vec()),
            ));
        }

        while let Some(res) = set.join_next().await {
            let res = res?; // propagate JoinError
            if let Ok(res) = res {
                // ignore timeouts
                let res = res?; // propagate single_probe_udp errors
                if let Some(res) = res {
                    // check for single_probe_udp returning None (aka no response)
                    set.abort_all();
                    return Ok(Some(res));
                }
            } else {
                debug!("timeout on udp service probe {}", addr);
            }
        }

        Ok(None)
    }
}

/// Returns the received payload or None in case there was no response. Returns
/// errors in case of other networking errors.
async fn single_probe_udp(
    wait_before: Duration,
    addr: SocketAddr,
    payload: Vec<u8>,
) -> Result<Option<Vec<u8>>, UdpServiceScanError> {
    sleep(wait_before).await;
    let sock = UdpSocket::bind(match addr {
        SocketAddr::V4(_) => "0.0.0.0:0",
        SocketAddr::V6(_) => "[::]:0",
    })
    .await?;
    let mut buf = [0; 4096];
    sock.connect(addr).await?;
    sock.send(&payload).await?;
    // TODO: it's possible the server might respond with ICMP Destination/port unreachable (could handle that here)
    let err = sock.recv(&mut buf).await;
    match err {
        Ok(n) => Ok(Some(buf[0..n].to_vec())),
        // TODO: certain I/O errors should probably just return None here
        Err(e) => Err(UdpServiceScanError::IoError(e)),
    }
}

#[derive(Debug, Clone)]
/// A found open or detected UDP service on a specific port.
pub struct UdpServiceDetectionResult {
    /// The host that was scanned.
    pub ip: IpAddr,
    /// The port that was found open with the given service.
    pub port: u16,
    /// The service that was found possibly running on this port.
    pub service: Service,
}

/// Detects the UDP service behind a socket by sending it known probes or trying `\r\n\r\n` in case there are no
/// matching probes.
pub async fn start_udp_service_detection(
    settings: UdpServiceDetectionSettings,
    tx: Sender<UdpServiceDetectionResult>,
) -> Result<(), UdpServiceScanError> {
    let settings = &settings;
    let ip = settings.ip;
    stream::iter(
        settings
            .ports
            .iter()
            .cloned()
            .flatten()
            .map(Ok::<u16, UdpServiceScanError>),
    )
    .try_for_each_concurrent(settings.concurrent_limit as usize, move |port| {
        let tx = tx.clone();
        async move {
            let mut partial_matches = Vec::new();
            for prev in 0..3 {
                debug!("Starting udp scans prevalence={prev}");
                for probe in &generated::PROBES.udp_probes[prev] {
                    if let Some(data) = settings.probe_udp(port, probe.payload).await? {
                        match probe.is_match(&data) {
                            Match::No => {}
                            Match::Partial => {
                                partial_matches.push(probe.service);
                            }
                            Match::Exact => {
                                debug!("Found exact UDP service {} on port {port}", probe.service);
                                tx.send(UdpServiceDetectionResult {
                                    ip,
                                    port,
                                    service: Service::Definitely(probe.service),
                                })
                                .await?;
                                return Ok(());
                            }
                        }
                    }
                }
            }

            if partial_matches.is_empty() {
                let payload = b"\r\n\r\n";
                if let Some(_data) = settings.probe_udp(port, payload).await? {
                    debug!("Generic CRLF probe on port {port} matched");
                    tx.send(UdpServiceDetectionResult {
                        ip,
                        port,
                        service: Service::Unknown,
                    })
                    .await?;
                }
            } else {
                debug!("Found maybe UDP services {partial_matches:?} on port {port}");
                tx.send(UdpServiceDetectionResult {
                    ip,
                    port,
                    service: Service::Maybe(partial_matches),
                })
                .await?;
            }

            Ok(())
        }
    })
    .await?;

    info!("Finished UDP service detection");

    Ok(())
}
