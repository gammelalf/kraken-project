//! This module holds a tcp connect port scanner

use std::net::SocketAddr;
use std::ops::RangeInclusive;
use std::time::Duration;

use futures::{stream, StreamExt};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use kraken_proto::shared::Address;
use kraken_proto::{
    any_attack_response, push_attack_request, RepeatedTcpPortScanResponse, TcpPortScanRequest,
    TcpPortScanResponse,
};
use log::{debug, info, trace, warn};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, timeout};
use tokio_stream::wrappers::ReceiverStream;
use tonic::Status;

use crate::modules::host_alive::icmp_scan::{IcmpScan, IcmpScanSettings};
use crate::modules::port_scanner::error::TcpPortScanError;
use crate::modules::StreamedAttack;

pub struct TcpPortScanner;
#[tonic::async_trait]
impl StreamedAttack for TcpPortScanner {
    type Settings = TcpPortScannerSettings;
    type Output = SocketAddr;
    type Error = TcpPortScanError;
    async fn execute(
        settings: Self::Settings,
        sender: Sender<Self::Output>,
    ) -> Result<(), Self::Error> {
        start_tcp_con_port_scan(settings, sender).await
    }

    type Request = TcpPortScanRequest;
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

        Ok(TcpPortScannerSettings {
            addresses: request
                .targets
                .into_iter()
                .map(IpNetwork::try_from)
                .collect::<Result<_, _>>()?,
            ports,
            timeout: Duration::from_millis(request.timeout),
            max_retries: request.max_retries,
            retry_interval: Duration::from_millis(request.retry_interval),
            concurrent_limit: request.concurrent_limit,
            skip_icmp_check: request.skip_icmp_check,
        })
    }

    type Response = TcpPortScanResponse;
    fn encode_output(output: Self::Output) -> Self::Response {
        TcpPortScanResponse {
            address: Some(Address::from(output.ip())),
            port: output.port() as u32,
        }
    }

    fn print_output(output: &Self::Output) {
        info!("Open port found: {output}");
    }

    fn wrap_for_backlog(response: Self::Response) -> any_attack_response::Response {
        any_attack_response::Response::TcpPortScan(response)
    }

    fn wrap_for_push(responses: Vec<Self::Response>) -> push_attack_request::Response {
        push_attack_request::Response::TcpPortScan(RepeatedTcpPortScanResponse { responses })
    }
}

/// The settings of a tcp connection port scan
#[derive(Clone, Debug)]
pub struct TcpPortScannerSettings {
    /// Ip addresses / networks to scan
    pub addresses: Vec<IpNetwork>,
    /// The port ranges to scan
    pub ports: Vec<RangeInclusive<u16>>,
    /// The duration to wait for a response
    pub timeout: Duration,
    /// Defines how many times a connection should be retried if it failed the last time
    pub max_retries: u32,
    /// The interval to wait in between the retries
    pub retry_interval: Duration,
    /// Maximum of concurrent tasks that should be spawned
    ///
    /// 0 means, that there should be no limit.
    pub concurrent_limit: u32,
    /// If set to true, there won't be an initial icmp check.
    ///
    /// All hosts are assumed to be reachable.
    pub skip_icmp_check: bool,
}

/// Start a TCP port scan with this function
///
/// **Parameter**:
/// - settings: [TcpPortScannerSettings]
/// - `tx`: [Sender] of [TcpPortScanResult]
pub async fn start_tcp_con_port_scan(
    settings: TcpPortScannerSettings,
    tx: Sender<SocketAddr>,
) -> Result<(), TcpPortScanError> {
    info!("Starting tcp port Scan");
    // Increase the NO_FILE limit if necessary
    if let Err(err) = rlimit::increase_nofile_limit(100_000) {
        return Err(TcpPortScanError::RiseNoFileLimit(err));
    }

    let addresses = if settings.skip_icmp_check {
        info!("Skipping icmp check");
        settings.addresses
    } else {
        let (tx, rx) = mpsc::channel(1);

        let icmp_settings = IcmpScanSettings {
            addresses: settings.addresses,
            timeout: Duration::from_millis(1000),
            concurrent_limit: settings.concurrent_limit,
        };
        let icmp_scan = tokio::spawn(IcmpScan::execute(icmp_settings, tx));
        let addresses = ReceiverStream::new(rx).map(IpNetwork::from).collect().await;
        icmp_scan.await.map_err(TcpPortScanError::TaskJoin)??;
        addresses
    };
    if addresses.is_empty() && settings.skip_icmp_check {
        warn!("All hosts are unreachable. Check your targets or disable the icmp check.");
    }
    let iter_addresses = addresses.iter().flat_map(|network| network.iter());
    let iter_ports = settings.ports.iter().cloned().flatten();

    stream::iter(iter_ports.cartesian_product(iter_addresses))
        .for_each_concurrent(settings.concurrent_limit as usize, move |(port, addr)| {
            let tx = tx.clone();

            async move {
                let s_addr = SocketAddr::new(addr, port);

                for _ in 0..=settings.max_retries {
                    if let Ok(res) = timeout(settings.timeout, TcpStream::connect(s_addr)).await {
                        match res {
                            Ok(mut stream) => {
                                if let Err(err) = stream.shutdown().await {
                                    debug!("Couldn't shut down tcp stream: {err}");
                                }

                                if let Err(err) = tx.send(s_addr).await {
                                    warn!("Could not send result to tx: {err}");
                                }

                                break;
                            }
                            Err(err) => {
                                let err_str = err.to_string();
                                if err_str.contains("refused") {
                                    trace!("Connection refused on {s_addr}: {err}");
                                } else if err_str.contains("No route to host") {
                                    trace!("{err} on port {port}");
                                } else {
                                    warn!("Unknown error on port {port}: {err}");
                                }
                            }
                        }
                    } else {
                        trace!("Timeout reached");
                    }
                    sleep(settings.retry_interval).await;
                }
            }
        })
        .await;

    info!("Finished tcp port scan");

    Ok(())
}
