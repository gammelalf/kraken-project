//! # Leeches
//! Leeches are the workers of kraken.
//!
//! They provide a gRPC server to receive requests from kraken and respond with results.
//! If this connection is lost somehow, they will store the results in a local database
//! and will try to connect to the kraken gRPC server to send the missing data.
//!
//! You can also use the leech as a cli utility without a kraken attached for manual
//! execution and testing. See the subcommand `run` for further information.
#![warn(missing_docs)]
#![cfg_attr(
    feature = "rorm-main",
    allow(dead_code, unused_variables, unused_imports)
)]

use std::error::Error;
use std::fmt::Debug;
use std::io::{stdin, stdout, Write};
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use std::{env, io};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use dehashed_rs::SearchType;
use ipnetwork::IpNetwork;
use kraken_proto::push_attack_service_client::PushAttackServiceClient;
use kraken_proto::PushAttackRequest;
use log::{error, info, warn};
use rorm::{cli, Database, DatabaseConfiguration, DatabaseDriver};
use tokio::sync::mpsc;
use tokio::task;
use tonic::transport::Endpoint;
use trust_dns_resolver::Name;
use uuid::Uuid;

use crate::backlog::start_backlog;
use crate::config::{get_config, Config};
use crate::modules::bruteforce_subdomains::{BruteforceSubdomain, BruteforceSubdomainsSettings};
use crate::modules::certificate_transparency::{
    CertificateTransparency, CertificateTransparencySettings,
};
use crate::modules::dns::txt::{DnsTxtScan, DnsTxtScanSettings};
use crate::modules::host_alive::icmp_scan::{IcmpScan, IcmpScanSettings};
use crate::modules::port_scanner::tcp_con::{TcpPortScanner, TcpPortScannerSettings};
use crate::modules::service_detection::udp::{UdpServiceDetection, UdpServiceDetectionSettings};
use crate::modules::service_detection::{DetectServiceSettings, ServiceDetection};
use crate::modules::{dehashed, whois, Attack, StreamedAttack};
use crate::rpc::start_rpc_server;
use crate::utils::{input, kraken_endpoint};

pub mod backlog;
pub mod config;
pub mod logging;
pub mod models;
pub mod modules;
pub mod rpc;
pub mod utils;

/// The technique to use for the port scan
#[derive(Debug, ValueEnum, Copy, Clone)]
pub enum PortScanTechnique {
    /// A tcp connect scan
    TcpCon,
    /// A icmp scan
    Icmp,
}

/// The execution commands
#[derive(Subcommand)]
pub enum RunCommand {
    /// Bruteforce subdomains via DNS
    BruteforceSubdomains {
        /// Valid domain name
        target: Name,
        /// Path to a wordlist that can be used for subdomain enumeration.
        ///
        /// The entries in the wordlist are assumed to be line seperated.
        #[clap(short = 'w', long = "wordlist")]
        wordlist_path: PathBuf,
        /// The concurrent task limit
        #[clap(long)]
        #[clap(default_value_t = NonZeroU32::new(100).unwrap())]
        concurrent_limit: NonZeroU32,
    },
    /// Parse known TXT DNS entries
    DnsTxt {
        /// Valid domain name
        target: Name,
    },
    /// Retrieve domains through certificate transparency
    CertificateTransparency {
        /// Valid domain name
        target: String,
        /// Whether expired certificates should be included
        #[clap(long)]
        #[clap(default_value_t = false)]
        include_expired: bool,
        /// The number of times the connection should be retried if it failed.
        #[clap(long)]
        #[clap(default_value_t = 6)]
        max_retries: u32,
        /// The interval that should be wait between retries on a port.
        ///
        /// The interval is specified in milliseconds.
        #[clap(long)]
        #[clap(default_value_t = 100)]
        retry_interval: u16,
    },
    /// A simple port scanning utility
    PortScanner {
        /// Valid IPv4 or IPv6 addresses or networks in CIDR notation
        #[clap(required(true))]
        targets: Vec<String>,
        /// A single port, multiple, comma seperated ports or (inclusive) port ranges
        ///
        /// If no values are supplied, 1-65535 is used as default
        #[clap(short = 'p')]
        ports: Vec<String>,
        /// The technique to use for port scans
        #[clap(short = 't', long)]
        #[clap(default_value = "tcp-con")]
        technique: PortScanTechnique,
        /// The time to wait until a connection is considered failed.
        ///
        /// The timeout is specified in milliseconds.
        #[clap(long)]
        #[clap(default_value_t = 1000)]
        timeout: u16,
        /// The concurrent task limit
        #[clap(long)]
        #[clap(default_value_t = NonZeroU32::new(1000).unwrap())]
        concurrent_limit: NonZeroU32,
        /// The number of times the connection should be retried if it failed.
        #[clap(long)]
        #[clap(default_value_t = 6)]
        max_retries: u32,
        /// The interval that should be wait between retries on a port.
        ///
        /// The interval is specified in milliseconds.
        #[clap(long)]
        #[clap(default_value_t = 100)]
        retry_interval: u16,
        /// Skips the initial icmp check.
        ///
        /// All hosts are assumed to be reachable.
        #[clap(long)]
        #[clap(default_value_t = false)]
        skip_icmp_check: bool,
    },
    /// Query the dehashed API
    Dehashed {
        /// The query for the api
        query: String,
    },
    /// Query whois entries
    Whois {
        /// The ip to query information for
        query: IpAddr,
    },
    /// Detect the service running behind a port
    ServiceDetection {
        /// The ip address to connect to
        addr: IpAddr,

        /// The port to connect to
        port: u16,

        /// The interval that should be waited for a response after connecting and sending an optional payload.
        ///
        /// The interval is specified in milliseconds.
        #[clap(long)]
        #[clap(default_value_t = 1000)]
        timeout: u64,

        /// Flag for debugging
        ///
        /// Normally the service detection would stop after the first successful match.
        /// When this flag is enabled it will always run all checks producing their logs before returning the first match.
        #[clap(long)]
        dont_stop_on_match: bool,
    },
    /// Detect the services running behind on a given address in the given port range
    ServiceDetectionUdp {
        /// The ip address to connect to
        addr: IpAddr,

        /// A single port, multiple, comma seperated ports or (inclusive) port ranges
        ///
        /// If no values are supplied, 1-65535 is used as default
        #[clap(short = 'p')]
        ports: Vec<String>,

        /// The interval that should be waited for a response after connecting and sending an optional payload.
        ///
        /// The interval is specified in milliseconds.
        #[clap(long)]
        #[clap(default_value_t = 10000)]
        timeout: u64,

        /// The number of times how often to retry sending a UDP packet
        #[clap(long)]
        #[clap(default_value_t = 3)]
        port_retries: u32,

        /// The time between sending UDP packets if a response isn't being heard
        /// back from in time.
        #[clap(long)]
        #[clap(default_value_t = 1000)]
        retry_interval: u64,

        /// The concurrent task limit
        #[clap(long)]
        #[clap(default_value_t = NonZeroU32::new(1000).unwrap())]
        concurrent_limit: NonZeroU32,
    },
}

/// All available subcommands
#[derive(Subcommand)]
pub enum Command {
    /// Start the leech as a server
    Server,
    /// Execute a command via CLI
    Execute {
        /// Specifies the verbosity of the output
        #[clap(short = 'v', global = true, action = ArgAction::Count)]
        verbosity: u8,

        /// Push the results to a workspace in kraken
        #[clap(long)]
        push: Option<Uuid>,

        /// Api key to authenticate when pushing
        #[clap(long)]
        api_key: Option<String>,

        /// the subcommand to execute
        #[clap(subcommand)]
        command: RunCommand,
    },
    /// Apply migrations to the database
    Migrate {
        /// The directory where the migration files are located
        migration_dir: String,
    },
}

/// The main CLI parser
#[derive(Parser)]
pub struct Cli {
    /// Specify an alternative path to the config file
    #[clap(long = "config-path")]
    #[clap(default_value_t = String::from("/etc/leech/config.toml"))]
    config_path: String,

    /// Subcommands
    #[clap(subcommand)]
    commands: Command,
}

#[rorm::rorm_main]
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.commands {
        Command::Migrate { migration_dir } => migrate(&cli.config_path, migration_dir).await?,
        Command::Server => {
            let config = get_config(&cli.config_path)?;
            logging::setup_logging(&config.logging)?;

            let db = get_db(&config).await?;
            let backlog = start_backlog(db, &config.kraken).await?;

            start_rpc_server(&config, backlog).await?;
        }
        Command::Execute {
            command,
            verbosity,
            push,
            api_key,
        } => {
            if env::var("RUST_LOG").is_err() {
                match verbosity {
                    0 => env::set_var("RUST_LOG", "leech=info"),
                    1 => env::set_var("RUST_LOG", "leech=debug"),
                    _ => env::set_var("RUST_LOG", "leech=trace"),
                }
            }
            env_logger::init();

            let push = if let Some(workspace) = push {
                let config = get_config(&cli.config_path)?;
                let endpoint = kraken_endpoint(&config.kraken)?;

                let api_key = if let Some(api_key) = api_key {
                    api_key
                } else {
                    print!("Please enter your api key: ");
                    std::io::stdout().flush().unwrap();
                    input()
                        .await?
                        .ok_or_else(|| "Can't push to kraken without api key".to_string())?
                };
                Some((endpoint, workspace, api_key))
            } else {
                None
            };

            match command {
                RunCommand::BruteforceSubdomains {
                    target,
                    wordlist_path,
                    concurrent_limit,
                } => {
                    run_streamed_attack::<BruteforceSubdomain>(
                        BruteforceSubdomainsSettings {
                            domain: target.to_string(),
                            wordlist_path,
                            concurrent_limit: u32::from(concurrent_limit),
                        },
                        push,
                    )
                    .await?;
                }
                RunCommand::DnsTxt { target } => {
                    run_streamed_attack::<DnsTxtScan>(
                        DnsTxtScanSettings {
                            domains: Vec::from([target.to_string()]),
                        },
                        push,
                    )
                    .await?;
                }
                RunCommand::CertificateTransparency {
                    target,
                    include_expired,
                    max_retries,
                    retry_interval,
                } => {
                    run_normal_attack::<CertificateTransparency>(
                        CertificateTransparencySettings {
                            target,
                            include_expired,
                            max_retries,
                            retry_interval: Duration::from_millis(retry_interval as u64),
                        },
                        push,
                    )
                    .await?;
                }
                RunCommand::PortScanner {
                    targets,
                    technique,
                    ports,
                    timeout,
                    concurrent_limit,
                    max_retries,
                    retry_interval,
                    skip_icmp_check,
                } => {
                    let addresses = targets
                        .iter()
                        .map(|s| IpNetwork::from_str(s))
                        .collect::<Result<_, _>>()?;

                    let mut port_range = vec![];
                    if ports.is_empty() {
                        port_range.push(1..=u16::MAX);
                    } else {
                        utils::parse_ports(&ports, &mut port_range)?;
                    }

                    match technique {
                        PortScanTechnique::TcpCon => {
                            run_streamed_attack::<TcpPortScanner>(
                                TcpPortScannerSettings {
                                    addresses,
                                    ports: port_range,
                                    timeout: Duration::from_millis(timeout as u64),
                                    skip_icmp_check,
                                    max_retries,
                                    retry_interval: Duration::from_millis(retry_interval as u64),
                                    concurrent_limit: u32::from(concurrent_limit),
                                },
                                push,
                            )
                            .await?;
                        }
                        PortScanTechnique::Icmp => {
                            run_streamed_attack::<IcmpScan>(
                                IcmpScanSettings {
                                    addresses,
                                    timeout: Duration::from_millis(timeout as u64),
                                    concurrent_limit: u32::from(concurrent_limit),
                                },
                                push,
                            )
                            .await?;
                        }
                    }
                }
                RunCommand::Dehashed { query } => {
                    let email = match env::var("DEHASHED_EMAIL") {
                        Ok(x) => x,
                        Err(_) => {
                            error!("Missing environment variable DEHASHED_EMAIL");
                            return Err("Missing environment variable DEHASHED_EMAIL".into());
                        }
                    };
                    let api_key = match env::var("DEHASHED_API_KEY") {
                        Ok(x) => x,
                        Err(_) => {
                            error!("Missing environment variable DEHASHED_API_KEY");
                            return Err("Missing environment variable DEHASHED_API_KEY".into());
                        }
                    };

                    match dehashed::query(
                        email,
                        api_key,
                        dehashed_rs::Query::Domain(SearchType::Simple(query)),
                    )
                    .await
                    {
                        Ok(x) => {
                            for entry in x.entries {
                                info!("{entry:?}");
                            }
                        }
                        Err(err) => error!("{err}"),
                    }
                }
                RunCommand::Whois { query } => match whois::query_whois(query).await {
                    Ok(x) => info!("Found result\n{x:#?}"),

                    Err(err) => error!("{err}"),
                },
                RunCommand::ServiceDetection {
                    addr,
                    port,
                    timeout: wait_for_response,
                    dont_stop_on_match: debug,
                } => {
                    run_normal_attack::<ServiceDetection>(
                        DetectServiceSettings {
                            socket: SocketAddr::new(addr, port),
                            timeout: Duration::from_millis(wait_for_response),
                            always_run_everything: debug,
                        },
                        push,
                    )
                    .await?;
                }
                RunCommand::ServiceDetectionUdp {
                    addr,
                    ports,
                    timeout,
                    port_retries,
                    retry_interval,
                    concurrent_limit,
                } => {
                    let mut port_range = vec![];
                    if ports.is_empty() {
                        port_range.push(1..=u16::MAX);
                    } else {
                        utils::parse_ports(&ports, &mut port_range)?;
                    }

                    run_streamed_attack::<UdpServiceDetection>(
                        UdpServiceDetectionSettings {
                            ip: addr,
                            ports: port_range,
                            max_retries: port_retries,
                            retry_interval: Duration::from_millis(retry_interval),
                            timeout: Duration::from_millis(timeout),
                            concurrent_limit: u32::from(concurrent_limit),
                        },
                        push,
                    )
                    .await?;
                }
            }
        }
    }

    Ok(())
}

async fn migrate(config_path: &str, migration_dir: String) -> Result<(), Box<dyn Error>> {
    let config = get_config(config_path)?;
    cli::migrate::run_migrate_custom(
        cli::config::DatabaseConfig {
            last_migration_table_name: None,
            driver: cli::config::DatabaseDriver::Postgres {
                host: config.database.host,
                port: config.database.port,
                name: config.database.name,
                user: config.database.user,
                password: config.database.password,
            },
        },
        migration_dir,
        false,
        None,
    )
    .await?;
    Ok(())
}

async fn get_db(config: &Config) -> Result<Database, String> {
    // TODO: make driver configurable...?
    let db_config = DatabaseConfiguration {
        driver: DatabaseDriver::Postgres {
            host: config.database.host.clone(),
            port: config.database.port,
            user: config.database.user.clone(),
            password: config.database.password.clone(),
            name: config.database.name.clone(),
        },
        min_connections: 2,
        max_connections: 20,
        disable_logging: Some(true),
        statement_log_level: None,
        slow_statement_log_level: None,
    };

    Database::connect(db_config)
        .await
        .map_err(|e| format!("Error connecting to the database: {e}"))
}

async fn run_normal_attack<A: Attack>(
    settings: A::Settings,
    push: Option<(Endpoint, Uuid, String)>,
) -> Result<(), Box<dyn Error>> {
    let output = A::execute(settings).await?;

    A::print_output(&output);

    if let Some((endpoint, workspace, api_key)) = push {
        if ask_push_confirmation(&output)?.is_continue() {
            let mut kraken = PushAttackServiceClient::connect(endpoint).await?;
            kraken
                .push_attack(PushAttackRequest {
                    workspace_uuid: workspace.to_string(),
                    api_key,
                    response: Some(A::wrap_for_push(A::encode_output(output))),
                })
                .await?;
        }
    }

    Ok(())
}

async fn run_streamed_attack<A: StreamedAttack>(
    settings: A::Settings,
    push: Option<(Endpoint, Uuid, String)>,
) -> Result<(), Box<dyn Error>> {
    let (tx, mut rx) = mpsc::channel::<A::Output>(1);

    let should_collect = push.is_some();
    let collector = task::spawn(async move {
        let mut outputs = Vec::new();
        while let Some(output) = rx.recv().await {
            A::print_output(&output);
            if should_collect {
                outputs.push(output);
            }
        }
        outputs
    });

    A::execute(settings, tx).await?;
    let outputs = collector.await?;

    if let Some((endpoint, workspace, api_key)) = push {
        if ask_push_confirmation(&outputs)?.is_continue() {
            let mut kraken = PushAttackServiceClient::connect(endpoint).await?;
            kraken
                .push_attack(PushAttackRequest {
                    workspace_uuid: workspace.to_string(),
                    api_key,
                    response: Some(A::wrap_for_push(
                        outputs.into_iter().map(A::encode_output).collect(),
                    )),
                })
                .await?;
        }
    }

    Ok(())
}

fn ask_push_confirmation(data: &impl Debug) -> io::Result<ControlFlow<()>> {
    let pager = env::var("PAGER")
        .ok()
        .or_else(|| {
            Path::new("/usr/bin/pager")
                .exists()
                .then_some("/usr/bin/pager".to_string())
        })
        .unwrap_or_else(|| "less".to_string());

    loop {
        print!("Do you want to push these results? [y/N/p/pp/?]: ");
        stdout().flush()?;

        let mut input = String::new();
        stdin().read_line(&mut input)?;
        input = input.trim().to_ascii_lowercase();

        match input.as_str() {
            "" | "n" => return Ok(ControlFlow::Break(())),
            "y" => return Ok(ControlFlow::Continue(())),
            "p" | "pp" => {
                let mut process = std::process::Command::new(&pager)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::inherit())
                    .spawn()?;

                if input.len() == 1 {
                    write!(process.stdin.take().unwrap(), "{data:?}")?;
                } else {
                    write!(process.stdin.take().unwrap(), "{data:#?}")?;
                }

                process.wait()?;
            }
            "?" => {
                println!("y  - yes");
                println!("n  - no");
                println!("p  - print data to push");
                println!("pp - pretty print data to push");
                println!("?  - show this message");
            }
            _ => println!("Unknown option"),
        }
    }
}
