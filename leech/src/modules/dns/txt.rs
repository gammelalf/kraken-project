//! leech module for parsing TXT entries in the DNS results specifically.

use std::fmt::Display;

use kraken_proto::shared::dns_txt_scan::Info;
use kraken_proto::shared::{
    spf_directive, spf_part, DnsTxtKnownEntry, Net, SpfDirective, SpfExplanationModifier, SpfInfo,
    SpfMechanismA, SpfMechanismAll, SpfMechanismExists, SpfMechanismInclude, SpfMechanismIp,
    SpfMechanismMx, SpfMechanismPtr, SpfPart, SpfQualifier, SpfRedirectModifier,
    SpfUnknownModifier,
};
use kraken_proto::{
    any_attack_response, push_attack_request, shared, DnsTxtScanRequest, DnsTxtScanResponse,
    RepeatedDnsTxtScanResponse,
};
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tokio::sync::mpsc::Sender;
use tokio::task::JoinSet;
use tonic::Status;
use trust_dns_resolver::name_server::{GenericConnector, TokioRuntimeProvider};
use trust_dns_resolver::proto::rr::Record;
use trust_dns_resolver::{AsyncResolver, TokioAsyncResolver};

use crate::modules::dns::resolve;
use crate::modules::StreamedAttack;

type ResolverT = AsyncResolver<GenericConnector<TokioRuntimeProvider>>;

use super::errors::DnsResolutionError;
use super::spf::{parse_spf, SPFMechanism, SPFPart, SPFQualifier};

pub struct DnsTxtScan;
#[tonic::async_trait]
impl StreamedAttack for DnsTxtScan {
    type Settings = DnsTxtScanSettings;
    type Output = DnsTxtScanResult;
    type Error = DnsResolutionError;
    async fn execute(
        settings: Self::Settings,
        sender: Sender<Self::Output>,
    ) -> Result<(), Self::Error> {
        start_dns_txt_scan(settings, sender).await
    }

    type Request = DnsTxtScanRequest;
    fn get_attack_uuid(request: &Self::Request) -> &str {
        &request.attack_uuid
    }
    fn decode_settings(request: Self::Request) -> Result<Self::Settings, Status> {
        if request.targets.is_empty() {
            return Err(Status::invalid_argument("nothing to resolve"));
        }

        Ok(DnsTxtScanSettings {
            domains: request.targets,
        })
    }

    type Response = DnsTxtScanResponse;
    fn encode_output(output: Self::Output) -> Self::Response {
        DnsTxtScanResponse {
            record: Some(shared::DnsTxtScan {
                domain: output.domain,
                rule: output.rule,
                info: Some(match output.info {
                    TxtScanInfo::HasGoogleAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasGoogleAccount as _)
                    }
                    TxtScanInfo::HasDocusignAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasDocusignAccount as _)
                    }
                    TxtScanInfo::HasAppleAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasAppleAccount as _)
                    }
                    TxtScanInfo::HasFacebookAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasFacebookAccount as _)
                    }
                    TxtScanInfo::HasHubspotAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasHubspotAccount as _)
                    }
                    TxtScanInfo::HasMsDynamics365 => {
                        Info::WellKnown(DnsTxtKnownEntry::HasMsDynamics365 as _)
                    }
                    TxtScanInfo::HasStripeAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasStripeAccount as _)
                    }
                    TxtScanInfo::HasOneTrustSso => {
                        Info::WellKnown(DnsTxtKnownEntry::HasOneTrustSso as _)
                    }
                    TxtScanInfo::HasBrevoAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasBrevoAccount as _)
                    }
                    TxtScanInfo::HasGlobalsignAccount => {
                        Info::WellKnown(DnsTxtKnownEntry::HasGlobalsignAccount as _)
                    }
                    TxtScanInfo::HasGlobalsignSMime => {
                        Info::WellKnown(DnsTxtKnownEntry::HasGlobalsignSMime as _)
                    }
                    TxtScanInfo::OwnsAtlassianAccounts => {
                        Info::WellKnown(DnsTxtKnownEntry::OwnsAtlassianAccounts as _)
                    }
                    TxtScanInfo::OwnsZoomAccounts => {
                        Info::WellKnown(DnsTxtKnownEntry::OwnsZoomAccounts as _)
                    }
                    TxtScanInfo::EmailProtonMail => {
                        Info::WellKnown(DnsTxtKnownEntry::EmailProtonMail as _)
                    }
                    TxtScanInfo::SPF { parts } => Info::Spf(SpfInfo {
                        parts: parts
                            .iter()
                            .map(|part| SpfPart {
                                rule: part.encode_spf(),
                                part: Some(match part {
                                    SPFPart::Directive {
                                        qualifier,
                                        mechanism,
                                    } => spf_part::Part::Directive(SpfDirective {
                                        mechanism: Some(match mechanism {
                                            SPFMechanism::All => {
                                                spf_directive::Mechanism::All(SpfMechanismAll {})
                                            }
                                            SPFMechanism::Include { domain } => {
                                                spf_directive::Mechanism::Include(
                                                    SpfMechanismInclude {
                                                        domain: domain.clone(),
                                                    },
                                                )
                                            }
                                            SPFMechanism::A {
                                                domain,
                                                ipv4_cidr,
                                                ipv6_cidr,
                                            } => spf_directive::Mechanism::A(SpfMechanismA {
                                                domain: domain.clone(),
                                                ipv4_cidr: ipv4_cidr.map(|a| a as _),
                                                ipv6_cidr: ipv6_cidr.map(|a| a as _),
                                            }),
                                            SPFMechanism::MX {
                                                domain,
                                                ipv4_cidr,
                                                ipv6_cidr,
                                            } => spf_directive::Mechanism::Mx(SpfMechanismMx {
                                                domain: domain.clone(),
                                                ipv4_cidr: ipv4_cidr.map(|a| a as _),
                                                ipv6_cidr: ipv6_cidr.map(|a| a as _),
                                            }),
                                            SPFMechanism::PTR { domain } => {
                                                spf_directive::Mechanism::Ptr(SpfMechanismPtr {
                                                    domain: domain.clone(),
                                                })
                                            }
                                            SPFMechanism::IP { ipnet } => {
                                                spf_directive::Mechanism::Ip(SpfMechanismIp {
                                                    ip: Some(Net::from(*ipnet)),
                                                })
                                            }
                                            SPFMechanism::Exists { domain } => {
                                                spf_directive::Mechanism::Exists(
                                                    SpfMechanismExists {
                                                        domain: domain.clone(),
                                                    },
                                                )
                                            }
                                        }),
                                        qualifier: match qualifier {
                                            SPFQualifier::Pass => SpfQualifier::Pass as _,
                                            SPFQualifier::Fail => SpfQualifier::Fail as _,
                                            SPFQualifier::SoftFail => SpfQualifier::SoftFail as _,
                                            SPFQualifier::Neutral => SpfQualifier::Neutral as _,
                                        },
                                    }),
                                    SPFPart::RedirectModifier { domain } => {
                                        spf_part::Part::Redirect(SpfRedirectModifier {
                                            domain: domain.clone(),
                                        })
                                    }
                                    SPFPart::ExplanationModifier { domain } => {
                                        spf_part::Part::Explanation(SpfExplanationModifier {
                                            domain: domain.clone(),
                                        })
                                    }
                                    SPFPart::UnknownModifier { name, value } => {
                                        spf_part::Part::UnknownModifier(SpfUnknownModifier {
                                            name: name.clone(),
                                            value: value.clone(),
                                        })
                                    }
                                }),
                            })
                            .collect(),
                    }),
                }),
            }),
        }
    }

    fn print_output(output: &Self::Output) {
        match &output.info {
            TxtScanInfo::SPF { parts } => {
                info!("Found SPF entry for {}:", output.domain);
                for part in parts {
                    info!("  {part}");
                }
            }
            _ => {
                info!("Found txt entry for {}: {}", output.domain, output.info);
            }
        };
    }

    fn wrap_for_backlog(response: Self::Response) -> any_attack_response::Response {
        any_attack_response::Response::DnsTxtScan(response)
    }
    fn wrap_for_push(responses: Vec<Self::Response>) -> push_attack_request::Response {
        push_attack_request::Response::DnsTxtScan(RepeatedDnsTxtScanResponse { responses })
    }
}

/// DNS TXT scanning settings
#[derive(Debug)]
pub struct DnsTxtScanSettings {
    /// The domains to start resolving TXT settings in
    pub domains: Vec<String>,
}

/// Represents a single parsed DNS TXT entry.
#[derive(Debug, Clone)]
pub enum TxtScanInfo {
    /// regex: /^GOOGLE-SITE-VERIFICATION=/i
    /// Google Search Console
    HasGoogleAccount,
    /// regex: /globalsign/i
    /// Globalsign TLS certificate
    HasGlobalsignAccount,
    /// regex: /globalsign-smime/i
    /// Globalsign mails?
    HasGlobalsignSMime,
    /// regex: /^docusign/i
    /// DocuSign Identity Provider -> When you claim and verify an email domain for your organization, you can manage all users for that domain, across all accounts linked to the organization.
    HasDocusignAccount,
    /// regex: /^apple-domain-verification=/i
    /// owns apple account
    HasAppleAccount,
    /// regex: /^facebook-domain-verification=/i
    /// owns facebook account
    HasFacebookAccount,
    /// regex: /^hubspot-developer-verification=/i
    /// owns hubspot account (marketing tools)
    HasHubspotAccount,
    /// regex: /^d365mktkey=/i
    /// has Microsoft ERP: Dynamics 365
    HasMsDynamics365,
    /// regex: /^stripe-verification=/i
    /// uses stripe payments
    HasStripeAccount,
    /// regex: /^onetrust-domain-verification=/i
    /// might use OneTrust SSO?
    HasOneTrustSso,
    /// regex: /^brevo-code:/i
    /// Emails sent from Brevo (CRM / marketing tools)
    HasBrevoAccount,
    /// regex: /^atlassian-domain-verification=/i
    /// owns atlassian account
    OwnsAtlassianAccounts,
    /// regex: /^ZOOM_verify_/i
    /// Probably has Zoom users with emails with this domain
    OwnsZoomAccounts,
    /// regex: /^protonmail-verification=/i
    /// Emails hosted at ProtonMail
    EmailProtonMail,
    /// /^v=spf1/ and parsed SPF domains & IPs
    SPF {
        /// A list of all successfully parsed SPF parts (unparsable parts simply skipped)
        parts: Vec<SPFPart>,
    },
}

static BASIC_TXT_TYPES_WITH_REGEX: [TxtScanInfo; 14] = [
    TxtScanInfo::HasGoogleAccount,
    TxtScanInfo::HasGlobalsignAccount,
    TxtScanInfo::HasGlobalsignSMime,
    TxtScanInfo::HasDocusignAccount,
    TxtScanInfo::HasAppleAccount,
    TxtScanInfo::HasFacebookAccount,
    TxtScanInfo::HasHubspotAccount,
    TxtScanInfo::HasMsDynamics365,
    TxtScanInfo::HasStripeAccount,
    TxtScanInfo::HasOneTrustSso,
    TxtScanInfo::HasBrevoAccount,
    TxtScanInfo::OwnsAtlassianAccounts,
    TxtScanInfo::OwnsZoomAccounts,
    TxtScanInfo::EmailProtonMail,
];

impl TxtScanInfo {
    fn matcher_regex(&self) -> Option<&'static Regex> {
        static RE_HAS_GOOGLE_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^GOOGLE-SITE-VERIFICATION=").unwrap());
        static RE_HAS_GLOBALSIGN_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)globalsign").unwrap());
        static RE_HAS_GLOBALSIGN_SMIME: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)globalsign-smime").unwrap());
        static RE_HAS_DOCUSIGN_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^docusign").unwrap());
        static RE_HAS_APPLE_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^apple-domain-verification=").unwrap());
        static RE_HAS_FACEBOOK_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^facebook-domain-verification=").unwrap());
        static RE_HAS_HUBSPOT_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^hubspot-developer-verification=").unwrap());
        static RE_HAS_MS_DYNAMICS365: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^d365mktkey=").unwrap());
        static RE_HAS_STRIPE_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^stripe-verification=").unwrap());
        static RE_HAS_ONE_TRUST_SSO: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^onetrust-domain-verification=").unwrap());
        static RE_HAS_BREVO_ACCOUNT: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^brevo-code:").unwrap());
        static RE_OWNS_ATLASSIAN_ACCOUNTS: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^atlassian-domain-verification=").unwrap());
        static RE_OWNS_ZOOM_ACCOUNTS: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^ZOOM_verify_").unwrap());
        static RE_EMAIL_PROTON_MAIL: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"(?i-u)^protonmail-verification=").unwrap());

        match self {
            TxtScanInfo::HasGoogleAccount => Some(&RE_HAS_GOOGLE_ACCOUNT),
            TxtScanInfo::HasGlobalsignAccount => Some(&RE_HAS_GLOBALSIGN_ACCOUNT),
            TxtScanInfo::HasGlobalsignSMime => Some(&RE_HAS_GLOBALSIGN_SMIME),
            TxtScanInfo::HasDocusignAccount => Some(&RE_HAS_DOCUSIGN_ACCOUNT),
            TxtScanInfo::HasAppleAccount => Some(&RE_HAS_APPLE_ACCOUNT),
            TxtScanInfo::HasFacebookAccount => Some(&RE_HAS_FACEBOOK_ACCOUNT),
            TxtScanInfo::HasHubspotAccount => Some(&RE_HAS_HUBSPOT_ACCOUNT),
            TxtScanInfo::HasMsDynamics365 => Some(&RE_HAS_MS_DYNAMICS365),
            TxtScanInfo::HasStripeAccount => Some(&RE_HAS_STRIPE_ACCOUNT),
            TxtScanInfo::HasOneTrustSso => Some(&RE_HAS_ONE_TRUST_SSO),
            TxtScanInfo::HasBrevoAccount => Some(&RE_HAS_BREVO_ACCOUNT),
            TxtScanInfo::OwnsAtlassianAccounts => Some(&RE_OWNS_ATLASSIAN_ACCOUNTS),
            TxtScanInfo::OwnsZoomAccounts => Some(&RE_OWNS_ZOOM_ACCOUNTS),
            TxtScanInfo::EmailProtonMail => Some(&RE_EMAIL_PROTON_MAIL),
            _ => None,
        }
    }
}

impl Display for TxtScanInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            TxtScanInfo::HasGoogleAccount => write!(f, "HasGoogleAccount"),
            TxtScanInfo::HasDocusignAccount => write!(f, "HasDocusignAccount"),
            TxtScanInfo::HasAppleAccount => write!(f, "HasAppleAccount"),
            TxtScanInfo::HasFacebookAccount => write!(f, "HasFacebookAccount"),
            TxtScanInfo::HasHubspotAccount => write!(f, "HasHubspotAccount"),
            TxtScanInfo::HasMsDynamics365 => write!(f, "HasMSDynamics365"),
            TxtScanInfo::HasStripeAccount => write!(f, "HasStripeAccount"),
            TxtScanInfo::HasOneTrustSso => write!(f, "HasOneTrustSSO"),
            TxtScanInfo::HasBrevoAccount => write!(f, "HasBrevoAccount"),
            TxtScanInfo::HasGlobalsignAccount => write!(f, "HasGlobalsignAccount"),
            TxtScanInfo::HasGlobalsignSMime => write!(f, "HasGlobalsignSMime"),
            TxtScanInfo::OwnsAtlassianAccounts => write!(f, "OwnsAtlassianAccounts"),
            TxtScanInfo::OwnsZoomAccounts => write!(f, "OwnsZoomAccounts"),
            TxtScanInfo::EmailProtonMail => write!(f, "EmailProtonMail"),
            TxtScanInfo::SPF { parts } => {
                write!(f, "SPF")?;
                for part in parts {
                    write!(f, " {}", part)?;
                }
                Ok(())
            }
        }
    }
}

/// Contains a single parsed TXT line along with the domain it was found on.
#[derive(Debug, Clone)]
pub struct DnsTxtScanResult {
    /// The domain this DNS entry was found on
    pub domain: String,
    /// The record (part) that was matched with this scan result.
    pub rule: String,
    /// The parsed DNS TXT entry
    pub info: TxtScanInfo,
}

/*
some more not yet mapped root domain results:

AkXbiQpYI7uX1sj7+NSmNLAv7t8dX15bc+LseeHs JFX9XIdflE1L8M3US5IfRzqPIUBd9zj1jMEhcl0f c2njJg==
bw=IOlfo6xQJX+xewM7+IiPqOSIPtLXKrWoS2RXCTPMmQZc
fg2t0gov9424p2tdcuo94goe9j
MS=ADD367D1CEC313426372A11C71D893E0B125A F07
MS=CF8A084602474BA62021A3664345E6E1EEB8233E
MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB
MS=ms15401227
MS=ms71454350
OSSRH-87525
proxy-ssl.webflow.com
t7sebee51jrj7vm932k531hipa
webexdomainverification.8YX6G=6e6922db-e3e6-4a36-904e-a805c28087fa
*/

/// Recursive DNS TXT scan
pub async fn start_dns_txt_scan(
    settings: DnsTxtScanSettings,
    tx: Sender<DnsTxtScanResult>,
) -> Result<(), DnsResolutionError> {
    info!("Started DNS TXT scanning");

    let resolver = TokioAsyncResolver::tokio_from_system_conf()
        .map_err(DnsResolutionError::CreateSystemResolver)?;

    let mut tasks = JoinSet::new();

    for domain in settings.domains {
        scan(&mut tasks, &resolver, &tx, domain);
    }

    while tasks.join_next().await.is_some() {}

    info!("Finished DNS resolution");

    Ok(())
}

fn scan(
    tasks: &mut JoinSet<()>,
    resolver: &ResolverT,
    tx: &Sender<DnsTxtScanResult>,
    domain: String,
) {
    tasks.spawn(domain_impl(resolver.clone(), tx.clone(), domain));
}

async fn process_txt_record(tx: &Sender<DnsTxtScanResult>, domain: &str, record: &[u8]) {
    if record.starts_with(b"v=spf1") {
        tx.send(DnsTxtScanResult {
            domain: domain.to_owned(),
            rule: String::from_utf8_lossy(record).to_string(),
            info: TxtScanInfo::SPF {
                parts: parse_spf(&record[6..]),
            },
        })
        .await
        .ok();
    }

    for txt_type in &BASIC_TXT_TYPES_WITH_REGEX {
        let regex = txt_type.matcher_regex().unwrap();
        if regex.is_match(record) {
            tx.send(DnsTxtScanResult {
                domain: domain.to_owned(),
                rule: String::from_utf8_lossy(record).to_string(),
                info: txt_type.clone(),
            })
            .await
            .ok();
        }
    }
}

async fn recurse_txt(tx: &Sender<DnsTxtScanResult>, domain: &str, records: &[Record]) {
    for record in records {
        if let Some(rdata) = record.data() {
            let txt = rdata.as_txt().unwrap(); // only TXT records allowed
            for data in txt.txt_data() {
                process_txt_record(tx, domain, data).await;
            }
        }
    }
}

async fn domain_impl(resolver: ResolverT, tx: Sender<DnsTxtScanResult>, domain: String) {
    if let Ok(res) = resolve(resolver.txt_lookup(&domain)).await {
        recurse_txt(&tx, &domain, res.as_lookup().records()).await;
    }

    debug!("Finished dns resolution for {}", domain);
}
