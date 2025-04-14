//! This module holds the swagger definitions.
//!
//! They got created with [utoipa].

use utoipa::openapi::security::ApiKey;
use utoipa::openapi::security::ApiKeyValue;
use utoipa::openapi::security::Http;
use utoipa::openapi::security::HttpAuthScheme;
use utoipa::openapi::security::SecurityScheme;
use utoipa::Modify;
use utoipa::OpenApi;

use super::service;
use crate::api::handler::aggregation_source;
use crate::api::handler::api_keys;
use crate::api::handler::attack_results;
use crate::api::handler::attacks;
use crate::api::handler::auth;
use crate::api::handler::bearer_tokens;
use crate::api::handler::common;
use crate::api::handler::data_export;
use crate::api::handler::domains;
use crate::api::handler::files;
use crate::api::handler::finding_affected;
use crate::api::handler::finding_categories;
use crate::api::handler::finding_definitions;
use crate::api::handler::finding_factory;
use crate::api::handler::findings;
use crate::api::handler::global_tags;
use crate::api::handler::hosts;
use crate::api::handler::http_services;
use crate::api::handler::leeches;
use crate::api::handler::oauth;
use crate::api::handler::oauth_applications;
use crate::api::handler::oauth_decisions;
use crate::api::handler::ports;
use crate::api::handler::services;
use crate::api::handler::settings;
use crate::api::handler::users;
use crate::api::handler::websocket;
use crate::api::handler::wordlists;
use crate::api::handler::workspace_invitations;
use crate::api::handler::workspace_tags;
use crate::api::handler::workspaces;
use crate::chan;
use crate::modules::oauth::schemas as oauth_schemas;

struct SecurityAddon;
impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Cookie(ApiKeyValue::new("id"))),
            )
        }
    }
}

struct SecurityAddon2;
impl Modify for SecurityAddon2 {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_token",
                SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
            )
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        auth::handler::test,
        auth::handler::login,
        auth::handler::logout,
        auth::handler::start_auth,
        auth::handler::finish_auth,
        auth::handler::start_register,
        auth::handler::finish_register,
        bearer_tokens::handler_admin::create_bearer_token,
        bearer_tokens::handler_admin::list_all_bearer_tokens,
        bearer_tokens::handler_admin::delete_bearer_token,
        leeches::handler_admin::create_leech,
        leeches::handler_admin::delete_leech,
        leeches::handler_admin::get_all_leeches,
        leeches::handler_admin::get_leech,
        leeches::handler_admin::update_leech,
        leeches::handler_admin::gen_leech_config,
        websocket::websocket,
        users::handler_admin::create_user,
        users::handler_admin::delete_user,
        users::handler_admin::get_user,
        users::handler_admin::get_all_users_admin,
        users::handler::get_me,
        users::handler::update_me,
        users::handler::set_password,
        users::handler::get_all_users,
        workspaces::handler::create_workspace,
        workspaces::handler::delete_workspace,
        workspaces::handler::get_workspace,
        workspaces::handler::get_all_workspaces,
        workspaces::handler::update_workspace,
        workspaces::handler_admin::get_workspace_admin,
        workspaces::handler_admin::get_all_workspaces_admin,
        workspaces::handler::transfer_ownership,
        workspaces::handler::create_invitation,
        workspaces::handler::retract_invitation,
        workspaces::handler::get_all_workspace_invitations,
        workspaces::handler::search,
        workspaces::handler::get_searches,
        workspaces::handler::get_search_results,
        workspaces::handler::archive_workspace,
        workspaces::handler::unarchive_workspace,
        files::handler::upload_file,
        files::handler::upload_image,
        files::handler::download_thumbnail,
        files::handler::download_file,
        files::handler_admin::get_all_files_admin,
        files::handler_admin::download_file_admin,
        files::handler_admin::delete_file_admin,
        attacks::handler::bruteforce_subdomains,
        attacks::handler::query_certificate_transparency,
        attacks::handler::delete_attack,
        attacks::handler::get_attack,
        attacks::handler::get_all_attacks,
        attacks::handler::get_workspace_attacks,
        attacks::handler::query_dehashed,
        attacks::handler::hosts_alive_check,
        attacks::handler::service_detection,
        attacks::handler::udp_service_detection,
        attacks::handler::dns_resolution,
        attacks::handler::dns_txt_scan,
        attacks::handler::os_detection,
        attacks::handler::testssl,
        attack_results::handler::get_bruteforce_subdomains_results,
        attack_results::handler::get_query_certificate_transparency_results,
        attack_results::handler::get_query_unhashed_results,
        attack_results::handler::get_host_alive_results,
        attack_results::handler::get_service_detection_results,
        attack_results::handler::get_udp_service_detection_results,
        attack_results::handler::get_dns_resolution_results,
        attack_results::handler::get_dns_txt_scan_results,
        attack_results::handler::get_os_detection_results,
        attack_results::handler::get_testssl_results,
        oauth_applications::handler_admin::create_oauth_app,
        oauth_applications::handler_admin::get_all_oauth_apps,
        oauth_applications::handler_admin::get_oauth_app,
        oauth_applications::handler_admin::update_oauth_app,
        oauth_applications::handler_admin::delete_oauth_app,
        oauth::handler::info,
        oauth::handler::accept,
        oauth::handler::deny,
        oauth_decisions::handler::get_decisions,
        oauth_decisions::handler::revoke_decision,
        settings::handler_admin::get_settings,
        settings::handler_admin::update_settings,
        api_keys::handler::create_api_key,
        api_keys::handler::delete_api_key,
        api_keys::handler::get_api_keys,
        api_keys::handler::update_api_key,
        global_tags::handler_admin::create_global_tag,
        global_tags::handler::get_all_global_tags,
        global_tags::handler_admin::update_global_tag,
        global_tags::handler_admin::delete_global_tag,
        workspace_tags::handler::create_workspace_tag,
        workspace_tags::handler::get_all_workspace_tags,
        workspace_tags::handler::update_workspace_tag,
        workspace_tags::handler::delete_workspace_tag,
        hosts::handler::get_all_hosts,
        hosts::handler::get_host,
        hosts::handler::create_host,
        hosts::handler::update_host,
        hosts::handler::delete_host,
        hosts::handler::get_host_sources,
        hosts::handler::get_host_relations,
        hosts::handler::get_host_findings,
        ports::handler::get_all_ports,
        ports::handler::get_port,
        ports::handler::create_port,
        ports::handler::update_port,
        ports::handler::delete_port,
        ports::handler::get_port_sources,
        ports::handler::get_port_relations,
        ports::handler::get_port_findings,
        services::handler::get_all_services,
        services::handler::get_service,
        services::handler::create_service,
        services::handler::update_service,
        services::handler::delete_service,
        services::handler::get_service_sources,
        services::handler::get_service_relations,
        services::handler::get_service_findings,
        domains::handler::get_all_domains,
        domains::handler::get_domain,
        domains::handler::create_domain,
        domains::handler::update_domain,
        domains::handler::delete_domain,
        domains::handler::get_domain_sources,
        domains::handler::get_domain_relations,
        domains::handler::get_domain_findings,
        http_services::handler::get_all_http_services,
        http_services::handler::get_http_service,
        http_services::handler::create_http_service,
        http_services::handler::update_http_service,
        http_services::handler::delete_http_service,
        http_services::handler::get_http_service_sources,
        http_services::handler::get_http_service_relations,
        http_services::handler::get_http_service_findings,
        wordlists::handler::get_all_wordlists,
        wordlists::handler_admin::create_wordlist_admin,
        wordlists::handler_admin::get_all_wordlists_admin,
        wordlists::handler_admin::update_wordlist_admin,
        wordlists::handler_admin::delete_wordlist_admin,
        workspace_invitations::handler::get_all_invitations,
        workspace_invitations::handler::accept_invitation,
        workspace_invitations::handler::decline_invitation,
        findings::handler::create_finding,
        findings::handler::get_all_findings,
        findings::handler::get_finding,
        findings::handler::update_finding,
        findings::handler::delete_finding,
        finding_affected::handler::create_finding_affected,
        finding_affected::handler::create_finding_affected_bulk,
        finding_affected::handler::get_finding_affected,
        finding_affected::handler::update_finding_affected,
        finding_affected::handler::delete_finding_affected,
        finding_categories::handler::get_all_finding_categories,
        finding_categories::handler_admin::create_finding_category,
        finding_categories::handler_admin::update_finding_category,
        finding_categories::handler_admin::delete_finding_category,
        finding_definitions::handler::create_finding_definition,
        finding_definitions::handler::get_finding_definition,
        finding_definitions::handler::get_all_finding_definitions,
        finding_definitions::handler::update_finding_definition,
        finding_definitions::handler_admin::get_finding_definition_usage,
        finding_definitions::handler_admin::delete_finding_definition,
        finding_factory::handler_admin::get_finding_factory_entries,
        finding_factory::handler_admin::update_finding_factory_entry,
    ),
    components(schemas(
        common::schema::ApiErrorResponse,
        common::schema::ApiStatusCode,
        common::schema::UuidResponse,
        common::schema::UuidsResponse,
        common::schema::SimpleTag,
        common::schema::TagType,
        common::schema::PageParams,
        aggregation_source::schema::SimpleAggregationSource,
        aggregation_source::schema::FullAggregationSource,
        aggregation_source::schema::ManualInsert,
        aggregation_source::schema::SourceAttack,
        aggregation_source::schema::SourceAttackResult,
        auth::schema::LoginRequest,
        auth::schema::FinishRegisterRequest,
        bearer_tokens::schema::CreateBearerTokenRequest,
        bearer_tokens::schema::FullBearerToken,
        bearer_tokens::schema::ListBearerTokens,
        leeches::schema::CreateLeechRequest,
        leeches::schema::SimpleLeech,
        leeches::schema::ListLeeches,
        leeches::schema::UpdateLeechRequest,
        leeches::schema::LeechConfig,
        leeches::schema::LeechTlsConfig,
        users::schema::CreateUserRequest,
        users::schema::SimpleUser,
        users::schema::FullUser,
        users::schema::ListFullUsers,
        users::schema::UpdateMeRequest,
        users::schema::SetPasswordRequest,
        users::schema::SimpleUser,
        users::schema::ListUsers,
        users::schema::UserPermission,
        workspaces::schema::CreateWorkspaceRequest,
        workspaces::schema::SimpleWorkspace,
        workspaces::schema::FullWorkspace,
        workspaces::schema::ListWorkspaces,
        workspaces::schema::UpdateWorkspaceRequest,
        workspaces::schema::TransferWorkspaceRequest,
        workspaces::schema::InviteToWorkspaceRequest,
        workspaces::schema::SearchWorkspaceRequest,
        workspaces::schema::SearchEntry,
        workspaces::schema::SearchResultEntry,
        files::schema::FullFile,
        attacks::schema::SimpleAttack,
        attacks::schema::ListAttacks,
        attacks::schema::BruteforceSubdomainsRequest,
        attacks::schema::HostsAliveRequest,
        attacks::schema::QueryCertificateTransparencyRequest,
        attacks::schema::PortOrRange,
        attacks::schema::ServiceDetectionRequest,
        attacks::schema::UdpServiceDetectionRequest,
        attacks::schema::DnsResolutionRequest,
        attacks::schema::DnsTxtScanRequest,
        attacks::schema::OsDetectionRequest,
        attacks::schema::TestSSLRequest,
        attacks::schema::DomainOrNetwork,
        attacks::schema::AttackType,
        attacks::schema::StartTLSProtocol,
        attack_results::schema::SimpleBruteforceSubdomainsResult,
        attack_results::schema::FullQueryCertificateTransparencyResult,
        attack_results::schema::SimpleQueryUnhashedResult,
        attack_results::schema::SimpleHostAliveResult,
        attack_results::schema::FullServiceDetectionResult,
        attack_results::schema::FullUdpServiceDetectionResult,
        attack_results::schema::SimpleDnsResolutionResult,
        attack_results::schema::DnsTxtScanEntry,
        attack_results::schema::SimpleDnsTxtScanResult,
        attack_results::schema::FullDnsTxtScanResult,
        attack_results::schema::FullOsDetectionResult,
        attack_results::schema::DnsTxtScanSpfType,
        attack_results::schema::DnsTxtScanServiceHintType,
        attack_results::schema::DnsTxtScanSummaryType,
        attack_results::schema::FullTestSSLResult,
        attack_results::schema::TestSSLFinding,
        attack_results::schema::TestSSLSection,
        attack_results::schema::TestSSLSeverity,
        dehashed_rs::Query,
        dehashed_rs::SearchType,
        attacks::schema::QueryDehashedRequest,
        oauth_applications::schema::CreateAppRequest,
        oauth_applications::schema::SimpleOauthClient,
        oauth_applications::schema::FullOauthClient,
        oauth_applications::schema::ListOauthApplications,
        oauth_applications::schema::UpdateAppRequest,
        oauth::schema::OpenRequestInfo,
        oauth_decisions::schema::ListOauthDecisions,
        oauth_decisions::schema::FullOauthDecision,
        settings::schema::SettingsFull,
        settings::schema::UpdateSettingsRequest,
        api_keys::schema::FullApiKey,
        api_keys::schema::CreateApiKeyRequest,
        api_keys::schema::ListApiKeys,
        api_keys::schema::UpdateApiKeyRequest,
        hosts::schema::SimpleHost,
        hosts::schema::FullHost,
        hosts::schema::UpdateHostRequest,
        hosts::schema::CreateHostRequest,
        hosts::schema::GetAllHostsQuery,
        hosts::schema::HostRelations,
        hosts::schema::OsType,
        hosts::schema::HostCertainty,
        hosts::schema::ManualHostCertainty,
        ports::schema::SimplePort,
        ports::schema::FullPort,
        ports::schema::UpdatePortRequest,
        ports::schema::CreatePortRequest,
        ports::schema::GetAllPortsQuery,
        ports::schema::PortRelations,
        ports::schema::PortCertainty,
        ports::schema::ManualPortCertainty,
        ports::schema::PortProtocol,
        services::schema::SimpleService,
        services::schema::FullService,
        services::schema::UpdateServiceRequest,
        services::schema::CreateServiceRequest,
        services::schema::GetAllServicesQuery,
        services::schema::ServiceRelations,
        services::schema::ServiceProtocols,
        services::schema::ServiceCertainty,
        services::schema::ManualServiceCertainty,
        domains::schema::SimpleDomain,
        domains::schema::FullDomain,
        domains::schema::UpdateDomainRequest,
        domains::schema::CreateDomainRequest,
        domains::schema::GetAllDomainsQuery,
        domains::schema::DomainRelations,
        domains::schema::DomainCertainty,
        http_services::schema::SimpleHttpService,
        http_services::schema::FullHttpService,
        http_services::schema::UpdateHttpServiceRequest,
        http_services::schema::CreateHttpServiceRequest,
        http_services::schema::GetAllHttpServicesQuery,
        http_services::schema::HttpServiceRelations,
        http_services::schema::HttpServiceCertainty,
        http_services::schema::ManualHttpServiceCertainty,
        common::schema::HostResultsPage,
        common::schema::DomainResultsPage,
        common::schema::PortResultsPage,
        common::schema::ServiceResultsPage,
        common::schema::Color,
        global_tags::schema::CreateGlobalTagRequest,
        global_tags::schema::FullGlobalTag,
        global_tags::schema::ListGlobalTags,
        global_tags::schema::UpdateGlobalTag,
        workspace_tags::schema::FullWorkspaceTag,
        workspace_tags::schema::ListWorkspaceTags,
        workspace_tags::schema::UpdateWorkspaceTag,
        workspace_tags::schema::CreateWorkspaceTagRequest,
        wordlists::schema::ListWordlists,
        wordlists::schema::SimpleWordlist,
        wordlists::schema::CreateWordlistRequest,
        wordlists::schema::ListWordlistsAdmin,
        wordlists::schema::FullWordlist,
        wordlists::schema::UpdateWordlistRequest,
        workspace_invitations::schema::FullWorkspaceInvitation,
        workspace_invitations::schema::WorkspaceInvitationList,
        chan::ws_manager::schema::WsMessage,
        chan::ws_manager::schema::WsClientMessage,
        chan::ws_manager::schema::AggregationType,
        chan::ws_manager::schema::CertificateTransparencyEntry,
        chan::ws_manager::schema::Change,
        chan::ws_manager::schema::FindingSection,
        chan::ws_manager::schema::FindingDetails,
        chan::ws_manager::schema::EditorTarget,
        chan::ws_manager::schema::CursorPosition,
        findings::schema::CreateFindingRequest,
        findings::schema::UpdateFindingRequest,
        findings::schema::SimpleFinding,
        findings::schema::FullFinding,
        findings::schema::SimpleFindingAffected,
        findings::schema::ListFindings,
        findings::schema::FindingSeverity,
        finding_affected::schema::CreateFindingAffectedRequest,
        finding_affected::schema::CreateFindingAffectedBulkRequest,
        finding_affected::schema::CreateFindingAffectedBulkRequestItem,
        finding_affected::schema::UpdateFindingAffectedRequest,
        finding_affected::schema::FullFindingAffected,
        finding_affected::schema::FindingAffectedObject,
        finding_categories::schema::CreateFindingCategoryRequest,
        finding_categories::schema::UpdateFindingCategoryRequest,
        finding_categories::schema::ListFindingCategories,
        finding_categories::schema::SimpleFindingCategory,
        finding_definitions::schema::CreateFindingDefinitionRequest,
        finding_definitions::schema::FullFindingDefinition,
        finding_definitions::schema::SimpleFindingDefinition,
        finding_definitions::schema::ListFindingDefinitions,
        finding_definitions::schema::UpdateFindingDefinitionRequest,
        finding_definitions::schema::ListFindingDefinitionUsages,
        finding_definitions::schema::FindingDefinitionUsage,
        finding_factory::schema::GetFindingFactoryEntriesResponse,
        finding_factory::schema::FullFindingFactoryEntry,
        finding_factory::schema::UpdateFindingFactoryEntryRequest,
        crate::modules::finding_factory::schema::FindingFactoryIdentifier,
    )),
    modifiers(&SecurityAddon)
)]
pub(crate) struct FrontendApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        oauth::handler::auth,
        oauth::handler::token,
        data_export::handler::export_workspace,
        data_export::handler::download_export_file,
    ),
    components(schemas(
        domains::schema::DomainCertainty,
        hosts::schema::OsType,
        hosts::schema::HostCertainty,
        ports::schema::PortProtocol,
        ports::schema::PortCertainty,
        services::schema::ServiceCertainty,
        services::schema::ServiceProtocols,
        http_services::schema::HttpServiceCertainty,
        findings::schema::FindingSeverity,
        common::schema::ApiErrorResponse,
        common::schema::ApiStatusCode,
        oauth_schemas::TokenRequest,
        oauth_schemas::TokenResponse,
        oauth_schemas::TokenError,
        oauth_schemas::TokenErrorType,
        chan::ws_manager::schema::AggregationType,
        data_export::schema::AggregatedWorkspace,
        data_export::schema::AggregatedHost,
        data_export::schema::AggregatedPort,
        data_export::schema::AggregatedService,
        data_export::schema::AggregatedHttpService,
        data_export::schema::AggregatedDomain,
        data_export::schema::AggregatedTags,
        data_export::schema::AggregatedRelation,
        data_export::schema::AggregatedFinding,
        data_export::schema::AggregatedFindingAffected,
    )),
    modifiers(&SecurityAddon2)
)]
pub(crate) struct ExternalApi;

#[derive(OpenApi)]
#[openapi(
    paths(service::workspaces::handler::create_workspace),
    components(schemas(
        service::workspaces::schema::CreateWorkspaceRequest,
        common::schema::UuidResponse,
        common::schema::ApiErrorResponse,
        common::schema::ApiStatusCode,
    )),
    modifiers(&SecurityAddon2)
)]
pub(crate) struct ServiceApi;
