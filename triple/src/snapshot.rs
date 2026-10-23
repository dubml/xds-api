// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements.  See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance with
// the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Validated routing graphs published atomically after each accepted update.
use crate::{
    Bootstrap, Cache, Result, decode, invalid,
    proto::{
        cluster::v1::{Cluster, cluster},
        core::v1 as core,
        endpoint::v1::ClusterLoadAssignment,
        extensions::filters::network::http_connection_manager::v1::{
            HttpConnectionManager, http_connection_manager,
        },
        extensions::transport_sockets::tls::v1::UpstreamTlsContext,
        listener::v1::Listener,
        route::v1::{self as route, RouteConfiguration},
    },
    require,
};
use rpc::rustls::ClientConfig;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

/// Immutable, owned routing state; selections survive subsequent updates.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    /// Accepted snapshot generation.
    pub generation: u64,
    /// All currently referenced resources have arrived.
    pub ready: bool,
    pub(crate) listeners: BTreeMap<String, RouteConfiguration>,
    pub(crate) clusters: BTreeMap<String, TargetCluster>,
    pub(crate) pending: BTreeSet<String>,
}
#[derive(Clone, Debug)]
pub(crate) struct TargetCluster {
    pub endpoints: Vec<TargetEndpoint>,
    pub tls: Option<Arc<ClientConfig>>,
    pub server_name: String,
    pub connect_timeout: Duration,
}
#[derive(Clone, Debug)]
pub(crate) struct TargetEndpoint {
    pub address: String,
    pub weight: u64,
}
#[derive(Default)]
pub(crate) struct Dependencies {
    pub routes: BTreeSet<String>,
    pub clusters: BTreeSet<String>,
    pub endpoints: BTreeSet<String>,
}

impl Snapshot {
    pub(crate) fn compile(
        cache: &Cache,
        bootstrap: &Bootstrap,
        generation: u64,
    ) -> Result<(Self, Dependencies)> {
        let mut snapshot = Self {
            generation,
            ..Self::default()
        };
        let mut dependencies = Dependencies::default();
        // Validate all delivered resources, including resources arriving before their references.
        for route in cache.routes.values() {
            validate_route(route)?;
        }
        for assignment in cache.endpoints.values() {
            endpoints(assignment)?;
        }
        let mut compiled = BTreeMap::new();
        for (name, cluster) in &cache.clusters {
            let target = compile_cluster(cluster, cache, bootstrap)?;
            compiled.insert(name.clone(), target);
        }
        for (name, listener) in &cache.listeners {
            let hcm = hcm(listener)?;
            let configuration = match hcm.route_specifier {
                Some(http_connection_manager::RouteSpecifier::Rds(rds)) => {
                    require(!rds.route_config_name.is_empty(), "empty RDS name")?;
                    validate_source(rds.config_source.as_ref())?;
                    dependencies.routes.insert(rds.route_config_name.clone());
                    match cache.routes.get(&rds.route_config_name) {
                        Some(route) => route.clone(),
                        None => {
                            snapshot.pending.insert(name.clone());
                            continue;
                        }
                    }
                }
                Some(http_connection_manager::RouteSpecifier::RouteConfig(route)) => {
                    validate_route(&route)?;
                    route
                }
                None => return Err(invalid("listener lacks route specifier")),
            };
            let names = route_clusters(&configuration)?;
            for cluster_name in names {
                dependencies.clusters.insert(cluster_name.clone());
                if let Some(cluster) = cache.clusters.get(&cluster_name) {
                    if let Some(service) = eds_name(cluster)? {
                        dependencies.endpoints.insert(service.clone());
                        if !cache.endpoints.contains_key(&service) {
                            snapshot.pending.insert(name.clone());
                        }
                    }
                    if let Some(target) = compiled.get(&cluster_name) {
                        snapshot
                            .clusters
                            .insert(cluster_name.clone(), target.clone());
                    }
                } else {
                    snapshot.pending.insert(name.clone());
                }
            }
            snapshot.listeners.insert(name.clone(), configuration);
        }
        snapshot.ready = snapshot.pending.is_empty()
            && !snapshot.listeners.is_empty()
            && snapshot.listeners.values().any(|route| {
                route
                    .virtual_hosts
                    .iter()
                    .any(|host| !host.routes.is_empty())
            });
        Ok((snapshot, dependencies))
    }
}
fn validate_source(source: Option<&core::ConfigSource>) -> Result<()> {
    require(
        source.is_none_or(|s| {
            matches!(
                s.config_source_specifier,
                None | Some(core::config_source::ConfigSourceSpecifier::Ads(_))
            )
        }),
        "only ADS config sources are supported",
    )
}
fn hcm(listener: &Listener) -> Result<HttpConnectionManager> {
    require(
        listener.filter_chains.is_empty()
            && listener.listener_filters.is_empty()
            && listener.use_original_dst != Some(true),
        "only API listeners without network filters are supported",
    )?;
    let any = listener
        .api_listener
        .as_ref()
        .and_then(|l| l.api_listener.as_ref())
        .ok_or_else(|| invalid("missing API listener"))?;
    let hcm: HttpConnectionManager = decode(
        any,
        "extensions.filters.network.http_connection_manager.v1.HttpConnectionManager",
    )?;
    require(hcm.codec_type == 0, "unsupported HCM codec")?;
    for filter in &hcm.http_filters {
        let any=filter.config_type.as_ref().map(|kind|match kind {crate::proto::extensions::filters::network::http_connection_manager::v1::http_filter::ConfigType::TypedConfig(any)=>any}).ok_or_else(||invalid("unconfigured HTTP filter"))?;
        let _: crate::proto::extensions::filters::http::router::v1::Router =
            decode(any, "extensions.filters.http.router.v1.Router")?;
    }
    Ok(hcm)
}
pub(crate) fn route_clusters(configuration: &RouteConfiguration) -> Result<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for host in &configuration.virtual_hosts {
        for route in &host.routes {
            if let Some(route::route::Action::Route(action)) = &route.action {
                for (name, _) in weights(action)? {
                    names.insert(name);
                }
            }
        }
    }
    Ok(names)
}
pub(crate) fn weights(action: &route::RouteAction) -> Result<Vec<(String, u64)>> {
    let values = match &action.cluster_specifier {
        Some(route::route_action::ClusterSpecifier::Cluster(name)) => vec![(name.clone(), 1)],
        Some(route::route_action::ClusterSpecifier::WeightedClusters(weighted)) => {
            let mut names = BTreeSet::new();
            let mut values = Vec::new();
            for c in &weighted.clusters {
                require(
                    c.cluster_header.is_empty() && names.insert(c.name.clone()),
                    "unsupported or duplicate weighted cluster",
                )?;
                let weight = u64::from(c.weight.ok_or_else(|| invalid("missing cluster weight"))?);
                values.push((c.name.clone(), weight));
            }
            let sum = values.iter().map(|v| v.1).sum::<u64>();
            require(
                weighted.total_weight.is_none_or(|w| u64::from(w) == sum),
                "cluster total_weight mismatch",
            )?;
            values
        }
        None => return Err(invalid("missing route cluster")),
    };
    require(
        !values.is_empty()
            && values.iter().all(|(n, _)| !n.is_empty())
            && values.iter().any(|(_, w)| *w > 0),
        "empty cluster or zero total weight",
    )?;
    Ok(values)
}
fn validate_route(configuration: &RouteConfiguration) -> Result<()> {
    require(
        configuration.agent_config.is_none(),
        "agent_config is unsupported by native Triple routing",
    )?;
    let mut domains = BTreeSet::new();
    for host in &configuration.virtual_hosts {
        require(!host.domains.is_empty(), "virtual host requires domains")?;
        for domain in &host.domains {
            require(
                !domain.is_empty() && !domain.chars().any(char::is_whitespace),
                "invalid virtual host domain",
            )?;
            let valid = !domain.contains('*')
                || domain == "*"
                || (domain.matches('*').count() == 1
                    && (domain.starts_with("*.") || domain.ends_with(".*")));
            require(
                valid && domains.insert(domain.to_ascii_lowercase()),
                "invalid or duplicate virtual host domain",
            )?;
        }
        for r in &host.routes {
            let matcher = r
                .r#match
                .as_ref()
                .ok_or_else(|| invalid("missing route match"))?;
            match &matcher.path_specifier {
                Some(route::route_match::PathSpecifier::Path(p))
                | Some(route::route_match::PathSpecifier::Prefix(p)) => {
                    require(p.starts_with('/'), "route path must start with /")?
                }
                _ => return Err(invalid("regex or missing path matcher is unsupported")),
            }
            for h in &matcher.headers {
                require(
                    !h.name.is_empty() && h.name == h.name.to_ascii_lowercase(),
                    "header names must be lowercase",
                )?;
                require(
                    matches!(
                        h.header_match_specifier,
                        Some(
                            route::header_matcher::HeaderMatchSpecifier::ExactMatch(_)
                                | route::header_matcher::HeaderMatchSpecifier::PrefixMatch(_)
                        )
                    ),
                    "regex or missing header matcher is unsupported",
                )?;
            }
            match &r.action {
                Some(route::route::Action::Route(a)) => {
                    weights(a)?;
                    require(
                        a.retry_policy.is_none() && a.fault_policy.is_none(),
                        "retry and fault policies are unsupported",
                    )?;
                    duration(a.timeout.as_ref(), Duration::ZERO)?;
                }
                Some(route::route::Action::NonForwardingAction(_)) => {}
                None => return Err(invalid("missing route action")),
            }
        }
    }
    Ok(())
}
pub(crate) fn duration(
    value: Option<&prost_types::Duration>,
    default: Duration,
) -> Result<Duration> {
    match value {
        None => Ok(default),
        Some(v) => {
            require(
                v.seconds >= 0 && v.nanos >= 0 && v.nanos < 1_000_000_000,
                "invalid protobuf duration",
            )?;
            Ok(Duration::new(v.seconds as u64, v.nanos as u32))
        }
    }
}
pub(crate) fn eds_name(cluster: &Cluster) -> Result<Option<String>> {
    match &cluster.cluster_discovery_type {
        Some(cluster::ClusterDiscoveryType::Type(value)) if *value == 3 => {
            let cfg = cluster
                .eds_cluster_config
                .as_ref()
                .ok_or_else(|| invalid("EDS cluster lacks config"))?;
            validate_source(cfg.eds_config.as_ref())?;
            Ok(Some(if cfg.service_name.is_empty() {
                cluster.name.clone()
            } else {
                cfg.service_name.clone()
            }))
        }
        Some(cluster::ClusterDiscoveryType::Type(0)) => Ok(None),
        _ => Err(invalid("only STATIC and EDS clusters are supported")),
    }
}
fn compile_cluster(
    cluster: &Cluster,
    cache: &Cache,
    bootstrap: &Bootstrap,
) -> Result<TargetCluster> {
    require(
        cluster.lb_policy == 0
            && cluster.health_checks.is_empty()
            && cluster.circuit_breakers.is_none()
            && cluster.outlier_detection.is_none()
            && cluster.max_requests_per_connection.is_none()
            && cluster.per_connection_buffer_limit_bytes.is_none(),
        "unsupported cluster policy",
    )?;
    // The contract only carries override_host_status. It limits explicit host
    // overrides, which this router never requests; normal endpoint health
    // filtering remains unchanged. Reject unknown health enum values.
    if let Some(statuses) = cluster
        .common_lb_config
        .as_ref()
        .and_then(|config| config.override_host_status.as_ref())
    {
        require(
            statuses
                .statuses
                .iter()
                .all(|status| (0..=5).contains(status)),
            "unknown override host health status",
        )?;
    }
    let connect_timeout = duration(cluster.connect_timeout.as_ref(), Duration::from_secs(3))?;
    require(!connect_timeout.is_zero(), "zero cluster connect timeout")?;
    let endpoints = match eds_name(cluster)? {
        Some(name) => {
            require(
                cluster.load_assignment.is_none(),
                "EDS cluster must not have inline endpoints",
            )?;
            cache
                .endpoints
                .get(&name)
                .map(endpoints)
                .transpose()?
                .unwrap_or_default()
        }
        None => {
            let assignment = cluster
                .load_assignment
                .as_ref()
                .ok_or_else(|| invalid("STATIC cluster requires load_assignment"))?;
            require(
                assignment.cluster_name == cluster.name,
                "STATIC assignment name mismatch",
            )?;
            endpoints(assignment)?
        }
    };
    let (tls, server_name) = match &cluster.transport_socket {
        None => (None, String::new()),
        Some(socket) => {
            require(
                socket.name == "transport_sockets.tls"
                    || socket.name == "envoy.transport_sockets.tls",
                "unsupported transport socket",
            )?;
            let any = socket
                .config_type
                .as_ref()
                .map(|c| match c {
                    core::transport_socket::ConfigType::TypedConfig(any) => any,
                })
                .ok_or_else(|| invalid("TLS socket lacks config"))?;
            let context: UpstreamTlsContext = decode(
                any,
                "extensions.transport_sockets.tls.v1.UpstreamTlsContext",
            )?;
            let tls = bootstrap.upstream_tls(&context)?;
            (Some(tls), context.sni)
        }
    };
    Ok(TargetCluster {
        endpoints,
        tls,
        server_name,
        connect_timeout,
    })
}
fn endpoints(assignment: &ClusterLoadAssignment) -> Result<Vec<TargetEndpoint>> {
    let mut priorities: BTreeMap<u32, Vec<TargetEndpoint>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for locality in &assignment.endpoints {
        require(
            locality.proximity.is_none(),
            "endpoint proximity is unsupported",
        )?;
        let locality_weight = u64::from(locality.load_balancing_weight.unwrap_or(1));
        for endpoint in &locality.lb_endpoints {
            require(
                (0..=5).contains(&endpoint.health_status),
                "unknown endpoint health status",
            )?;
            let host = match &endpoint.host_identifier {
                Some(crate::proto::endpoint::v1::lb_endpoint::HostIdentifier::Endpoint(host)) => {
                    host
                }
                _ => return Err(invalid("endpoint_name is unsupported")),
            };
            let socket = match host.address.as_ref().and_then(|a| a.address.as_ref()) {
                Some(core::address::Address::SocketAddress(socket)) => socket,
                _ => return Err(invalid("endpoint requires socket address")),
            };
            let port = match socket.port_specifier {
                Some(core::socket_address::PortSpecifier::PortValue(port))
                    if port > 0 && port <= 65535 =>
                {
                    port
                }
                _ => return Err(invalid("invalid endpoint port")),
            };
            require(
                !socket.address.is_empty()
                    && !socket.address.chars().any(char::is_whitespace)
                    && !socket.address.contains('/')
                    && !socket.address.contains('@'),
                "invalid endpoint host",
            )?;
            let address = if socket.address.contains(':') {
                format!("[{}]:{port}", socket.address)
            } else {
                format!("{}:{port}", socket.address)
            };
            require(seen.insert(address.clone()), "duplicate endpoint address")?;
            let weight = locality_weight
                .checked_mul(u64::from(endpoint.load_balancing_weight.unwrap_or(1)))
                .ok_or_else(|| invalid("endpoint weight overflow"))?;
            if matches!(endpoint.health_status, 0 | 1) && weight > 0 {
                priorities
                    .entry(locality.priority)
                    .or_default()
                    .push(TargetEndpoint { address, weight });
            }
        }
    }
    let values = priorities.into_values().next().unwrap_or_default();
    values.iter().try_fold(0u64, |sum, e| {
        sum.checked_add(e.weight)
            .ok_or_else(|| invalid("endpoint total weight overflow"))
    })?;
    Ok(values)
}
