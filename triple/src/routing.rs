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

//! Deterministic weighted picks and snapshot-pinned native Triple calls.
use crate::{
    Error, Result, Snapshot,
    proto::route::v1 as route,
    snapshot::{duration, weights},
};
use rpc::{CallOptions, Client, Deadline, Limits, Metadata, rustls::ClientConfig};
use std::{sync::Arc, time::Duration};

/// An owned route decision, unaffected by future resource updates.
#[derive(Clone, Debug)]
pub struct Selection {
    /// Selected cluster name.
    pub cluster: String,
    /// Selected healthy socket address.
    pub address: String,
    /// Generation from which the decision was made.
    pub generation: u64,
    pub(crate) tls: Option<Arc<ClientConfig>>,
    pub(crate) server_name: String,
    pub(crate) connect_timeout: Duration,
    pub(crate) timeout: Duration,
}
impl Snapshot {
    /// Selects a weighted cluster and healthy endpoint using a deterministic ticket.
    pub fn select(
        &self,
        listener: &str,
        authority: &str,
        path: &str,
        metadata: &Metadata,
        ticket: u64,
    ) -> Result<Selection> {
        let configuration = self.listeners.get(listener).ok_or_else(|| {
            if self.pending.contains(listener) {
                Error::Unavailable(listener.into())
            } else {
                Error::NoRoute(listener.into())
            }
        })?;
        let authority = authority.to_ascii_lowercase();
        let host = configuration
            .virtual_hosts
            .iter()
            .filter_map(|host| {
                host.domains
                    .iter()
                    .filter_map(|domain| domain_score(domain, &authority))
                    .max()
                    .map(|score| (score, host))
            })
            .max_by_key(|v| v.0)
            .map(|(_, host)| host)
            .ok_or_else(|| Error::NoRoute(path.into()))?;
        let route = host
            .routes
            .iter()
            .find(|route| {
                route
                    .r#match
                    .as_ref()
                    .is_some_and(|m| matches(m, &authority, path, metadata))
            })
            .ok_or_else(|| Error::NoRoute(path.into()))?;
        let action = match &route.action {
            Some(route::route::Action::Route(action)) => action,
            _ => return Err(Error::NoRoute(path.into())),
        };
        let weights = weights(action)?;
        let sum = weights.iter().map(|w| w.1).sum::<u64>();
        let mut offset = ticket % sum;
        let selected = weights
            .iter()
            .find(|(_, weight)| {
                if offset < *weight {
                    true
                } else {
                    offset -= *weight;
                    false
                }
            })
            .ok_or_else(|| Error::NoRoute(path.into()))?;
        let cluster = self
            .clusters
            .get(&selected.0)
            .ok_or_else(|| Error::Unavailable(selected.0.clone()))?;
        let sum = cluster.endpoints.iter().map(|e| e.weight).sum::<u64>();
        if sum == 0 {
            return Err(Error::NoEndpoint(selected.0.clone()));
        }
        let mut offset = (ticket / weights.iter().map(|w| w.1).sum::<u64>()) % sum;
        let endpoint = cluster
            .endpoints
            .iter()
            .find(|endpoint| {
                if offset < endpoint.weight {
                    true
                } else {
                    offset -= endpoint.weight;
                    false
                }
            })
            .ok_or_else(|| Error::NoEndpoint(selected.0.clone()))?;
        Ok(Selection {
            cluster: selected.0.clone(),
            address: endpoint.address.clone(),
            generation: self.generation,
            tls: cluster.tls.clone(),
            server_name: cluster.server_name.clone(),
            connect_timeout: cluster.connect_timeout,
            timeout: duration(action.timeout.as_ref(), Duration::ZERO)?,
        })
    }
}
impl Selection {
    /// Connects once to the chosen endpoint; callers retain the client for in-flight calls.
    pub async fn connect(&self, limits: Limits) -> Result<Client> {
        let operation = async {
            match &self.tls {
                None => Ok(Client::connect(&self.address, limits).await?),
                Some(config) => {
                    let name = if self.server_name.is_empty() {
                        crate::bootstrap::host(&self.address)?
                    } else {
                        self.server_name.clone()
                    };
                    Ok(Client::connect_tls(&self.address, &name, config.clone(), limits).await?)
                }
            }
        };
        tokio::time::timeout(self.connect_timeout, operation)
            .await
            .map_err(|_| Error::Unavailable("endpoint connect timeout".into()))?
    }
    /// Applies the route timeout to the caller's budget, without extending an earlier deadline.
    pub fn call_options(&self, options: &CallOptions) -> Result<CallOptions> {
        let mut options = CallOptions {
            metadata: options.metadata.clone(),
            deadline: options.deadline,
            cancellation: options.cancellation.clone(),
        };
        if !self.timeout.is_zero() {
            let deadline = Deadline::after(self.timeout)?;
            options.deadline = Some(
                options
                    .deadline
                    .map_or(deadline, |existing| existing.min(deadline)),
            );
        }
        Ok(options)
    }
}
fn domain_score(domain: &str, authority: &str) -> Option<(u8, usize)> {
    let domain = domain.to_ascii_lowercase();
    if domain == authority {
        Some((4, domain.len()))
    } else if domain == "*" {
        Some((1, 0))
    } else if domain.starts_with("*.")
        && authority.ends_with(&domain[1..])
        && authority.len() > domain.len() - 1
    {
        Some((3, domain.len()))
    } else if domain.ends_with(".*")
        && authority.starts_with(&domain[..domain.len() - 1])
        && authority.len() > domain.len() - 1
    {
        Some((2, domain.len()))
    } else {
        None
    }
}
fn matches(matcher: &route::RouteMatch, authority: &str, path: &str, metadata: &Metadata) -> bool {
    let path_match = match &matcher.path_specifier {
        Some(route::route_match::PathSpecifier::Path(p)) => path == p,
        Some(route::route_match::PathSpecifier::Prefix(p)) => path.starts_with(p),
        _ => false,
    };
    path_match
        && matcher.headers.iter().all(|header| {
            let matches = |value: &str| match &header.header_match_specifier {
                Some(route::header_matcher::HeaderMatchSpecifier::ExactMatch(want)) => {
                    value == want
                }
                Some(route::header_matcher::HeaderMatchSpecifier::PrefixMatch(want)) => {
                    value.starts_with(want)
                }
                _ => false,
            };
            match header.name.as_str() {
                ":authority" => matches(authority),
                ":path" => matches(path),
                _ => metadata.ascii_values(&header.name).any(matches),
            }
        })
}
