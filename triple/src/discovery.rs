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

//! Per-type subscriptions, response validation, ACK/NACK and reconnect replay.
use crate::{
    Bootstrap, Cache, ResourceType, Result, Snapshot,
    proto::service::discovery::v1::{DiscoveryRequest, DiscoveryResponse},
    require,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// Independent subscription state for a single type URL.
#[derive(Clone, Debug, Default)]
pub struct Subscription {
    /// Requested names; empty names mean wildcard only for active LDS/CDS.
    pub names: BTreeSet<String>,
    /// Last accepted version, retained across reconnects.
    pub version: String,
    /// Latest response nonce on this connection.
    pub nonce: String,
    /// Whether this family is currently needed.
    pub active: bool,
    last_response: Option<DiscoveryResponse>,
    last_error: Option<String>,
}
/// Transactional discovery state, independent of a particular ADS connection.
pub struct Discovery {
    bootstrap: Bootstrap,
    cache: Cache,
    subscriptions: BTreeMap<ResourceType, Subscription>,
    snapshot: Arc<Snapshot>,
    listener_received: bool,
}
impl Discovery {
    pub(crate) fn replace_bootstrap(&mut self, bootstrap: Bootstrap) -> Result<()> {
        let (snapshot, _) =
            Snapshot::compile(&self.cache, &bootstrap, self.snapshot.generation + 1)?;
        self.bootstrap = bootstrap;
        self.snapshot = Arc::new(snapshot);
        Ok(())
    }
    /// Starts LDS discovery for explicit listener names or a wildcard empty list.
    pub fn new(bootstrap: Bootstrap, listeners: impl IntoIterator<Item = String>) -> Result<Self> {
        let names: BTreeSet<_> = listeners.into_iter().collect();
        require(
            names.iter().all(|name| !name.is_empty()),
            "empty subscribed listener name",
        )?;
        let mut subscriptions: BTreeMap<_, _> = ResourceType::all()
            .into_iter()
            .map(|kind| (kind, Subscription::default()))
            .collect();
        subscriptions.insert(
            ResourceType::Listener,
            Subscription {
                names,
                active: true,
                ..Subscription::default()
            },
        );
        Ok(Self {
            bootstrap,
            cache: Cache::default(),
            subscriptions,
            snapshot: Arc::new(Snapshot::default()),
            listener_received: false,
        })
    }
    /// Last accepted cache; a NACK does not alter it.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }
    /// Returns an owned view of the latest accepted graph.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.clone()
    }
    /// Returns per-type state.
    pub fn subscription(&self, kind: ResourceType) -> &Subscription {
        &self.subscriptions[&kind]
    }
    /// A validated Listener response has been received at least once.
    pub fn listener_received(&self) -> bool {
        self.listener_received
    }
    /// Replays current subscriptions with versions and node, never old stream nonces.
    pub fn reconnect_requests(&mut self) -> Vec<DiscoveryRequest> {
        for state in self.subscriptions.values_mut() {
            state.nonce.clear();
            state.last_response = None;
            state.last_error = None;
        }
        ResourceType::all()
            .into_iter()
            .filter(|kind| self.subscriptions[kind].active)
            .map(|kind| self.request(kind, None, true))
            .collect()
    }
    /// Fully validates an update before accepting it; returns ACK/NACK and dependent subscriptions.
    pub fn process(&mut self, response: DiscoveryResponse) -> Vec<DiscoveryRequest> {
        let Some(kind) = ResourceType::from_url(&response.type_url) else {
            return vec![DiscoveryRequest {
                type_url: response.type_url,
                response_nonce: response.nonce,
                error_detail: Some(error_detail("unsupported resource type")),
                ..DiscoveryRequest::default()
            }];
        };
        let state = &self.subscriptions[&kind];
        if state.last_response.as_ref() == Some(&response) {
            return vec![self.request(kind, state.last_error.as_deref(), false)];
        }
        let duplicate_nonce = state
            .last_response
            .as_ref()
            .is_some_and(|old| old.nonce == response.nonce);
        let mut candidate = self.cache.clone();
        let outcome = (|| -> Result<_> {
            require(!response.nonce.is_empty(), "empty response nonce")?;
            require(!response.canary, "canary responses are unsupported")?;
            require(!duplicate_nonce, "nonce reused for a different response")?;
            let empty_scope = BTreeSet::new();
            // dubbod sends targeted EDS updates without a wire-level partial marker.
            // Merge assignments by name; an explicitly empty assignment revokes endpoints.
            let scope = if kind == ResourceType::Endpoint || !state.active {
                Some(&empty_scope)
            } else if state.names.is_empty()
                && matches!(kind, ResourceType::Listener | ResourceType::Cluster)
            {
                None
            } else {
                Some(&state.names)
            };
            candidate.apply(kind, &response.resources, scope)?;
            Snapshot::compile(&candidate, &self.bootstrap, self.snapshot.generation + 1)
        })();
        let error = outcome.as_ref().err().map(ToString::to_string);
        let state = self.subscriptions.get_mut(&kind);
        if let Some(state) = state {
            state.nonce = response.nonce.clone();
            state.last_response = Some(response.clone());
            state.last_error = error.clone();
            if error.is_none() {
                state.version = response.version_info;
            }
        }
        let mut requests = vec![self.request(kind, error.as_deref(), false)];
        if let Ok((snapshot, dependencies)) = outcome {
            self.cache = candidate;
            self.snapshot = Arc::new(snapshot);
            if kind == ResourceType::Listener {
                self.listener_received = true;
            }
            for (kind, names) in [
                (ResourceType::Route, dependencies.routes),
                (ResourceType::Cluster, dependencies.clusters),
                (ResourceType::Endpoint, dependencies.endpoints),
            ] {
                let active = !names.is_empty();
                let previous = &self.subscriptions[&kind];
                if names != previous.names || active != previous.active {
                    // Evict resources whose references were withdrawn. Resubscribing must
                    // not make an old cached dependency appear ready before a fresh response.
                    let removed: Vec<_> = previous.names.difference(&names).cloned().collect();
                    for name in removed {
                        match kind {
                            ResourceType::Route => {
                                self.cache.routes.remove(&name);
                            }
                            ResourceType::Cluster => {
                                self.cache.clusters.remove(&name);
                            }
                            ResourceType::Endpoint => {
                                self.cache.endpoints.remove(&name);
                            }
                            ResourceType::Listener => {}
                        }
                    }
                    if let Some(state) = self.subscriptions.get_mut(&kind) {
                        state.names = names;
                        state.active = active;
                    }
                    // Empty CDS would mean wildcard. Keep an unneeded watch dormant instead.
                    if active || kind != ResourceType::Cluster {
                        let mut request = self.request(kind, None, false);
                        // Subscription changes are separate from the ACK above.
                        // A matching nonce with empty EDS/RDS names is interpreted
                        // by dubbod as an ACK that preserves the previous watch.
                        // Clear it to unsubscribe or request fresh dependencies.
                        request.response_nonce.clear();
                        requests.push(request);
                    }
                }
            }
        }
        requests
    }
    fn request(&self, kind: ResourceType, error: Option<&str>, node: bool) -> DiscoveryRequest {
        let state = &self.subscriptions[&kind];
        DiscoveryRequest {
            version_info: state.version.clone(),
            node: node.then(|| self.bootstrap.node.clone()),
            resource_names: state.names.iter().cloned().collect(),
            type_url: kind.type_url().into(),
            response_nonce: state.nonce.clone(),
            error_detail: error.map(error_detail),
        }
    }
}
fn error_detail(message: &str) -> crate::proto::google::rpc::Status {
    crate::proto::google::rpc::Status {
        code: 3,
        message: message.chars().take(1024).collect(),
        details: Vec::new(),
    }
}
