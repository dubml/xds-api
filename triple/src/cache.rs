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

//! Transactional, bounded SotW resource cache with subscription-scoped deletion.
use crate::{
    Result, decode, invalid,
    proto::{
        cluster::v1::Cluster, endpoint::v1::ClusterLoadAssignment, listener::v1::Listener,
        route::v1::RouteConfiguration,
    },
    require,
};
use prost::Message;
use prost_types::Any;
use std::collections::{BTreeMap, BTreeSet};

/// Supported resource families in dependency order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResourceType {
    /// Listener discovery.
    Listener,
    /// Route discovery.
    Route,
    /// Cluster discovery.
    Cluster,
    /// Endpoint discovery.
    Endpoint,
}
impl ResourceType {
    /// The custom contract's type URL, preserving its package names.
    pub fn type_url(self) -> &'static str {
        match self {
            Self::Listener => "type.googleapis.com/listener.v1.Listener",
            Self::Route => "type.googleapis.com/route.v1.RouteConfiguration",
            Self::Cluster => "type.googleapis.com/cluster.v1.Cluster",
            Self::Endpoint => "type.googleapis.com/endpoint.v1.ClusterLoadAssignment",
        }
    }
    /// Recognizes a supported resource type.
    pub fn from_url(url: &str) -> Option<Self> {
        Self::all().into_iter().find(|kind| kind.type_url() == url)
    }
    pub(crate) fn all() -> [Self; 4] {
        [Self::Listener, Self::Route, Self::Cluster, Self::Endpoint]
    }
}
/// Last accepted resources; mutations are staged in a clone before ACK.
#[derive(Clone, Debug, Default)]
pub struct Cache {
    /// Accepted Listener resources.
    pub listeners: BTreeMap<String, Listener>,
    /// Accepted RouteConfiguration resources.
    pub routes: BTreeMap<String, RouteConfiguration>,
    /// Accepted Cluster resources.
    pub clusters: BTreeMap<String, Cluster>,
    /// Accepted ClusterLoadAssignment resources.
    pub endpoints: BTreeMap<String, ClusterLoadAssignment>,
}
impl Cache {
    pub(crate) fn apply(
        &mut self,
        kind: ResourceType,
        resources: &[Any],
        scope: Option<&BTreeSet<String>>,
    ) -> Result<()> {
        macro_rules! update {
            ($map:ident,$message:ty,$name:ident) => {{
                let mut updates = BTreeMap::new();
                for any in resources {
                    let resource: $message = decode(
                        any,
                        kind.type_url().trim_start_matches("type.googleapis.com/"),
                    )?;
                    require(!resource.$name.is_empty(), "empty resource name")?;
                    require(
                        updates.insert(resource.$name.clone(), resource).is_none(),
                        "duplicate resource name",
                    )?;
                }
                match scope {
                    Some(names) => self.$map.retain(|name, _| !names.contains(name)),
                    None => self.$map.clear(),
                }
                self.$map.extend(updates);
            }};
        }
        match kind {
            ResourceType::Listener => update!(listeners, Listener, name),
            ResourceType::Route => update!(routes, RouteConfiguration, name),
            ResourceType::Cluster => update!(clusters, Cluster, name),
            ResourceType::Endpoint => update!(endpoints, ClusterLoadAssignment, cluster_name),
        }
        let count =
            self.listeners.len() + self.routes.len() + self.clusters.len() + self.endpoints.len();
        let bytes = self
            .listeners
            .values()
            .map(Message::encoded_len)
            .sum::<usize>()
            + self
                .routes
                .values()
                .map(Message::encoded_len)
                .sum::<usize>()
            + self
                .clusters
                .values()
                .map(Message::encoded_len)
                .sum::<usize>()
            + self
                .endpoints
                .values()
                .map(Message::encoded_len)
                .sum::<usize>();
        if count > 4096 || bytes > 16 * 1024 * 1024 {
            return Err(invalid("resource cache limit exceeded"));
        }
        Ok(())
    }
}
