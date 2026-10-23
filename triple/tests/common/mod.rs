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

#![allow(missing_docs, dead_code, clippy::unwrap_used, clippy::expect_used)]
use prost::Message;
use prost_types::Any;
use xds_client::{
    Bootstrap, Discovery, ResourceType,
    proto::{
        cluster::v1::{Cluster, cluster},
        core::v1 as core,
        endpoint::v1 as endpoint,
        extensions::filters::network::http_connection_manager::v1::{
            HttpConnectionManager, Rds, http_connection_manager,
        },
        listener::v1::{ApiListener, Listener},
        route::v1 as route,
        service::discovery::v1::DiscoveryResponse,
    },
};
pub fn bootstrap(address: &str) -> Bootstrap {
    Bootstrap::from_json(serde_json::json!({"xds_servers":[{"server_uri":address,"channel_creds":[{"type":"insecure"}]}],"node":{"id":"inherent~10.0.0.1~pod-1~app.svc.cluster.local","metadata":{"GENERATOR":"grpc","NAMESPACE":"app","nested":{"a":[true,null,1]}}}}).to_string().as_bytes()).unwrap()
}
pub fn any<M: Message>(name: &str, message: &M) -> Any {
    Any {
        type_url: format!("type.googleapis.com/{name}"),
        value: message.encode_to_vec(),
    }
}
pub fn listener(name: &str, route: &str) -> Listener {
    let hcm = HttpConnectionManager {
        route_specifier: Some(http_connection_manager::RouteSpecifier::Rds(Rds {
            route_config_name: route.into(),
            ..Rds::default()
        })),
        ..HttpConnectionManager::default()
    };
    Listener {
        name: name.into(),
        api_listener: Some(ApiListener {
            api_listener: Some(any(
                "extensions.filters.network.http_connection_manager.v1.HttpConnectionManager",
                &hcm,
            )),
        }),
        ..Listener::default()
    }
}
pub fn route(name: &str, weights: &[(&str, u32)]) -> route::RouteConfiguration {
    let weighted = route::WeightedCluster {
        clusters: weights
            .iter()
            .map(|(name, weight)| route::weighted_cluster::ClusterWeight {
                name: (*name).into(),
                weight: Some(*weight),
                ..Default::default()
            })
            .collect(),
        total_weight: Some(weights.iter().map(|v| v.1).sum()),
    };
    let action = route::RouteAction {
        cluster_specifier: Some(route::route_action::ClusterSpecifier::WeightedClusters(
            weighted,
        )),
        ..Default::default()
    };
    route::RouteConfiguration {
        name: name.into(),
        virtual_hosts: vec![route::VirtualHost {
            name: "host".into(),
            domains: vec!["*".into()],
            routes: vec![route::Route {
                name: "echo".into(),
                r#match: Some(route::RouteMatch {
                    path_specifier: Some(route::route_match::PathSpecifier::Prefix("/".into())),
                    ..Default::default()
                }),
                action: Some(route::route::Action::Route(action)),
            }],
        }],
        ..Default::default()
    }
}
pub fn cluster(name: &str) -> Cluster {
    Cluster {
        name: name.into(),
        cluster_discovery_type: Some(cluster::ClusterDiscoveryType::Type(3)),
        eds_cluster_config: Some(cluster::EdsClusterConfig {
            service_name: name.into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}
pub fn assignment(
    name: &str,
    addresses: &[(&str, u16, i32, u32)],
) -> endpoint::ClusterLoadAssignment {
    endpoint::ClusterLoadAssignment {
        cluster_name: name.into(),
        endpoints: vec![endpoint::LocalityLbEndpoints {
            lb_endpoints: addresses
                .iter()
                .map(|(host, port, health, weight)| endpoint::LbEndpoint {
                    health_status: *health,
                    load_balancing_weight: Some(*weight),
                    host_identifier: Some(endpoint::lb_endpoint::HostIdentifier::Endpoint(
                        endpoint::Endpoint {
                            address: Some(core::Address {
                                address: Some(core::address::Address::SocketAddress(
                                    core::SocketAddress {
                                        address: (*host).into(),
                                        port_specifier: Some(
                                            core::socket_address::PortSpecifier::PortValue(
                                                u32::from(*port),
                                            ),
                                        ),
                                    },
                                )),
                            }),
                        },
                    )),
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }],
    }
}
pub fn response(kind: ResourceType, version: &str, resources: Vec<Any>) -> DiscoveryResponse {
    DiscoveryResponse {
        type_url: kind.type_url().into(),
        version_info: version.into(),
        nonce: format!("nonce-{version}"),
        resources,
        ..Default::default()
    }
}
pub fn loaded() -> Discovery {
    let mut discovery = Discovery::new(bootstrap("127.0.0.1:1"), ["listener".into()]).unwrap();
    for response in [
        response(
            ResourceType::Listener,
            "1",
            vec![any("listener.v1.Listener", &listener("listener", "routes"))],
        ),
        response(
            ResourceType::Route,
            "2",
            vec![any(
                "route.v1.RouteConfiguration",
                &route("routes", &[("a", 1), ("b", 3)]),
            )],
        ),
        response(
            ResourceType::Cluster,
            "3",
            vec![
                any("cluster.v1.Cluster", &cluster("a")),
                any("cluster.v1.Cluster", &cluster("b")),
            ],
        ),
        response(
            ResourceType::Endpoint,
            "4",
            vec![
                any(
                    "endpoint.v1.ClusterLoadAssignment",
                    &assignment("a", &[("127.0.0.1", 1001, 1, 1)]),
                ),
                any(
                    "endpoint.v1.ClusterLoadAssignment",
                    &assignment("b", &[("127.0.0.1", 1002, 1, 1)]),
                ),
            ],
        ),
    ] {
        assert!(discovery.process(response)[0].error_detail.is_none());
    }
    assert!(discovery.snapshot().ready);
    discovery
}
