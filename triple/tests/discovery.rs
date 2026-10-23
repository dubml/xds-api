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

#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]
mod common;
use common::*;
use rpc::{CallOptions, Deadline, Metadata};
use std::{sync::Arc, time::Duration};
use xds_client::{Bootstrap, Discovery, Error, ResourceType, proto::route::v1 as route};

#[test]
fn bootstrap_preserves_node_metadata_and_rejects_malformed_configuration() {
    let bootstrap = bootstrap("dns:///dubbod.test:15012");
    assert_eq!(
        bootstrap.node.id,
        "inherent~10.0.0.1~pod-1~app.svc.cluster.local"
    );
    assert_eq!(
        bootstrap.node.metadata.unwrap().fields["GENERATOR"].kind,
        Some(prost_types::value::Kind::StringValue("grpc".into()))
    );
    for raw in [
        "{}",
        r#"{"xds_servers":[],"node":{"id":"x"}}"#,
        r#"{"xds_servers":[{"server_uri":"x:1","channel_creds":[{"type":"tls"}]}],"node":{"id":"x"}}"#,
        r#"{"xds_servers":[{"server_uri":"x:1","channel_creds":[{"type":"insecure"}]}],"node":{"id":"x","metadata":"bad"}}"#,
    ] {
        assert!(Bootstrap::from_json(raw.as_bytes()).is_err());
    }
    let mut raw = serde_json::json!({"xds_servers":[{"server_uri":"dubbod.test:15012","server_features":["xds_v3"],"channel_creds":[{"type":"tls","config":{"certificate_file":"cert.pem","private_key_file":"key.pem","ca_certificate_file":"root.pem","refresh_interval":"900s"}}]}],"node":{"id":"x"},"certificate_providers":{"default":{"plugin_name":"file_watcher","config":{"certificate_file":"cert.pem","private_key_file":"key.pem","ca_certificate_file":"root.pem","refresh_interval":"900s"}}}});
    let parsed = Bootstrap::from_json(raw.to_string().as_bytes()).unwrap();
    assert_eq!(
        parsed.certificate_providers["default"]
            .refresh_interval
            .as_deref(),
        Some("900s")
    );
    raw["certificate_providers"]["default"]["config"]["refresh_interval"] =
        serde_json::json!("-1s");
    assert!(Bootstrap::from_json(raw.to_string().as_bytes()).is_err());
}
#[test]
fn dependency_subscriptions_and_reconnect_replay_preserve_versions_without_nonces() {
    let mut state = Discovery::new(bootstrap("127.0.0.1:1"), ["listener".into()]).unwrap();
    let initial = state.reconnect_requests();
    assert_eq!(initial.len(), 1);
    assert!(initial[0].node.is_some());
    assert!(initial[0].response_nonce.is_empty());
    let requests = state.process(response(
        ResourceType::Listener,
        "1",
        vec![any("listener.v1.Listener", &listener("listener", "routes"))],
    ));
    assert_eq!(requests[1].type_url, ResourceType::Route.type_url());
    assert_eq!(requests[1].resource_names, ["routes"]);
    // A real dubbod can push CDS before the client's RDS/CDS subscription.
    state.process(response(
        ResourceType::Cluster,
        "2",
        vec![any("cluster.v1.Cluster", &cluster("a"))],
    ));
    let requests = state.process(response(
        ResourceType::Route,
        "3",
        vec![any(
            "route.v1.RouteConfiguration",
            &route("routes", &[("a", 1)]),
        )],
    ));
    assert!(
        requests
            .iter()
            .any(|r| r.type_url == ResourceType::Cluster.type_url() && r.resource_names == ["a"])
    );
    assert!(
        requests
            .iter()
            .any(|r| r.type_url == ResourceType::Endpoint.type_url() && r.resource_names == ["a"])
    );
    let replay = state.reconnect_requests();
    assert_eq!(replay.len(), 4);
    assert!(
        replay
            .iter()
            .all(|r| r.node.is_some() && r.response_nonce.is_empty())
    );
    assert_eq!(state.subscription(ResourceType::Listener).version, "1");
    assert_eq!(state.subscription(ResourceType::Cluster).version, "2");
}
#[test]
fn mixed_bad_resource_nacks_transaction_and_preserves_snapshot() {
    let mut state = loaded();
    let snapshot = state.snapshot();
    let good = any("cluster.v1.Cluster", &cluster("a"));
    let mut bad = cluster("b");
    bad.lb_policy = 99;
    let requests = state.process(response(
        ResourceType::Cluster,
        "bad",
        vec![good, any("cluster.v1.Cluster", &bad)],
    ));
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].version_info, "3");
    assert_eq!(requests[0].response_nonce, "nonce-bad");
    assert_eq!(requests[0].error_detail.as_ref().unwrap().code, 3);
    assert!(Arc::ptr_eq(&snapshot, &state.snapshot()));
    assert_eq!(state.cache().clusters["b"].lb_policy, 0);
}
#[test]
fn duplicate_response_does_not_republish_and_reused_nonce_nacks() {
    let mut state = loaded();
    let r = response(
        ResourceType::Endpoint,
        "repeat",
        vec![any(
            "endpoint.v1.ClusterLoadAssignment",
            &assignment("a", &[("127.0.0.1", 1003, 1, 1)]),
        )],
    );
    assert!(state.process(r.clone())[0].error_detail.is_none());
    let generation = state.snapshot().generation;
    assert!(state.process(r.clone())[0].error_detail.is_none());
    assert_eq!(state.snapshot().generation, generation);
    let mut changed = r;
    changed.resources.clear();
    assert!(state.process(changed)[0].error_detail.is_some());
    assert_eq!(state.snapshot().generation, generation);
}
#[test]
fn unknown_type_mismatched_any_and_duplicate_names_nack() {
    let mut state = loaded();
    let old = state.snapshot();
    let mut unknown = response(ResourceType::Listener, "unknown", vec![]);
    unknown.type_url = "type.googleapis.com/unknown.Type".into();
    assert!(state.process(unknown)[0].error_detail.is_some());
    let wrong = any("cluster.v1.Cluster", &cluster("a"));
    assert!(
        state.process(response(ResourceType::Listener, "wrong", vec![wrong]))[0]
            .error_detail
            .is_some()
    );
    let item = any("listener.v1.Listener", &listener("listener", "routes"));
    assert!(
        state.process(response(
            ResourceType::Listener,
            "dupe",
            vec![item.clone(), item]
        ))[0]
            .error_detail
            .is_some()
    );
    assert!(Arc::ptr_eq(&old, &state.snapshot()));
}
#[test]
fn targeted_eds_merge_preserves_other_clusters_and_empty_assignment_revokes_only_its_target() {
    let mut state = loaded();
    let update = assignment("a", &[("127.0.0.1", 1003, 1, 1)]);
    state.process(response(
        ResourceType::Endpoint,
        "new",
        vec![any("endpoint.v1.ClusterLoadAssignment", &update)],
    ));
    assert_eq!(
        state
            .snapshot()
            .select("listener", "example", "/Echo", &Metadata::new(), 0)
            .unwrap()
            .address,
        "127.0.0.1:1003"
    );
    assert_eq!(
        state
            .snapshot()
            .select("listener", "example", "/Echo", &Metadata::new(), 1)
            .unwrap()
            .address,
        "127.0.0.1:1002"
    );
    state.process(response(
        ResourceType::Endpoint,
        "empty",
        vec![any(
            "endpoint.v1.ClusterLoadAssignment",
            &assignment("a", &[]),
        )],
    ));
    assert!(matches!(
        state
            .snapshot()
            .select("listener", "example", "/Echo", &Metadata::new(), 0),
        Err(Error::NoEndpoint(_))
    ));
    assert!(
        state
            .snapshot()
            .select("listener", "example", "/Echo", &Metadata::new(), 1)
            .is_ok()
    );
}
#[test]
fn listener_deletion_revokes_new_calls_but_pinned_snapshot_survives_and_resubscribe_waits() {
    let mut state = loaded();
    let previous = state.snapshot();
    state.process(response(ResourceType::Listener, "deleted", vec![]));
    assert!(!state.snapshot().ready);
    assert!(
        state
            .snapshot()
            .select("listener", "x", "/Echo", &Metadata::new(), 0)
            .is_err()
    );
    assert!(
        previous
            .select("listener", "x", "/Echo", &Metadata::new(), 0)
            .is_ok()
    );
    assert!(state.cache().routes.is_empty());
    assert!(state.cache().clusters.is_empty());
    assert!(state.cache().endpoints.is_empty());
    state.process(response(
        ResourceType::Listener,
        "recreated",
        vec![any("listener.v1.Listener", &listener("listener", "routes"))],
    ));
    assert!(!state.snapshot().ready);
}
#[test]
fn cds_and_rds_scoped_deletions_do_not_keep_a_withdrawn_route_callable() {
    let mut state = loaded();
    state.process(response(
        ResourceType::Cluster,
        "deleted",
        vec![any("cluster.v1.Cluster", &cluster("a"))],
    ));
    assert!(matches!(
        state
            .snapshot()
            .select("listener", "x", "/Echo", &Metadata::new(), 1),
        Err(Error::Unavailable(_))
    ));
    assert!(
        state
            .snapshot()
            .select("listener", "x", "/Echo", &Metadata::new(), 0)
            .is_ok()
    );
    state.process(response(ResourceType::Route, "deleted-rds", vec![]));
    assert!(
        state
            .snapshot()
            .select("listener", "x", "/Echo", &Metadata::new(), 0)
            .is_err()
    );
}
#[test]
fn weighted_cluster_picks_and_header_path_domain_updates_are_deterministic() {
    let mut state = loaded();
    let mut counts = [0; 2];
    for ticket in 0..400 {
        let picked = state
            .snapshot()
            .select("listener", "example", "/Echo", &Metadata::new(), ticket)
            .unwrap();
        counts[usize::from(picked.cluster == "b")] += 1;
    }
    assert_eq!(counts, [100, 300]);
    let mut route = route("routes", &[("b", 1)]);
    route.virtual_hosts[0].domains = vec!["*.example.test".into()];
    let matcher = route.virtual_hosts[0].routes[0].r#match.as_mut().unwrap();
    matcher.path_specifier = Some(route::route_match::PathSpecifier::Path("/Echo/Call".into()));
    matcher.headers.push(route::HeaderMatcher {
        name: "tenant".into(),
        header_match_specifier: Some(route::header_matcher::HeaderMatchSpecifier::ExactMatch(
            "blue".into(),
        )),
    });
    state.process(response(
        ResourceType::Route,
        "changed",
        vec![any("route.v1.RouteConfiguration", &route)],
    ));
    let mut metadata = Metadata::new();
    metadata.append_ascii("tenant", "blue").unwrap();
    assert_eq!(
        state
            .snapshot()
            .select("listener", "api.example.test", "/Echo/Call", &metadata, 0)
            .unwrap()
            .cluster,
        "b"
    );
    for (host, path) in [
        ("example.test", "/Echo/Call"),
        ("api.example.test", "/Echo/Other"),
    ] {
        assert!(
            state
                .snapshot()
                .select("listener", host, path, &metadata, 0)
                .is_err()
        );
    }
    assert!(
        state
            .snapshot()
            .select(
                "listener",
                "api.example.test",
                "/Echo/Call",
                &Metadata::new(),
                0
            )
            .is_err()
    );
}
#[test]
fn unhealthy_endpoints_are_excluded_and_lowest_healthy_priority_is_used() {
    let mut state = loaded();
    let mut value = assignment(
        "a",
        &[
            ("127.0.0.1", 1003, 2, 100),
            ("127.0.0.1", 1004, 1, 1),
            ("127.0.0.1", 1005, 0, 3),
        ],
    );
    let mut fallback = value.endpoints[0].clone();
    fallback.priority = 1;
    fallback.lb_endpoints = assignment("fallback", &[("127.0.0.1", 1006, 1, 1)])
        .endpoints
        .remove(0)
        .lb_endpoints;
    value.endpoints.push(fallback);
    state.process(response(
        ResourceType::Endpoint,
        "health",
        vec![any("endpoint.v1.ClusterLoadAssignment", &value)],
    ));
    let mut counts = [0; 2];
    for ticket in (0..160).step_by(4) {
        let address = state
            .snapshot()
            .select("listener", "x", "/Echo", &Metadata::new(), ticket)
            .unwrap()
            .address;
        counts[usize::from(address.ends_with("1005"))] += 1;
        assert!(address.ends_with("1004") || address.ends_with("1005"));
    }
    assert_eq!(counts, [10, 30]);
}
#[test]
fn unsupported_regex_retry_and_tls_provider_nack_without_replacing_valid_configuration() {
    let mut state = loaded();
    let old = state.snapshot();
    let mut bad = route("routes", &[("a", 1)]);
    bad.virtual_hosts[0].routes[0]
        .r#match
        .as_mut()
        .unwrap()
        .path_specifier = Some(route::route_match::PathSpecifier::SafeRegex(
        Default::default(),
    ));
    assert!(
        state.process(response(
            ResourceType::Route,
            "regex",
            vec![any("route.v1.RouteConfiguration", &bad)]
        ))[0]
            .error_detail
            .is_some()
    );
    let mut bad = route("routes", &[("a", 1)]);
    if let Some(route::route::Action::Route(action)) = &mut bad.virtual_hosts[0].routes[0].action {
        action.retry_policy = Some(Default::default());
    }
    assert!(
        state.process(response(
            ResourceType::Route,
            "retry",
            vec![any("route.v1.RouteConfiguration", &bad)]
        ))[0]
            .error_detail
            .is_some()
    );
    let mut bad = cluster("a");
    bad.transport_socket = Some(xds_client::proto::core::v1::TransportSocket {
        name: "transport_sockets.tls".into(),
        config_type: Some(
            xds_client::proto::core::v1::transport_socket::ConfigType::TypedConfig(any(
                "extensions.transport_sockets.tls.v1.UpstreamTlsContext",
                &xds_client::proto::extensions::transport_sockets::tls::v1::UpstreamTlsContext {
                    common_tls_context: Some(Default::default()),
                    sni: "echo.test".into(),
                },
            )),
        ),
    });
    assert!(
        state.process(response(
            ResourceType::Cluster,
            "provider",
            vec![any("cluster.v1.Cluster", &bad)]
        ))[0]
            .error_detail
            .is_some()
    );
    assert!(Arc::ptr_eq(&old, &state.snapshot()));
}
#[test]
fn route_timeout_never_extends_an_explicit_caller_deadline() {
    let mut state = loaded();
    let mut route = route("routes", &[("a", 1)]);
    if let Some(route::route::Action::Route(action)) = &mut route.virtual_hosts[0].routes[0].action
    {
        action.timeout = Some(prost_types::Duration {
            seconds: 1,
            nanos: 0,
        });
    }
    state.process(response(
        ResourceType::Route,
        "timeout",
        vec![any("route.v1.RouteConfiguration", &route)],
    ));
    let selected = state
        .snapshot()
        .select("listener", "x", "/Echo", &Metadata::new(), 0)
        .unwrap();
    let short = Deadline::after(Duration::from_millis(10)).unwrap();
    let options = CallOptions {
        deadline: Some(short),
        ..Default::default()
    };
    assert_eq!(
        selected.call_options(&options).unwrap().deadline,
        Some(short)
    );
    let long = Deadline::after(Duration::from_secs(30)).unwrap();
    let options = CallOptions {
        deadline: Some(long),
        ..Default::default()
    };
    assert!(selected.call_options(&options).unwrap().deadline.unwrap() < long);
}
