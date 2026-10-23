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
#[path = "echo/mod.rs"]
mod echo;
use rpc::{Limits, Metadata};
use xds_client::ResourceType;
#[tokio::test]
async fn dynamic_endpoint_update_preserves_pinned_inflight_connection_and_changes_new_calls() {
    let (first, stop_first, server_first) = echo::spawn_server(Limits::default()).await.unwrap();
    let (second, stop_second, server_second) = echo::spawn_server(Limits::default()).await.unwrap();
    let mut discovery = loaded();
    for (version, address) in [("first", &first), ("second", &second)] {
        let address: std::net::SocketAddr = address.parse().unwrap();
        discovery.process(response(
            ResourceType::Endpoint,
            version,
            vec![any(
                "endpoint.v1.ClusterLoadAssignment",
                &assignment("a", &[("127.0.0.1", address.port(), 1, 1)]),
            )],
        ));
        if version == "first" {
            let selected = discovery
                .snapshot()
                .select("listener", "test", "/test.Echo/Unary", &Metadata::new(), 0)
                .unwrap();
            let mut client = selected.connect(Limits::default()).await.unwrap();
            let call = client
                .call("/test.Echo/Unary", &Metadata::new())
                .await
                .unwrap();
            let next: std::net::SocketAddr = second.parse().unwrap();
            discovery.process(response(
                ResourceType::Endpoint,
                "during-call",
                vec![any(
                    "endpoint.v1.ClusterLoadAssignment",
                    &assignment("a", &[("127.0.0.1", next.port(), 1, 1)]),
                )],
            ));
            let mut requests = call.requests;
            requests
                .send(&echo::Echo {
                    text: "pinned old connection".into(),
                })
                .await
                .unwrap();
            requests.close().unwrap();
            let mut incoming = call.response.receive().await.unwrap();
            assert_eq!(
                incoming
                    .message::<echo::Echo>()
                    .await
                    .unwrap()
                    .unwrap()
                    .text,
                "pinned old connection"
            );
            assert!(incoming.message::<echo::Echo>().await.unwrap().is_none());
            assert_eq!(selected.address, first);
        }
    }
    let selected = discovery
        .snapshot()
        .select("listener", "test", "/test.Echo/Unary", &Metadata::new(), 0)
        .unwrap();
    assert_eq!(selected.address, second);
    let mut client = selected.connect(Limits::default()).await.unwrap();
    let result: echo::Echo = client
        .unary(
            "/test.Echo/Unary",
            &echo::Echo {
                text: "new endpoint".into(),
            },
            &Metadata::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "new endpoint");
    drop(client);
    stop_first.cancel();
    stop_second.cancel();
    server_first.await.unwrap().unwrap();
    server_second.await.unwrap().unwrap();
}
