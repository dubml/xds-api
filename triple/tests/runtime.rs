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
use rpc::{CancellationToken, Incoming, Limits, Metadata, Outgoing, RpcKind, Service};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify, task::JoinSet};
use xds_client::{
    ADS_PATH, Controller, ResourceType, proto::service::discovery::v1::DiscoveryRequest,
};

struct Ads {
    connections: AtomicUsize,
    requests: Mutex<Vec<DiscoveryRequest>>,
    reconnected: Notify,
}
impl Service for Ads {
    fn contains(&self, path: &str) -> bool {
        path == ADS_PATH
    }
    fn kind(&self, path: &str) -> Option<RpcKind> {
        self.contains(path).then_some(RpcKind::Bidirectional)
    }
    async fn call(
        &self,
        _: &str,
        incoming: &mut Incoming,
        outgoing: &mut Outgoing,
    ) -> rpc::Result<()> {
        let attempt = self.connections.fetch_add(1, Ordering::SeqCst);
        let initial = incoming.message::<DiscoveryRequest>().await?.unwrap();
        self.requests.lock().unwrap().push(initial);
        if attempt == 0 {
            let responses = [
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
                        &route("routes", &[("a", 1)]),
                    )],
                ),
                response(
                    ResourceType::Cluster,
                    "3",
                    vec![any("cluster.v1.Cluster", &cluster("a"))],
                ),
                response(
                    ResourceType::Endpoint,
                    "4",
                    vec![any(
                        "endpoint.v1.ClusterLoadAssignment",
                        &assignment("a", &[("127.0.0.1", 1001, 1, 1)]),
                    )],
                ),
            ];
            for response in responses {
                outgoing.send(&response).await?;
                loop {
                    let request = incoming.message::<DiscoveryRequest>().await?.unwrap();
                    let is_ack = request.response_nonce == response.nonce;
                    self.requests.lock().unwrap().push(request);
                    if is_ack {
                        break;
                    }
                }
            }
            Err(rpc::Status::new(rpc::Code::Unavailable, "restart control plane").into())
        } else {
            for _ in 0..3 {
                let request = incoming.message::<DiscoveryRequest>().await?.unwrap();
                self.requests.lock().unwrap().push(request);
            }
            self.reconnected.notify_one();
            std::future::pending::<rpc::Result<()>>().await
        }
    }
}
#[tokio::test]
async fn network_reconnect_replays_node_names_and_versions_without_old_nonce_and_cancels_tasks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let service = Arc::new(Ads {
        connections: AtomicUsize::new(0),
        requests: Mutex::new(Vec::new()),
        reconnected: Notify::new(),
    });
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server_service = service.clone();
    let server = tokio::spawn(async move {
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {_=server_stop.cancelled()=>break,accepted=listener.accept()=>{let(io,_)=accepted.unwrap();tasks.spawn(rpc::serve_connection(io,server_service.clone(),Limits::default(),server_stop.clone(),Duration::from_millis(100)));},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
        while tasks.join_next().await.is_some() {}
    });
    let (controller, handle) = Controller::new(
        bootstrap(&address.to_string()),
        ["listener".into()],
        Limits::default(),
    )
    .unwrap();
    let shutdown = CancellationToken::new();
    let controller_stop = shutdown.clone();
    let controller = tokio::spawn(controller.run(controller_stop));
    tokio::time::timeout(Duration::from_secs(5), service.reconnected.notified())
        .await
        .unwrap();
    assert!(handle.status().ready);
    assert!(handle.status().attempts >= 2);
    assert_eq!(
        handle
            .snapshot()
            .select("listener", "test", "/Echo", &Metadata::new(), 0)
            .unwrap()
            .address,
        "127.0.0.1:1001"
    );
    let replay: Vec<_> = service
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.node.is_some() && !r.version_info.is_empty())
        .cloned()
        .collect();
    assert_eq!(replay.len(), 4);
    assert!(
        replay
            .iter()
            .all(|r| r.response_nonce.is_empty() && !r.resource_names.is_empty())
    );
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(1), controller)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!handle.status().connected);
    assert!(handle.snapshot().ready);
    stop.cancel();
    server.await.unwrap();
}
#[tokio::test]
async fn cancelled_initial_connect_and_backoff_cannot_become_ready() {
    let (controller, handle) = Controller::new(
        bootstrap("127.0.0.1:1"),
        ["listener".into()],
        Limits::default(),
    )
    .unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(controller.run(stop.clone()));
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(!handle.status().ready);
    assert!(!handle.status().listener_received);
    stop.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
