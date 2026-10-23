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

//! Bounded independent ADS send/receive loops and cancellable reconnect backoff.
use crate::{
    ADS_PATH, Bootstrap, Discovery, Error, Result, Snapshot,
    proto::service::discovery::v1::{DiscoveryRequest, DiscoveryResponse},
};
use rpc::{CallOptions, CancellationToken, Limits, RpcKind};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

/// Observable connection and configuration state without certificate material.
#[derive(Clone, Debug, Default)]
pub struct Status {
    /// ADS response headers have arrived on the current stream.
    pub connected: bool,
    /// A validated LDS response has arrived.
    pub listener_received: bool,
    /// A usable graph has all its required dependencies.
    pub ready: bool,
    /// Number of connection attempts.
    pub attempts: u64,
    /// Latest transport, authentication or validation error.
    pub last_error: Option<String>,
}
/// Read-only handle to the current configuration and ADS status.
#[derive(Clone)]
pub struct Handle {
    snapshot: watch::Receiver<Arc<Snapshot>>,
    status: watch::Receiver<Status>,
}
impl Handle {
    /// Pins the current immutable snapshot for a call.
    pub fn snapshot(&self) -> Arc<Snapshot> {
        self.snapshot.borrow().clone()
    }
    /// Reads current status; connectivity and configuration readiness are independent.
    pub fn status(&self) -> Status {
        self.status.borrow().clone()
    }
    /// Waits for configuration publication, or an error if the controller was dropped.
    pub async fn changed(&mut self) -> Result<()> {
        self.snapshot
            .changed()
            .await
            .map_err(|_| Error::Unavailable("discovery controller stopped".into()))
    }
    /// Waits for a connection or readiness status change.
    pub async fn status_changed(&mut self) -> Result<()> {
        self.status
            .changed()
            .await
            .map_err(|_| Error::Unavailable("discovery controller stopped".into()))
    }
}
/// Owns discovery; its run future polls both ADS directions without detached tasks.
pub struct Controller {
    bootstrap: Bootstrap,
    discovery: Discovery,
    snapshots: watch::Sender<Arc<Snapshot>>,
    statuses: watch::Sender<Status>,
    limits: Limits,
}
impl Controller {
    /// Constructs a controller without starting background tasks.
    pub fn new(
        mut bootstrap: Bootstrap,
        listeners: impl IntoIterator<Item = String>,
        limits: Limits,
    ) -> Result<(Self, Handle)> {
        bootstrap.reload_certificates()?;
        let discovery = Discovery::new(bootstrap.clone(), listeners)?;
        let (snapshots, snapshot) = watch::channel(discovery.snapshot());
        let (statuses, status) = watch::channel(Status::default());
        Ok((
            Self {
                bootstrap,
                discovery,
                snapshots,
                statuses,
                limits,
            },
            Handle { snapshot, status },
        ))
    }
    /// Runs until cancelled, retaining the accepted snapshot across control-plane failures.
    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        let mut failures = 0u32;
        loop {
            if shutdown.is_cancelled() {
                break;
            }
            self.statuses.send_modify(|status| status.attempts += 1);
            self.reload_if_changed();
            let initial_generation = self.discovery.snapshot().generation;
            let outcome = self.session(&shutdown).await;
            if shutdown.is_cancelled() {
                break;
            }
            if matches!(outcome, Ok(true)) {
                self.statuses.send_modify(|status| status.connected = false);
                continue;
            }
            if self.discovery.snapshot().generation != initial_generation {
                failures = 0;
            }
            self.statuses.send_modify(|status| {
                status.connected = false;
                status.last_error = Some(
                    outcome
                        .err()
                        .map_or_else(|| "ADS stream ended".into(), |error| error.to_string()),
                );
            });
            let delay = backoff(failures, fastrand::u64(..));
            failures = failures.saturating_add(1);
            tokio::select! {biased;_ = shutdown.cancelled()=>break,_=tokio::time::sleep(delay)=>{}}
        }
        self.statuses.send_modify(|status| status.connected = false);
        Ok(())
    }
    fn reload_if_changed(&mut self) {
        let mut candidate = self.bootstrap.clone();
        match candidate.reload_certificates().and_then(|changed| {
            if changed {
                self.discovery.replace_bootstrap(candidate.clone())?;
            }
            Ok(changed)
        }) {
            Ok(true) => {
                self.bootstrap = candidate;
                self.snapshots.send_replace(self.discovery.snapshot());
            }
            Ok(false) => {}
            Err(error) => self.statuses.send_modify(|status| {
                status.last_error = Some(format!("certificate reload: {error}"))
            }),
        }
    }
    async fn session(&mut self, shutdown: &CancellationToken) -> Result<bool> {
        let cancellation = shutdown.child_token();
        let mut client = tokio::select! {biased;_=cancellation.cancelled()=>return Ok(false),client=tokio::time::timeout(Duration::from_secs(10),self.bootstrap.connect(self.limits))=>client.map_err(|_|Error::Unavailable("ADS connect timeout".into()))??};
        let ping = client.take_ping_pong();
        let keepalive = keepalive(ping, self.bootstrap.keepalive.clone());
        let certificates = watch_certificates(self.bootstrap.clone(), self.statuses.clone());
        let options = CallOptions {
            cancellation: cancellation.clone(),
            ..CallOptions::default()
        };
        let call = client
            .call_with_options(ADS_PATH, RpcKind::Bidirectional, &options)
            .await?;
        let (sender, mut receiver) = mpsc::channel::<DiscoveryRequest>(16);
        let writer_stop = cancellation.clone();
        let mut outgoing = call.requests;
        let writer = async move {
            loop {
                tokio::select! {biased;
                    _=writer_stop.cancelled()=>{outgoing.cancel();return Ok::<_,rpc::Error>(());},
                    request=receiver.recv()=>match request {Some(request)=>outgoing.send(&request).await?,None=>{outgoing.close()?;return Ok(());}},
                }
            }
        };
        tokio::pin!(writer);
        let operation = async {
            for request in self.discovery.reconnect_requests() {
                sender
                    .send(request)
                    .await
                    .map_err(|_| Error::Unavailable("ADS writer stopped".into()))?;
            }
            let mut incoming = call.response.receive().await?;
            self.statuses.send_modify(|status| status.connected = true);
            loop {
                let Some(response) = incoming.message::<DiscoveryResponse>().await? else {
                    return Ok(());
                };
                let requests = self.discovery.process(response);
                let error = requests
                    .first()
                    .and_then(|r| r.error_detail.as_ref())
                    .map(|e| e.message.clone());
                if error.is_none() {
                    self.snapshots.send_replace(self.discovery.snapshot());
                }
                let snapshot = self.discovery.snapshot();
                self.statuses.send_modify(|status| {
                    status.listener_received = self.discovery.listener_received();
                    status.ready = status.listener_received && snapshot.ready;
                    status.last_error = error;
                });
                for request in requests {
                    sender
                        .send(request)
                        .await
                        .map_err(|_| Error::Unavailable("ADS writer stopped".into()))?;
                }
            }
        };
        let outcome = tokio::select! {biased;
            _=cancellation.cancelled()=>Ok(None),
            result=&mut writer=>result.map(|_|None).map_err(Error::from),
            result=operation=>result.map(|_|None),
            result=keepalive=>result.map(|_|None),
            result=certificates=>result.map(Some),
        };
        cancellation.cancel();
        drop(sender);
        drop(client);
        if let Some(candidate) = outcome? {
            self.discovery.replace_bootstrap(candidate.clone())?;
            self.bootstrap = candidate;
            self.snapshots.send_replace(self.discovery.snapshot());
            self.statuses.send_modify(|status| status.last_error = None);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

async fn keepalive(
    mut ping: Option<h2::PingPong>,
    settings: crate::bootstrap::Keepalive,
) -> Result<()> {
    if !settings.enabled {
        return std::future::pending().await;
    }
    let ping = ping
        .as_mut()
        .ok_or_else(|| Error::Unavailable("HTTP/2 PING handle unavailable".into()))?;
    let interval = crate::bootstrap::parse_interval(&settings.time)?;
    let timeout = crate::bootstrap::parse_interval(&settings.timeout)?;
    loop {
        tokio::time::sleep(interval).await;
        tokio::time::timeout(timeout, ping.ping(h2::Ping::opaque()))
            .await
            .map_err(|_| Error::Unavailable("HTTP/2 PING timeout".into()))?
            .map_err(|error| Error::Unavailable(format!("HTTP/2 PING failed: {error}")))?;
    }
}

async fn watch_certificates(
    bootstrap: Bootstrap,
    statuses: watch::Sender<Status>,
) -> Result<Bootstrap> {
    let interval = bootstrap.refresh_interval()?;
    loop {
        tokio::time::sleep(interval).await;
        let mut candidate = bootstrap.clone();
        match candidate.reload_certificates() {
            Ok(true) => return Ok(candidate),
            Ok(false) => statuses.send_modify(|status| {
                if status
                    .last_error
                    .as_ref()
                    .is_some_and(|error| error.starts_with("certificate reload:"))
                {
                    status.last_error = None;
                }
            }),
            Err(error) => statuses.send_modify(|status| {
                status.last_error = Some(format!("certificate reload: {error}"))
            }),
        }
    }
}
/// Exponential reconnect delay with a hard cap and bounded jitter.
pub fn backoff(failures: u32, jitter: u64) -> Duration {
    let cap = (100u64.saturating_mul(1u64 << failures.min(6))).min(5000);
    Duration::from_millis(cap / 2 + jitter % (cap / 2 + 1))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::{backoff, keepalive};
    use crate::{Error, bootstrap::Keepalive};
    use rpc::CancellationToken;
    use std::time::Duration;

    #[test]
    fn reconnect_delay_grows_and_remains_bounded_at_counter_overflow() {
        assert_eq!(backoff(0, 0), Duration::from_millis(50));
        assert_eq!(backoff(1, 0), Duration::from_millis(100));
        assert_eq!(backoff(6, 0), Duration::from_millis(2500));
        for failures in [0, 1, 5, 6, 100, u32::MAX] {
            for jitter in [0, 50, 2500, u64::MAX] {
                let delay = backoff(failures, jitter);
                assert!((Duration::from_millis(50)..=Duration::from_millis(5000)).contains(&delay));
            }
        }
    }

    #[tokio::test]
    async fn keepalive_detects_an_unresponsive_http2_peer_and_accepts_pong() {
        for responsive in [true, false] {
            let (client, server) = tokio::io::duplex(65536);
            let stop = CancellationToken::new();
            let server_stop = stop.clone();
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                if responsive {
                    loop {
                        tokio::select! {
                            _=server_stop.cancelled()=>break,
                            stream=connection.accept()=>if stream.is_none(){break;},
                        }
                    }
                } else {
                    server_stop.cancelled().await;
                }
            });
            let (sender, mut connection) = h2::client::handshake(client).await.unwrap();
            let ping = connection.ping_pong();
            let driver = tokio::spawn(connection);
            let settings: Keepalive = serde_json::from_value(
                serde_json::json!({"enabled":true,"time":"30ms","timeout":"100ms"}),
            )
            .unwrap();
            let result =
                tokio::time::timeout(Duration::from_millis(400), keepalive(ping, settings)).await;
            if responsive {
                assert!(result.is_err(), "healthy peer must keep the stream alive");
            } else {
                assert!(
                    matches!(result, Ok(Err(Error::Unavailable(ref message))) if message.contains("PING timeout"))
                );
            }
            drop(sender);
            stop.cancel();
            server.await.unwrap();
            let _ = driver.await.unwrap();
        }
    }
}
