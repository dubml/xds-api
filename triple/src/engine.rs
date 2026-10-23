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

//! Workload execution and status endpoints for the Helm Triple engine template.
use crate::{Bootstrap, Controller, Handle, Result};
use rpc::{CancellationToken, Limits};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
};

/// Runs discovery and bounded status handling until shutdown, then joins all work.
pub async fn run(
    bootstrap: Bootstrap,
    listeners: Vec<String>,
    status_address: &str,
    shutdown: CancellationToken,
) -> Result<()> {
    let (controller, handle) = Controller::new(bootstrap, listeners, Limits::default())?;
    let listener = TcpListener::bind(status_address).await?;
    let discovery = controller.run(shutdown.clone());
    let status = serve_status(listener, handle, shutdown.clone());
    tokio::pin!(discovery, status);
    tokio::select! {
        result=&mut discovery=>{shutdown.cancel();status.await?;result},
        result=&mut status=>{shutdown.cancel();discovery.await?;result},
    }
}

async fn serve_status(
    listener: TcpListener,
    handle: Handle,
    shutdown: CancellationToken,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let result = loop {
        tokio::select! {biased;
            _=shutdown.cancelled()=>break Ok(()),
            _=tasks.join_next(),if !tasks.is_empty()=>{},
            accepted=listener.accept()=>match accepted {
                Ok((io,_))=>{
                    if tasks.len()<32 {
                        let handle=handle.clone();
                        tasks.spawn(async move { let _=tokio::time::timeout(Duration::from_secs(2), status_request(io,handle)).await; });
                    }
                },
                Err(error)=>break Err(error.into()),
            },
        }
    };
    tasks.shutdown().await;
    result
}

async fn status_request(mut io: TcpStream, handle: Handle) -> Result<()> {
    let mut bytes = Vec::new();
    while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
        let mut buffer = [0u8; 1024];
        let count = io.read(&mut buffer).await?;
        if count == 0 || bytes.len() + count > 8192 {
            return Ok(());
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let request = String::from_utf8_lossy(&bytes);
    let mut line = request
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace();
    let method = line.next().unwrap_or_default();
    let path = line.next().unwrap_or_default();
    let status = handle.status();
    let snapshot = handle.snapshot();
    let state = serde_json::json!({"connected":status.connected,"ready":status.ready,"listener_received":status.listener_received,"attempts":status.attempts,"generation":snapshot.generation,"last_error":status.last_error});
    let (code, content_type, body) = if method != "GET" {
        (405, "text/plain", "method not allowed\n".into())
    } else {
        match path {
            "/livez" => (200, "text/plain", "alive\n".into()),
            "/readyz" => (
                if status.connected && status.ready {
                    200
                } else {
                    503
                },
                "application/json",
                state.to_string(),
            ),
            "/status" => (200, "application/json", state.to_string()),
            "/metrics" => (
                200,
                "text/plain; version=0.0.4",
                format!(
                    "dubbo_triple_ads_connected {}\ndubbo_triple_config_ready {}\ndubbo_triple_ads_attempts_total {}\ndubbo_triple_config_generation {}\n",
                    u8::from(status.connected),
                    u8::from(status.ready),
                    status.attempts,
                    snapshot.generation
                ),
            ),
            _ => (404, "text/plain", "not found\n".into()),
        }
    };
    let reason = match code {
        200 => "OK",
        503 => "Service Unavailable",
        405 => "Method Not Allowed",
        _ => "Not Found",
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    io.write_all(response.as_bytes()).await?;
    io.shutdown().await?;
    Ok(())
}
