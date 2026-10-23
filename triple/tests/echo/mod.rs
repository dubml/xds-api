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

#![allow(missing_docs, dead_code)]
use rpc::{
    CancellationToken, Code, Error, Incoming, Limits, Metadata, Outgoing, Result, RpcKind, Service,
    Status, serve_connection,
};
use std::{sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    task::{JoinHandle, JoinSet},
};
#[derive(Clone, PartialEq, prost::Message)]
pub struct Echo {
    #[prost(string, tag = "1")]
    pub text: String,
}
pub struct EchoService;
impl Service for EchoService {
    fn contains(&self, path: &str) -> bool {
        self.kind(path).is_some()
    }
    fn kind(&self, path: &str) -> Option<RpcKind> {
        Some(match method(path) {
            "Unary" | "Fail" | "Slow" => RpcKind::Unary,
            "ServerStreaming" | "EmptyServerStream" => RpcKind::ServerStreaming,
            "ClientStreaming" | "EmptyClientResponse" | "ExtraClientResponse" => {
                RpcKind::ClientStreaming
            }
            "Bidirectional" | "StreamFail" => RpcKind::Bidirectional,
            _ => return None,
        })
    }

    fn response_metadata(&self, _path: &str, request: &Metadata) -> Result<Metadata> {
        let mut response = Metadata::new();
        for value in request.ascii_values("echo-key") {
            response.append_ascii("echo-key", value)?;
        }
        for value in request.binary_values("echo-bin")? {
            response.append_binary("echo-bin", &value)?;
        }
        Ok(response)
    }

    async fn call(
        &self,
        path: &str,
        request: &mut Incoming,
        response: &mut Outgoing,
    ) -> Result<()> {
        match method(path) {
            "Slow" => {
                tokio::time::sleep(Duration::from_secs(60)).await;
                Ok(())
            }
            "Fail" => Err(Status::new(Code::PermissionDenied, "denied: 测试 %")
                .with_details(&[8, 7])?
                .into()),
            "StreamFail" => {
                let message = request
                    .message::<Echo>()
                    .await?
                    .ok_or(Error::Cardinality("request"))?;
                response.send(&message).await?;
                response
                    .trailers_mut()
                    .append_ascii("failure-key", "last")?;
                Err(Status::new(Code::PermissionDenied, "stream failed").into())
            }
            "Unary" => {
                let message = request
                    .message::<Echo>()
                    .await?
                    .ok_or(Error::Cardinality("request"))?;
                response.send(&message).await
            }
            "EmptyServerStream" => {
                request
                    .message::<Echo>()
                    .await?
                    .ok_or(Error::Cardinality("request"))?;
                Ok(())
            }
            "EmptyClientResponse" | "ExtraClientResponse" => {
                while request.message::<Echo>().await?.is_some() {}
                if path.ends_with("ExtraClientResponse") {
                    response
                        .send(&Echo {
                            text: "first".into(),
                        })
                        .await?;
                    response
                        .send(&Echo {
                            text: "extra".into(),
                        })
                        .await?;
                }
                Ok(())
            }
            "ServerStreaming" => {
                let message = request
                    .message::<Echo>()
                    .await?
                    .ok_or(Error::Cardinality("request"))?;
                for suffix in ["0", "1", "2"] {
                    response
                        .send(&Echo {
                            text: format!("{}:{suffix}", message.text),
                        })
                        .await?;
                }
                Ok(())
            }
            "ClientStreaming" => {
                let mut text = String::new();
                while let Some(message) = request.message::<Echo>().await? {
                    text.push_str(&message.text);
                }
                response.send(&Echo { text }).await
            }
            "Bidirectional" => {
                while let Some(message) = request.message::<Echo>().await? {
                    response.send(&message).await?;
                }
                Ok(())
            }
            _ => Err(Status::new(Code::Unimplemented, "unknown method").into()),
        }
    }
}

pub async fn spawn_server(
    limits: Limits,
) -> Result<(String, CancellationToken, JoinHandle<Result<()>>)> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(transport::Error::from)?;
    let address = listener
        .local_addr()
        .map_err(transport::Error::from)?
        .to_string();
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let handle = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = stop.cancelled() => break,
                accepted = listener.accept() => {
                    let (io, _) = accepted.map_err(transport::Error::from)?;
                    connections.spawn(serve_connection(io, Arc::new(EchoService), limits, stop.clone(), Duration::from_secs(1)));
                }
            }
        }
        while let Some(result) = connections.join_next().await {
            match result.map_err(|_| Error::InvalidHeader("test server task"))? {
                Ok(()) => {}
                // A peer dropping its TCP connection may produce ECONNRESET.
                Err(Error::Transport(transport::Error::Transport(error))) if error.is_io() => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    });
    Ok((address, shutdown, handle))
}

fn method(path: &str) -> &str {
    path.strip_prefix("/test.Echo/")
        .or_else(|| path.strip_prefix("/org.apache.dubbo.triple.fixture.Echo/"))
        .unwrap_or("")
}
