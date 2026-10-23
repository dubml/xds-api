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

//! Rust Triple xDS entry point embedded in dubbod and started by the triple-engine template.
use rpc::CancellationToken;
use xds_client::Bootstrap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut listeners = std::env::var("DUBBO_TRIPLE_LISTENERS")
        .unwrap_or_default()
        .split(',')
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let mut status =
        std::env::var("DUBBO_TRIPLE_STATUS_ADDRESS").unwrap_or_else(|_| "0.0.0.0:9090".into());
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--watch" => {}
            "--listener" => listeners.push(arguments.next().ok_or("--listener requires a name")?),
            "--status-address" => {
                status = arguments
                    .next()
                    .ok_or("--status-address requires an address")?
            }
            "--help" => {
                println!(
                    "triple-engine [--watch] [--listener NAME] [--status-address ADDRESS]\nReads TRIPLE_XDS_BOOTSTRAP; runs ADS and /livez, /readyz, /status, /metrics."
                );
                return Ok(());
            }
            _ => return Err(format!("unknown argument {argument}").into()),
        }
    }
    let bootstrap = Bootstrap::from_env()?;
    let shutdown = CancellationToken::new();
    let operation = xds_client::engine::run(bootstrap, listeners, &status, shutdown.clone());
    tokio::pin!(operation);
    tokio::select! {
        result=&mut operation=>result?,
        result=termination()=>{result?;shutdown.cancel();operation.await?;},
    }
    Ok(())
}

async fn termination() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! { result=tokio::signal::ctrl_c()=>result,_=terminate.recv()=>Ok(()) }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
}
