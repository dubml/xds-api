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

//! Authenticated ADS acceptance probe; this is a test fixture, not the injection agent.
use rpc::{CancellationToken, Limits};
use std::time::Duration;
use xds_client::{Bootstrap, Controller};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [path, listener, expect] = args.as_slice() else {
        return Err(
            "usage: probe bootstrap.json listener ready|reconnect|rotate|denied|invalid".into(),
        );
    };
    let bootstrap = match Bootstrap::from_file(path) {
        Ok(bootstrap) => bootstrap,
        Err(error) if expect == "invalid" => {
            println!("PASS rejected invalid bootstrap: {error}");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    if expect == "invalid" {
        return Err("invalid bootstrap was accepted".into());
    }
    let (controller, mut handle) =
        Controller::new(bootstrap, [listener.clone()], Limits::default())?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(controller.run(shutdown.clone()));
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        let mut initial_generation = None;
        let mut rejected_generation = false;
        loop {
            let status = handle.status();
            if expect == "ready" && status.connected && status.listener_received && status.ready {
                return Ok::<_, Box<dyn std::error::Error>>(());
            }
            if matches!(expect.as_str(), "reconnect" | "rotate")
                && status.connected
                && status.listener_received
                && status.ready
            {
                let generation = handle.snapshot().generation;
                if let Some(initial) = initial_generation {
                    if status.attempts > 1
                        && generation > initial
                        && (expect != "rotate" || rejected_generation)
                    {
                        return Ok(());
                    }
                    if expect == "rotate"
                        && !rejected_generation
                        && status
                            .last_error
                            .as_deref()
                            .is_some_and(|error| error.starts_with("certificate reload:"))
                    {
                        if generation != initial || status.attempts != 1 {
                            return Err(
                                "incomplete certificate generation replaced the valid connection"
                                    .into(),
                            );
                        }
                        rejected_generation = true;
                        println!("RELOAD rejected incomplete generation");
                    }
                } else {
                    initial_generation = Some(generation);
                    println!("READY first ADS connection");
                }
            }
            if expect == "denied" && status.last_error.is_some() {
                if status.listener_received || status.ready {
                    return Err("failed identity became ready".into());
                }
                return Ok(());
            }
            handle.status_changed().await?;
        }
    })
    .await;
    if result.is_err() {
        eprintln!("ADS acceptance timeout: {:?}", handle.status());
    }
    shutdown.cancel();
    task.await??;
    result??;
    println!("PASS Rust Triple -> dubbod ADS: {expect}");
    Ok(())
}
