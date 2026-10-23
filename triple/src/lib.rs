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

//! Authenticated SotW ADS discovery and atomic native Triple routing.
/// Generated messages from the pinned xds-api contract.
#[allow(missing_docs, clippy::all)]
pub mod proto {
    include!("generated/mod.rs");
}

mod bootstrap;
mod cache;
mod discovery;
mod routing;
mod runtime;
mod snapshot;
mod tls;

pub mod engine;

pub use bootstrap::{Bootstrap, CertificateFiles};
pub use cache::{Cache, ResourceType};
pub use discovery::{Discovery, Subscription};
pub use routing::Selection;
pub use runtime::{Controller, Handle, Status};
pub use snapshot::Snapshot;

/// Existing custom ADS service path; this is not Envoy's package name.
pub const ADS_PATH: &str =
    "/service.discovery.v1.AggregatedDiscoveryService/StreamAggregatedResources";
/// Failures while validating discovery or selecting a native Triple target.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Malformed or unsupported configuration.
    #[error("invalid xDS configuration: {0}")]
    Invalid(String),
    /// A required dependency has not arrived yet.
    #[error("xDS dependency unavailable: {0}")]
    Unavailable(String),
    /// No healthy endpoint is available for this cluster.
    #[error("no healthy endpoint for {0}")]
    NoEndpoint(String),
    /// No configured route matches this call.
    #[error("no matching route for {0}")]
    NoRoute(String),
    /// Native Triple transport or RPC failure.
    #[error(transparent)]
    Rpc(#[from] rpc::Error),
    /// Invalid Protobuf resource.
    #[error(transparent)]
    Decode(#[from] prost::DecodeError),
    /// Bootstrap or certificate file failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Malformed JSON bootstrap.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
/// Result returned by this discovery client.
pub type Result<T> = std::result::Result<T, Error>;
fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}
fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(invalid(message))
    }
}
fn decode<M: prost::Message + Default>(any: &prost_types::Any, name: &str) -> Result<M> {
    require(
        any.type_url == format!("type.googleapis.com/{name}"),
        "resource Any type_url mismatch",
    )?;
    Ok(M::decode(any.value.as_slice())?)
}
