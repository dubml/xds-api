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

//! Regenerates checked-in messages only when XDS_API_SOURCE is explicitly set.
use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-env-changed=XDS_API_SOURCE");
    let Some(source) = env::var_os("XDS_API_SOURCE") else {
        return Ok(());
    };
    let source = PathBuf::from(source);
    let files = [
        "service/discovery/v1/ads.proto",
        "service/secret/v1/sds.proto",
        "listener/v1/listener.proto",
        "route/v1/route.proto",
        "cluster/v1/cluster.proto",
        "endpoint/v1/endpoint.proto",
        "extensions/transport_sockets/tls/v1/tls.proto",
        "extensions/filters/v1/network/http_connection_manager/http_connection_manager.proto",
        "extensions/filters/v1/http/router/router.proto",
        "extensions/filters/v1/http/rbac/rbac.proto",
        "extensions/filters/v1/http/jwt_authn/jwt_authn.proto",
    ];
    let paths: Vec<_> = files.iter().map(|file| source.join(file)).collect();
    for path in &paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    // Also track transitive imports in the contract's source directories.
    for directory in [
        "core",
        "service",
        "listener",
        "route",
        "cluster",
        "endpoint",
        "extensions",
        "type",
        "google",
    ] {
        let path = source.join(directory);
        if path.is_dir() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    prost_build::Config::new()
        .btree_map(["."])
        .include_file("mod.rs")
        .out_dir("src/generated")
        .file_descriptor_set_path("src/generated/descriptor.bin")
        .compile_protos(&paths, &[source])?;
    Ok(())
}
