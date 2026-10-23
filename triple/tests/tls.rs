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
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
use rpc::{
    CancellationToken, Identity, Limits, Metadata,
    rustls::{RootCertStore, pki_types::PrivatePkcs8KeyDer},
};
use std::{sync::Arc, time::Duration};
use xds_client::{
    Bootstrap, Discovery, ResourceType,
    proto::{core::v1 as core, extensions::transport_sockets::tls::v1 as tls},
};

#[tokio::test]
async fn cds_provider_tls_verifies_spiffe_san_chain_and_client_identity() {
    let directory = std::env::temp_dir().join(format!(
        "triple-xds-cert-{}-{}",
        std::process::id(),
        fastrand::u64(..)
    ));
    std::fs::create_dir(&directory).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(directory.clone());
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root = ca.self_signed(&ca_key).unwrap();
    let issuer = Issuer::from_params(&ca, &ca_key);
    let issue = |identity: &str| {
        let key = KeyPair::generate().unwrap();
        let mut parameters = CertificateParams::default();
        parameters.subject_alt_names = vec![SanType::URI(identity.try_into().unwrap())];
        let certificate = parameters.signed_by(&key, &issuer).unwrap();
        (certificate, key)
    };
    let (server_certificate, server_key) = issue("spiffe://cluster.local/ns/app/sa/echo");
    let (client_certificate, client_key) = issue("spiffe://cluster.local/ns/app/sa/client");
    let cert = directory.join("client.pem");
    let key = directory.join("key.pem");
    let ca_file = directory.join("ca.pem");
    std::fs::write(&cert, client_certificate.pem()).unwrap();
    std::fs::write(&key, client_key.serialize_pem()).unwrap();
    std::fs::write(&ca_file, root.pem()).unwrap();
    let bootstrap=Bootstrap::from_json(serde_json::json!({"node":{"id":"test"},"xds_servers":[{"server_uri":"127.0.0.1:1","channel_creds":[{"type":"insecure"}]}],"certificate_providers":{"default":{"plugin_name":"file_watcher","config":{"certificate_file":cert,"private_key_file":key,"ca_certificate_file":ca_file}}}}).to_string().as_bytes()).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(root.der().clone()).unwrap();
    let identity = Identity {
        certificates: vec![server_certificate.der().clone()],
        private_key: PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
    };
    let config = rpc::server_tls_config(identity, Some(roots)).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let server = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {_=server_stop.cancelled()=>break,connection=listener.accept()=>{let(io,_)=connection.unwrap();tasks.spawn(rpc::serve_tls_connection(io,config.clone(),Arc::new(echo::EchoService),Limits::default(),server_stop.clone(),Duration::from_millis(100)));},_=tasks.join_next(),if !tasks.is_empty()=>{}}
        }
        while tasks.join_next().await.is_some() {}
    });
    let mut discovery = Discovery::new(bootstrap, ["listener".into()]).unwrap();
    discovery.process(response(
        ResourceType::Listener,
        "1",
        vec![any(
            "listener.v1.Listener",
            &common::listener("listener", "routes"),
        )],
    ));
    discovery.process(response(
        ResourceType::Route,
        "2",
        vec![any(
            "route.v1.RouteConfiguration",
            &route("routes", &[("a", 1)]),
        )],
    ));
    let mut cluster = cluster("a");
    let tls_context = |san: &str| tls::UpstreamTlsContext {
        common_tls_context: Some(tls::CommonTlsContext {
            tls_certificate_certificate_provider_instance: Some(
                tls::common_tls_context::CertificateProviderInstance {
                    instance_name: "default".into(),
                    certificate_name: "default".into(),
                },
            ),
            alpn_protocols: vec!["h2".into()],
            validation_context_type: Some(
                tls::common_tls_context::ValidationContextType::CombinedValidationContext(
                    tls::common_tls_context::CombinedCertificateValidationContext {
                        validation_context_certificate_provider_instance: Some(
                            tls::common_tls_context::CertificateProviderInstance {
                                instance_name: "default".into(),
                                certificate_name: "ROOTCA".into(),
                            },
                        ),
                        default_validation_context: Some(tls::CertificateValidationContext {
                            match_subject_alt_names: vec![san.into()],
                            ..Default::default()
                        }),
                    },
                ),
            ),
        }),
        sni: "echo.test".into(),
    };
    cluster.transport_socket = Some(core::TransportSocket {
        name: "transport_sockets.tls".into(),
        config_type: Some(core::transport_socket::ConfigType::TypedConfig(any(
            "extensions.transport_sockets.tls.v1.UpstreamTlsContext",
            &tls_context("spiffe://cluster.local/ns/app/sa/echo"),
        ))),
    });
    assert!(
        discovery.process(response(
            ResourceType::Cluster,
            "3",
            vec![any("cluster.v1.Cluster", &cluster)]
        ))[0]
            .error_detail
            .is_none()
    );
    discovery.process(response(
        ResourceType::Endpoint,
        "4",
        vec![any(
            "endpoint.v1.ClusterLoadAssignment",
            &assignment("a", &[("127.0.0.1", address.port(), 1, 1)]),
        )],
    ));
    let selected = discovery
        .snapshot()
        .select(
            "listener",
            "echo.test",
            "/test.Echo/Unary",
            &Metadata::new(),
            0,
        )
        .unwrap();
    let mut client = selected.connect(Limits::default()).await.unwrap();
    let result: echo::Echo = client
        .unary(
            "/test.Echo/Unary",
            &echo::Echo {
                text: "authenticated".into(),
            },
            &Metadata::new(),
        )
        .await
        .unwrap();
    assert_eq!(result.text, "authenticated");
    drop(client);
    cluster.transport_socket.as_mut().unwrap().config_type =
        Some(core::transport_socket::ConfigType::TypedConfig(any(
            "extensions.transport_sockets.tls.v1.UpstreamTlsContext",
            &tls_context("spiffe://cluster.local/ns/other/sa/echo"),
        )));
    discovery.process(response(
        ResourceType::Cluster,
        "wrong-identity",
        vec![any("cluster.v1.Cluster", &cluster)],
    ));
    assert!(
        discovery
            .snapshot()
            .select(
                "listener",
                "echo.test",
                "/test.Echo/Unary",
                &Metadata::new(),
                0
            )
            .unwrap()
            .connect(Limits::default())
            .await
            .is_err()
    );
    // A matching URI SAN alone cannot bypass the root-chain check.
    let wrong_key = KeyPair::generate().unwrap();
    let wrong_root = ca.self_signed(&wrong_key).unwrap();
    std::fs::write(&ca_file, wrong_root.pem()).unwrap();
    cluster.transport_socket.as_mut().unwrap().config_type =
        Some(core::transport_socket::ConfigType::TypedConfig(any(
            "extensions.transport_sockets.tls.v1.UpstreamTlsContext",
            &tls_context("spiffe://cluster.local/ns/app/sa/echo"),
        )));
    discovery.process(response(
        ResourceType::Cluster,
        "wrong-ca",
        vec![any("cluster.v1.Cluster", &cluster)],
    ));
    assert!(
        discovery
            .snapshot()
            .select(
                "listener",
                "echo.test",
                "/test.Echo/Unary",
                &Metadata::new(),
                0
            )
            .unwrap()
            .connect(Limits::default())
            .await
            .is_err()
    );
    stop.cancel();
    server.await.unwrap();
}
