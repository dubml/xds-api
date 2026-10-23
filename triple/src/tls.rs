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

//! Root-chain validation plus the exact DNS/URI SAN policy emitted by dubbod.
use crate::{CertificateFiles, Result, invalid};
use rpc::rustls::{
    self, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        verify_server_cert_signed_by_trust_anchor,
    },
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime, pem::PemObject},
    server::ParsedCertificate,
};
use std::{fmt, io::Read, sync::Arc};

/// One validated, in-memory generation of certificate files; keys are never formatted.
pub(crate) struct Material {
    raw: Vec<Vec<u8>>,
    certificates: Vec<CertificateDer<'static>>,
    key: Option<PrivateKeyDer<'static>>,
    roots: Vec<CertificateDer<'static>>,
}
impl fmt::Debug for Material {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Material { certificate generation }")
    }
}
impl Material {
    pub(crate) fn load(files: &CertificateFiles) -> Result<Self> {
        let mut raw = Vec::new();
        for path in [
            &files.certificate_file,
            &files.private_key_file,
            &files.ca_certificate_file,
        ] {
            raw.push(read_certificate_file(path)?);
        }
        let certificates = parse_certificates(&raw[0])?;
        for certificate in &certificates {
            let (remaining, parsed) = x509_parser::parse_x509_certificate(certificate.as_ref())
                .map_err(|_| invalid("invalid identity certificate"))?;
            crate::require(
                remaining.is_empty() && parsed.validity().is_valid(),
                "identity certificate is not currently valid",
            )?;
        }
        let key = if raw[1].is_empty() {
            None
        } else {
            Some(
                PrivateKeyDer::from_pem_slice(&raw[1])
                    .map_err(|_| invalid("invalid private key PEM"))?,
            )
        };
        crate::require(
            certificates.is_empty() == key.is_none(),
            "missing certificate or private key",
        )?;
        if let Some(key) = &key {
            rustls::sign::CertifiedKey::from_der(
                certificates.clone(),
                key.clone_key(),
                &rustls::crypto::ring::default_provider(),
            )
            .map_err(|_| invalid("certificate/key mismatch"))?;
        }
        let roots = parse_certificates(&raw[2])?;
        let mut store = RootCertStore::empty();
        for root in &roots {
            store
                .add(root.clone())
                .map_err(|_| invalid("invalid trust anchor"))?;
        }
        for (path, bytes) in [
            &files.certificate_file,
            &files.private_key_file,
            &files.ca_certificate_file,
        ]
        .into_iter()
        .zip(&raw)
        {
            crate::require(
                read_certificate_file(path)? == *bytes,
                "certificate files changed while loading",
            )?;
        }
        Ok(Self {
            raw,
            certificates,
            key,
            roots,
        })
    }
    pub(crate) fn same_generation(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}
fn read_certificate_file(path: &str) -> Result<Vec<u8>> {
    if path.is_empty() {
        return Ok(Vec::new());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    crate::require(bytes.len() <= 1024 * 1024, "certificate file exceeds limit")?;
    Ok(bytes)
}
fn parse_certificates(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let certificates = CertificateDer::pem_slice_iter(bytes)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| invalid("invalid certificate PEM"))?;
    crate::require(!certificates.is_empty(), "empty certificate PEM")?;
    Ok(certificates)
}

pub(crate) fn config(
    identity: &CertificateFiles,
    root_files: &CertificateFiles,
    sans: &[String],
) -> Result<Arc<ClientConfig>> {
    config_material(
        &Material::load(identity)?,
        &Material::load(root_files)?,
        sans,
    )
}

pub(crate) fn config_material(
    identity: &Material,
    root_files: &Material,
    sans: &[String],
) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for certificate in &root_files.roots {
        roots
            .add(certificate.clone())
            .map_err(|_| invalid("invalid trust anchor"))?;
    }
    crate::require(!roots.is_empty(), "empty trust store")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let default =
        WebPkiServerVerifier::builder_with_provider(Arc::new(roots.clone()), provider.clone())
            .build()
            .map_err(|_| invalid("invalid trust roots"))?;
    let verifier = Arc::new(SanVerifier {
        roots,
        default,
        sans: sans.to_vec(),
        provider: provider.clone(),
    });
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| invalid("invalid TLS protocols"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut config = if let Some(key) = &identity.key {
        builder
            .with_client_auth_cert(identity.certificates.clone(), key.clone_key())
            .map_err(|_| invalid("certificate/key mismatch"))?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(config))
}
#[derive(Debug)]
struct SanVerifier {
    roots: RootCertStore,
    default: Arc<WebPkiServerVerifier>,
    sans: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}
impl ServerCertVerifier for SanVerifier {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        chain: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if self.sans.is_empty() {
            return self
                .default
                .verify_server_cert(leaf, chain, name, ocsp, now);
        }
        let parsed = ParsedCertificate::try_from(leaf)?;
        verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            chain,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let (_, certificate) =
            x509_parser::parse_x509_certificate(leaf.as_ref()).map_err(|_| {
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
            })?;
        let extension = certificate.subject_alternative_name().map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let allowed = extension.is_some_and(|san| {
            san.value.general_names.iter().any(|name| {
                use x509_parser::extensions::GeneralName;
                match name {
                    GeneralName::DNSName(value) | GeneralName::URI(value) => {
                        self.sans.iter().any(|s| s == value)
                    }
                    _ => false,
                }
            })
        });
        if !allowed {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::NotValidForName,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.default
            .verify_tls12_signature(message, cert, signature)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        self.default
            .verify_tls13_signature(message, cert, signature)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.default.supported_verify_schemes()
    }
}
