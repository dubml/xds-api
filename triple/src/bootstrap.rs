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

//! Existing dubbod bootstrap JSON and certificate-provider configuration.
use crate::{
    Result, invalid,
    proto::core::v1::{Locality, Node},
    require,
};
use rpc::{Client, Limits, rustls};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc, time::Duration};

/// PEM files used by a file_watcher certificate provider.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateFiles {
    /// Leaf-first client certificate chain.
    #[serde(default)]
    pub certificate_file: String,
    /// Client private key.
    #[serde(default)]
    pub private_key_file: String,
    /// Trusted root certificates.
    #[serde(default)]
    pub ca_certificate_file: String,
    /// Protobuf JSON interval used to reload certificate file generations.
    #[serde(default)]
    pub refresh_interval: Option<String>,
}

/// Validated bootstrap retaining node metadata and named certificate providers.
#[derive(Clone, Debug)]
pub struct Bootstrap {
    /// Management server address, including an optional scheme.
    pub server_uri: String,
    /// Node sent again on every ADS connection.
    pub node: Node,
    /// Named providers used by CDS TLS configuration.
    pub certificate_providers: BTreeMap<String, CertificateFiles>,
    pub(crate) channel: Channel,
    pub(crate) keepalive: Keepalive,
    loaded: BTreeMap<Option<String>, Arc<crate::tls::Material>>,
}
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct Keepalive {
    pub enabled: bool,
    pub time: String,
    pub timeout: String,
    // ADS always has an active stream; this flag only controls idle channels.
    #[serde(default, rename = "permit_without_stream")]
    _permit_without_stream: bool,
}
impl Default for Keepalive {
    fn default() -> Self {
        Self {
            enabled: false,
            time: "30s".into(),
            timeout: "10s".into(),
            _permit_without_stream: false,
        }
    }
}
#[derive(Clone, Debug)]
pub(crate) enum Channel {
    Insecure,
    Tls(CertificateFiles),
}
#[derive(Deserialize)]
struct Raw {
    xds_servers: Vec<Server>,
    node: Value,
    #[serde(default)]
    certificate_providers: BTreeMap<String, Provider>,
    #[serde(default)]
    dubbo_grpc_keepalive: Keepalive,
}
#[derive(Deserialize)]
struct Server {
    server_uri: String,
    channel_creds: Vec<Credentials>,
    #[serde(default)]
    server_features: Vec<String>,
}
#[derive(Deserialize)]
struct Credentials {
    r#type: String,
    #[serde(default)]
    config: Option<CertificateFiles>,
}
#[derive(Deserialize)]
struct Provider {
    plugin_name: String,
    config: CertificateFiles,
}

impl Bootstrap {
    /// Reads the injected TRIPLE_XDS_BOOTSTRAP file.
    pub fn from_env() -> Result<Self> {
        let path = std::env::var_os("TRIPLE_XDS_BOOTSTRAP")
            .ok_or_else(|| invalid("TRIPLE_XDS_BOOTSTRAP is missing"))?;
        Self::from_file(path)
    }
    /// Reads a bootstrap; relative certificate paths are resolved beside it.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let mut value = Self::from_json(&std::fs::read(path)?)?;
        let directory = path.parent().unwrap_or(Path::new("."));
        if let Channel::Tls(files) = &mut value.channel {
            files.resolve(directory);
        }
        for files in value.certificate_providers.values_mut() {
            files.resolve(directory);
        }
        Ok(value)
    }
    /// Parses the existing bootstrap format without discarding malformed node metadata.
    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let raw: Raw = serde_json::from_slice(bytes)?;
        parse_interval(&raw.dubbo_grpc_keepalive.time)?;
        parse_interval(&raw.dubbo_grpc_keepalive.timeout)?;
        let server = raw
            .xds_servers
            .into_iter()
            .next()
            .ok_or_else(|| invalid("xds_servers is empty"))?;
        validate_uri(&server.server_uri)?;
        require(
            server
                .server_features
                .iter()
                .all(|feature| feature == "xds_v3"),
            "unsupported xDS server feature",
        )?;
        let node = parse_node(&raw.node)?;
        let credential = server
            .channel_creds
            .into_iter()
            .find(|c| matches!(c.r#type.as_str(), "tls" | "insecure"))
            .ok_or_else(|| invalid("no supported channel credential"))?;
        let mut certificate_providers = BTreeMap::new();
        for (name, provider) in raw.certificate_providers {
            require(
                !name.is_empty() && provider.plugin_name == "file_watcher",
                "unsupported certificate provider",
            )?;
            provider.config.validate(false)?;
            certificate_providers.insert(name, provider.config);
        }
        let channel = match credential.r#type.as_str() {
            "tls" => {
                require(
                    !server.server_uri.starts_with("unix://"),
                    "TLS over Unix management sockets is unsupported",
                )?;
                let mut files = credential.config.unwrap_or_default();
                if files.certificate_file.is_empty()
                    && files.private_key_file.is_empty()
                    && files.ca_certificate_file.is_empty()
                {
                    files = certificate_providers
                        .get("default")
                        .cloned()
                        .ok_or_else(|| {
                            invalid("TLS requires certificate configuration or a default provider")
                        })?;
                }
                files.validate(true)?;
                Channel::Tls(files)
            }
            _ => {
                require(
                    !server.server_uri.starts_with("https://"),
                    "https server URI requires TLS credentials",
                )?;
                Channel::Insecure
            }
        };
        Ok(Self {
            server_uri: server.server_uri,
            node,
            certificate_providers,
            channel,
            keepalive: raw.dubbo_grpc_keepalive,
            loaded: BTreeMap::new(),
        })
    }
    pub(crate) async fn connect(&self, limits: Limits) -> Result<Client> {
        let address = dial_address(&self.server_uri);
        match &self.channel {
            Channel::Insecure if self.server_uri.starts_with("unix://") => {
                #[cfg(unix)]
                {
                    Ok(Client::from_io(
                        tokio::net::UnixStream::connect(address).await?,
                        "http://localhost",
                        limits,
                    )
                    .await?)
                }
                #[cfg(not(unix))]
                {
                    Err(invalid("Unix sockets unavailable on this platform"))
                }
            }
            Channel::Insecure => Ok(Client::connect(address, limits).await?),
            Channel::Tls(files) => {
                let name = host(address)?;
                let config = match self.loaded.get(&None) {
                    Some(material) => crate::tls::config_material(material, material, &[])?,
                    None => crate::tls::config(files, files, &[])?,
                };
                Ok(Client::connect_tls(address, &name, config, limits).await?)
            }
        }
    }
    pub(crate) fn upstream_tls(
        &self,
        context: &crate::proto::extensions::transport_sockets::tls::v1::UpstreamTlsContext,
    ) -> Result<Arc<rustls::ClientConfig>> {
        use crate::proto::extensions::transport_sockets::tls::v1::common_tls_context::ValidationContextType;
        let common = context
            .common_tls_context
            .as_ref()
            .ok_or_else(|| invalid("missing common TLS context"))?;
        require(
            common.alpn_protocols.is_empty() || common.alpn_protocols == ["h2"],
            "unsupported upstream ALPN",
        )?;
        let cert = common
            .tls_certificate_certificate_provider_instance
            .as_ref()
            .filter(|p| !p.instance_name.is_empty())
            .map_or("default", |p| p.instance_name.as_str());
        let (root, sans) = match &common.validation_context_type {
            Some(ValidationContextType::CombinedValidationContext(value)) => {
                let provider = value
                    .validation_context_certificate_provider_instance
                    .as_ref()
                    .filter(|p| !p.instance_name.is_empty())
                    .map_or("default", |p| p.instance_name.as_str());
                let sans = value
                    .default_validation_context
                    .as_ref()
                    .map(|c| c.match_subject_alt_names.as_slice())
                    .unwrap_or(&[]);
                require(
                    value
                        .default_validation_context
                        .as_ref()
                        .is_none_or(|c| c.trusted_ca.is_none()),
                    "inline TLS roots are unsupported; use file_watcher",
                )?;
                (provider, sans)
            }
            None => ("default", &[][..]),
        };
        let identity = self
            .certificate_providers
            .get(cert)
            .ok_or_else(|| invalid(format!("missing certificate provider {cert}")))?;
        let roots = self
            .certificate_providers
            .get(root)
            .ok_or_else(|| invalid(format!("missing root provider {root}")))?;
        require(
            !identity.certificate_file.is_empty(),
            "upstream mTLS requires client identity",
        )?;
        match (
            self.loaded.get(&Some(cert.into())),
            self.loaded.get(&Some(root.into())),
        ) {
            (Some(identity), Some(roots)) => crate::tls::config_material(identity, roots, sans),
            _ => crate::tls::config(identity, roots, sans),
        }
    }

    pub(crate) fn reload_certificates(&mut self) -> Result<bool> {
        let mut loaded = BTreeMap::new();
        for (name, files) in &self.certificate_providers {
            loaded.insert(
                Some(name.clone()),
                Arc::new(crate::tls::Material::load(files)?),
            );
        }
        if let Channel::Tls(files) = &self.channel {
            let material = Arc::new(crate::tls::Material::load(files)?);
            crate::tls::config_material(&material, &material, &[])?;
            loaded.insert(None, material);
        }
        let changed = loaded.len() != self.loaded.len()
            || loaded.iter().any(|(name, value)| {
                self.loaded
                    .get(name)
                    .is_none_or(|old| !old.same_generation(value))
            });
        if changed {
            self.loaded = loaded;
        }
        Ok(changed)
    }

    pub(crate) fn refresh_interval(&self) -> Result<Duration> {
        let mut interval = Duration::from_secs(900);
        for files in self
            .certificate_providers
            .values()
            .chain(match &self.channel {
                Channel::Tls(files) => Some(files),
                _ => None,
            })
        {
            interval = interval.min(parse_interval(
                files.refresh_interval.as_deref().unwrap_or("1s"),
            )?);
        }
        Ok(interval)
    }
}

pub(crate) fn parse_interval(value: &str) -> Result<Duration> {
    let mut remainder = value;
    let mut seconds = 0.0;
    while !remainder.is_empty() {
        let length = remainder
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .ok_or_else(|| invalid("duration requires a unit"))?;
        let number: f64 = remainder[..length]
            .parse()
            .map_err(|_| invalid("invalid duration"))?;
        remainder = &remainder[length..];
        let (unit, scale) = [
            ("ns", 1e-9),
            ("us", 1e-6),
            ("µs", 1e-6),
            ("ms", 1e-3),
            ("s", 1.0),
            ("m", 60.0),
            ("h", 3600.0),
        ]
        .into_iter()
        .find(|(unit, _)| remainder.starts_with(unit))
        .ok_or_else(|| invalid("unsupported duration unit"))?;
        seconds += number * scale;
        remainder = &remainder[unit.len()..];
    }
    let duration = Duration::try_from_secs_f64(seconds).map_err(|_| invalid("invalid duration"))?;
    require(!duration.is_zero(), "duration must be positive")?;
    Ok(duration)
}
impl CertificateFiles {
    fn validate(&self, roots: bool) -> Result<()> {
        if let Some(interval) = &self.refresh_interval {
            let value = interval
                .strip_suffix('s')
                .ok_or_else(|| invalid("invalid refresh_interval"))?;
            let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
            require(
                !seconds.is_empty()
                    && seconds.bytes().all(|b| b.is_ascii_digit())
                    && fraction.len() <= 9
                    && fraction.bytes().all(|b| b.is_ascii_digit())
                    && (!value.contains('.') || !fraction.is_empty()),
                "invalid refresh_interval",
            )?;
            let seconds: u64 = seconds
                .parse()
                .map_err(|_| invalid("invalid refresh_interval"))?;
            require(
                seconds <= 315_576_000_000 && (seconds > 0 || fraction.bytes().any(|b| b != b'0')),
                "invalid refresh_interval",
            )?;
        }
        require(
            self.certificate_file.is_empty() == self.private_key_file.is_empty(),
            "certificate_file and private_key_file must be paired",
        )?;
        require(
            !roots || !self.ca_certificate_file.is_empty(),
            "TLS requires ca_certificate_file",
        )
    }
    fn resolve(&mut self, directory: &Path) {
        for path in [
            &mut self.certificate_file,
            &mut self.private_key_file,
            &mut self.ca_certificate_file,
        ] {
            if !path.is_empty() && Path::new(path).is_relative() {
                *path = directory.join(&*path).to_string_lossy().into_owned();
            }
        }
    }
}
pub(crate) fn dial_address(uri: &str) -> &str {
    uri.strip_prefix("dns:///")
        .or_else(|| uri.strip_prefix("unix://"))
        .or_else(|| uri.strip_prefix("https://"))
        .or_else(|| uri.strip_prefix("http://"))
        .unwrap_or(uri)
}
fn validate_uri(uri: &str) -> Result<()> {
    let address = dial_address(uri);
    require(
        !address.is_empty() && !address.chars().any(char::is_whitespace),
        "invalid server_uri",
    )?;
    if uri.starts_with("unix://") {
        require(
            address.starts_with('/'),
            "Unix socket path must be absolute",
        )
    } else {
        host(address).map(|_| ())
    }
}
pub(crate) fn host(address: &str) -> Result<String> {
    let (name, port) = address
        .rsplit_once(':')
        .ok_or_else(|| invalid("address requires host:port"))?;
    require(
        !name.is_empty() && !name.contains('/') && !name.contains('@'),
        "invalid address host",
    )?;
    require(
        port.parse::<u16>().is_ok_and(|p| p != 0),
        "invalid address port",
    )?;
    Ok(name
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned())
}
fn parse_node(value: &Value) -> Result<Node> {
    let map = value
        .as_object()
        .ok_or_else(|| invalid("node must be an object"))?;
    require(
        map.keys()
            .all(|k| matches!(k.as_str(), "id" | "cluster" | "metadata" | "locality")),
        "unknown node field",
    )?;
    let id = map
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("node.id is required"))?
        .to_owned();
    let cluster = map
        .get("cluster")
        .map(|v| v.as_str().ok_or_else(|| invalid("invalid node.cluster")))
        .transpose()?
        .unwrap_or("")
        .to_owned();
    let metadata = map.get("metadata").map(json_struct).transpose()?;
    let locality = map
        .get("locality")
        .map(|v| -> Result<Locality> {
            let m = v.as_object().ok_or_else(|| invalid("invalid locality"))?;
            require(
                m.keys()
                    .all(|k| matches!(k.as_str(), "region" | "zone" | "subZone" | "sub_zone")),
                "unknown locality field",
            )?;
            let field = |key: &str| -> Result<String> {
                Ok(m.get(key)
                    .map(|v| v.as_str().ok_or_else(|| invalid("invalid locality value")))
                    .transpose()?
                    .unwrap_or("")
                    .to_owned())
            };
            Ok(Locality {
                region: field("region")?,
                zone: field("zone")?,
                sub_zone: if m.contains_key("subZone") {
                    field("subZone")?
                } else {
                    field("sub_zone")?
                },
            })
        })
        .transpose()?;
    Ok(Node {
        id,
        cluster,
        metadata,
        locality,
    })
}
fn json_struct(value: &Value) -> Result<prost_types::Struct> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("metadata must be an object"))?;
    Ok(prost_types::Struct {
        fields: object
            .iter()
            .map(|(k, v)| Ok((k.clone(), json_value(v)?)))
            .collect::<Result<_>>()?,
    })
}
fn json_value(value: &Value) -> Result<prost_types::Value> {
    use prost_types::value::Kind;
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(v) => Kind::BoolValue(*v),
        Value::String(v) => Kind::StringValue(v.clone()),
        Value::Number(v) => Kind::NumberValue(
            v.as_f64()
                .ok_or_else(|| invalid("invalid metadata number"))?,
        ),
        Value::Array(v) => Kind::ListValue(prost_types::ListValue {
            values: v.iter().map(json_value).collect::<Result<_>>()?,
        }),
        Value::Object(_) => Kind::StructValue(json_struct(value)?),
    };
    Ok(prost_types::Value { kind: Some(kind) })
}
