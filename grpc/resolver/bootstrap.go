package resolver

import (
	"encoding/json"
	"fmt"
	"os"

	corev1 "github.com/dubml/xds-api/core/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// BootstrapConfig holds parsed xDS bootstrap configuration.
type BootstrapConfig struct {
	ServerURI    string
	ChannelCreds []ChannelCredsConfig
	Node         *corev1.Node
	// CertProviders maps provider instance name to file-watcher cert config.
	// Key matches the instance_name in UpstreamTlsContext certificate_provider_instance.
	CertProviders map[string]FileWatcherCertConfig
	Keepalive     *KeepaliveConfig
}

// ChannelCredsConfig holds the channel credentials for the xDS management
// server declared in xds_servers[0].channel_creds.
type ChannelCredsConfig struct {
	Type   string
	Config FileWatcherCertConfig
}

// FileWatcherCertConfig holds the resolved file paths for a certificate provider.
type FileWatcherCertConfig struct {
	CertificateFile   string `json:"certificate_file"`
	PrivateKeyFile    string `json:"private_key_file"`
	CACertificateFile string `json:"ca_certificate_file"`
}

type KeepaliveConfig struct {
	Enabled             bool   `json:"enabled"`
	Time                string `json:"time"`
	Timeout             string `json:"timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
}

// ParseBootstrap reads and parses the xDS bootstrap JSON file.
func ParseBootstrap(path string) (*BootstrapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap file %s: %w", path, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap JSON: %w", err)
	}

	cfg := &BootstrapConfig{
		CertProviders: make(map[string]FileWatcherCertConfig),
	}

	// Parse xds_servers[0].server_uri and xds_servers[0].channel_creds.
	if serversRaw, ok := raw["xds_servers"]; ok {
		var servers []map[string]json.RawMessage
		if err := json.Unmarshal(serversRaw, &servers); err == nil && len(servers) > 0 {
			if uriRaw, ok := servers[0]["server_uri"]; ok {
				var uri string
				if err := json.Unmarshal(uriRaw, &uri); err == nil {
					cfg.ServerURI = uri
				}
			}
			if credsRaw, ok := servers[0]["channel_creds"]; ok {
				var creds []struct {
					Type   string          `json:"type"`
					Config json.RawMessage `json:"config"`
				}
				if err := json.Unmarshal(credsRaw, &creds); err != nil {
					return nil, fmt.Errorf("failed to parse xds_servers[0].channel_creds: %w", err)
				}
				for _, cred := range creds {
					out := ChannelCredsConfig{Type: cred.Type}
					if len(cred.Config) > 0 && string(cred.Config) != "null" {
						if err := json.Unmarshal(cred.Config, &out.Config); err != nil {
							return nil, fmt.Errorf("failed to parse xds_servers[0].channel_creds config: %w", err)
						}
					}
					cfg.ChannelCreds = append(cfg.ChannelCreds, out)
				}
			}
		}
	}
	if cfg.ServerURI == "" {
		return nil, fmt.Errorf("no xds_servers[0].server_uri found in bootstrap")
	}

	if keepaliveRaw, ok := raw["dubbo_grpc_keepalive"]; ok {
		keepalive := &KeepaliveConfig{}
		if err := json.Unmarshal(keepaliveRaw, keepalive); err != nil {
			return nil, fmt.Errorf("failed to parse dubbo_grpc_keepalive: %w", err)
		}
		cfg.Keepalive = keepalive
	}

	// Parse node using protojson (Node contains protobuf Struct for metadata)
	if nodeRaw, ok := raw["node"]; ok {
		node := &corev1.Node{}
		if err := protojson.Unmarshal(nodeRaw, node); err == nil {
			cfg.Node = node
		} else {
			var fallback map[string]json.RawMessage
			if err := json.Unmarshal(nodeRaw, &fallback); err == nil {
				if idRaw, ok := fallback["id"]; ok {
					var id string
					if err := json.Unmarshal(idRaw, &id); err == nil {
						cfg.Node = &corev1.Node{Id: id}
					}
				}
			}
		}
	}

	// Parse certificate_providers — each entry has plugin_name and config.
	// We support the "file_watcher" plugin which carries cert/key/ca file paths.
	if providersRaw, ok := raw["certificate_providers"]; ok {
		var providers map[string]struct {
			PluginName string          `json:"plugin_name"`
			Config     json.RawMessage `json:"config"`
		}
		if err := json.Unmarshal(providersRaw, &providers); err == nil {
			for name, p := range providers {
				if p.PluginName == "file_watcher" && p.Config != nil {
					var fwCfg FileWatcherCertConfig
					if err := json.Unmarshal(p.Config, &fwCfg); err == nil {
						cfg.CertProviders[name] = fwCfg
					}
				}
			}
		}
	}

	return cfg, nil
}
