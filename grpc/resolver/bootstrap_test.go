package resolver

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	tlsv1 "github.com/dubml/xds-api/extensions/transport_sockets/tls/v1"
)

func TestParseBootstrapReadsManagementServerChannelCreds(t *testing.T) {
	dir := t.TempDir()
	bootstrapPath := filepath.Join(dir, "grpc-bootstrap.json")
	data := []byte(`{
  "xds_servers": [{
    "server_uri": "dubbod.dubbo-system.svc:15012",
    "channel_creds": [{
      "type": "tls",
      "config": {
        "certificate_file": "/etc/dubbo/proxy/cert-chain.pem",
        "private_key_file": "/etc/dubbo/proxy/key.pem",
        "ca_certificate_file": "/etc/dubbo/proxy/root-cert.pem"
      }
    }],
    "server_features": ["xds_v3"]
  }],
  "node": {"id": "inherent~10.0.0.1~client.app~app.svc.cluster.local"},
  "dubbo_grpc_keepalive": {
    "enabled": true,
    "time": "30s",
    "timeout": "10s",
    "permit_without_stream": true
  },
  "certificate_providers": {
    "default": {
      "plugin_name": "file_watcher",
      "config": {
        "certificate_file": "/etc/dubbo/proxy/cert-chain.pem",
        "private_key_file": "/etc/dubbo/proxy/key.pem",
        "ca_certificate_file": "/etc/dubbo/proxy/root-cert.pem"
      }
    }
  }
}`)
	if err := os.WriteFile(bootstrapPath, data, 0o600); err != nil {
		t.Fatalf("write bootstrap: %v", err)
	}

	cfg, err := ParseBootstrap(bootstrapPath)
	if err != nil {
		t.Fatalf("ParseBootstrap() failed: %v", err)
	}
	if got, want := cfg.ServerURI, "dubbod.dubbo-system.svc:15012"; got != want {
		t.Fatalf("ServerURI = %q, want %q", got, want)
	}
	if got, want := len(cfg.ChannelCreds), 1; got != want {
		t.Fatalf("channel creds count = %d, want %d", got, want)
	}
	if got, want := cfg.ChannelCreds[0].Type, "tls"; got != want {
		t.Fatalf("channel creds type = %q, want %q", got, want)
	}
	if got, want := cfg.ChannelCreds[0].Config.CACertificateFile, "/etc/dubbo/proxy/root-cert.pem"; got != want {
		t.Fatalf("channel creds CA = %q, want %q", got, want)
	}
	if cfg.Node == nil || cfg.Node.Id != "inherent~10.0.0.1~client.app~app.svc.cluster.local" {
		t.Fatalf("node id = %#v", cfg.Node)
	}
	if got, want := cfg.CertProviders["default"].CertificateFile, "/etc/dubbo/proxy/cert-chain.pem"; got != want {
		t.Fatalf("default cert provider certificate = %q, want %q", got, want)
	}
	if cfg.Keepalive == nil {
		t.Fatalf("keepalive config = nil, want parsed config")
	}
	if !cfg.Keepalive.Enabled {
		t.Fatalf("keepalive enabled = false, want true")
	}
	if got, want := cfg.Keepalive.Time, "30s"; got != want {
		t.Fatalf("keepalive time = %q, want %q", got, want)
	}
	if got, want := cfg.Keepalive.Timeout, "10s"; got != want {
		t.Fatalf("keepalive timeout = %q, want %q", got, want)
	}
	if !cfg.Keepalive.PermitWithoutStream {
		t.Fatalf("keepalive permit_without_stream = false, want true")
	}
}

func TestDialOptionsFromBootstrapConsumesKeepalive(t *testing.T) {
	opts, err := DialOptionsFromBootstrap(&BootstrapConfig{
		ServerURI: "dubbod.dubbo-system.svc:26012",
		ChannelCreds: []ChannelCredsConfig{{
			Type: "insecure",
		}},
		Keepalive: &KeepaliveConfig{
			Enabled:             true,
			Time:                "30s",
			Timeout:             "10s",
			PermitWithoutStream: true,
		},
	})
	if err != nil {
		t.Fatalf("DialOptionsFromBootstrap() failed: %v", err)
	}
	if got, want := len(opts), 2; got != want {
		t.Fatalf("dial option count = %d, want %d", got, want)
	}
}

func TestDialOptionsFromBootstrapRejectsInvalidKeepalive(t *testing.T) {
	_, err := DialOptionsFromBootstrap(&BootstrapConfig{
		ServerURI: "dubbod.dubbo-system.svc:26012",
		ChannelCreds: []ChannelCredsConfig{{
			Type: "insecure",
		}},
		Keepalive: &KeepaliveConfig{
			Enabled: true,
			Time:    "bad",
		},
	})
	if err == nil {
		t.Fatalf("DialOptionsFromBootstrap() error = nil, want invalid keepalive error")
	}
}

func TestTransportCredentialsFromBootstrap(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *BootstrapConfig
		protocol string
	}{
		{
			name: "unix sockets use insecure credentials",
			cfg: &BootstrapConfig{
				ServerURI: "unix:///tmp/xds.sock",
				ChannelCreds: []ChannelCredsConfig{{
					Type: "tls",
				}},
			},
			protocol: "insecure",
		},
		{
			name: "insecure channel credentials",
			cfg: &BootstrapConfig{
				ServerURI: "dubbod.dubbo-system.svc:15010",
				ChannelCreds: []ChannelCredsConfig{{
					Type: "insecure",
				}},
			},
			protocol: "insecure",
		},
		{
			name: "tls channel credentials",
			cfg: &BootstrapConfig{
				ServerURI: "dubbod.dubbo-system.svc:15012",
				ChannelCreds: []ChannelCredsConfig{{
					Type: "tls",
				}},
			},
			protocol: "tls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds, err := TransportCredentialsFromBootstrap(tt.cfg)
			if err != nil {
				t.Fatalf("TransportCredentialsFromBootstrap() failed: %v", err)
			}
			if got := creds.Info().SecurityProtocol; got != tt.protocol {
				t.Fatalf("security protocol = %q, want %q", got, tt.protocol)
			}
		})
	}
}

func TestDialAddress(t *testing.T) {
	if got, want := DialAddress("unix:///tmp/xds.sock"), "unix:/tmp/xds.sock"; got != want {
		t.Fatalf("DialAddress() = %q, want %q", got, want)
	}
	if got, want := DialAddress("dubbod.dubbo-system.svc:15012"), "dubbod.dubbo-system.svc:15012"; got != want {
		t.Fatalf("DialAddress() = %q, want %q", got, want)
	}
}

func TestDataPlaneTLSConfigFromBootstrapUsesCDSContext(t *testing.T) {
	dir := t.TempDir()
	rootDER, rootPEM, rootKey := newTestCA(t)
	leafDER, leafPEM, leafKeyPEM := newTestLeaf(t, rootDER, rootKey)

	certFile := filepath.Join(dir, "cert-chain.pem")
	keyFile := filepath.Join(dir, "key.pem")
	rootFile := filepath.Join(dir, "root-cert.pem")
	for path, data := range map[string][]byte{
		certFile: leafPEM,
		keyFile:  leafKeyPEM,
		rootFile: rootPEM,
	} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	cfg, err := DataPlaneTLSConfigFromBootstrap(&BootstrapConfig{
		CertProviders: map[string]FileWatcherCertConfig{
			"default": {
				CertificateFile:   certFile,
				PrivateKeyFile:    keyFile,
				CACertificateFile: rootFile,
			},
		},
	}, &tlsv1.UpstreamTlsContext{
		Sni: "nginx.app.svc.cluster.local",
		CommonTlsContext: &tlsv1.CommonTlsContext{
			AlpnProtocols: []string{"h2"},
			TlsCertificateCertificateProviderInstance: &tlsv1.CommonTlsContext_CertificateProviderInstance{
				InstanceName: "default",
			},
			ValidationContextType: &tlsv1.CommonTlsContext_CombinedValidationContext{
				CombinedValidationContext: &tlsv1.CommonTlsContext_CombinedCertificateValidationContext{
					DefaultValidationContext: &tlsv1.CertificateValidationContext{
						MatchSubjectAltNames: []string{"spiffe://cluster.local/ns/app/sa/payment"},
					},
					ValidationContextCertificateProviderInstance: &tlsv1.CommonTlsContext_CertificateProviderInstance{
						InstanceName: "default",
					},
				},
			},
		},
	}, "fallback.invalid:443")
	if err != nil {
		t.Fatalf("DataPlaneTLSConfigFromBootstrap() failed: %v", err)
	}
	if cfg.ServerName != "nginx.app.svc.cluster.local" {
		t.Fatalf("ServerName = %q, want nginx host", cfg.ServerName)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("certificates = %d, want 1", len(cfg.Certificates))
	}
	if len(cfg.NextProtos) != 1 || cfg.NextProtos[0] != "h2" {
		t.Fatalf("NextProtos = %v, want [h2]", cfg.NextProtos)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{leafDER}, nil); err != nil {
		t.Fatalf("VerifyPeerCertificate() failed: %v", err)
	}
	if err := verifyPeerCertificateChain([][]byte{leafDER}, cfg.RootCAs, []string{
		"spiffe://cluster.local/ns/app/sa/other",
	}); err == nil {
		t.Fatal("certificate outside the CDS SAN allowlist was accepted")
	}
}

func newTestCA(t *testing.T) ([]byte, []byte, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate(root) failed: %v", err)
	}
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), key
}

func newTestLeaf(t *testing.T, rootDER []byte, rootKey *rsa.PrivateKey) ([]byte, []byte, []byte) {
	t.Helper()
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate(root) failed: %v", err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-leaf"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	identity, err := url.Parse("spiffe://cluster.local/ns/app/sa/payment")
	if err != nil {
		t.Fatalf("parse SPIFFE identity: %v", err)
	}
	tmpl.URIs = []*url.URL{identity}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(leaf) failed: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return der, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPEM
}
