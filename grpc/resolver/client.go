package resolver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	corev1 "github.com/dubml/xds-api/core/v1"
	tlsv1 "github.com/dubml/xds-api/extensions/transport_sockets/tls/v1"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

const (
	defaultKeepaliveTime    = 30 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
)

// Client is a minimal xDS ADS client backed by xds-api types.
type Client struct {
	conn   *grpc.ClientConn
	stream discovery.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	client discovery.AggregatedDiscoveryServiceClient
	node   *corev1.Node
}

// NewClient dials the xDS management server and opens an ADS stream.
// node is the Node parsed from the bootstrap file; if nil, a minimal node
// is built from environment variables.
func NewClient(ctx context.Context, serverURI string, node *corev1.Node) (*Client, error) {
	return dialClient(ctx, DialAddress(serverURI), node, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// NewClientWithBootstrap dials the xDS management server using the bootstrap
// server URI, node identity, and channel credentials.
func NewClientWithBootstrap(ctx context.Context, bootstrap *BootstrapConfig) (*Client, error) {
	if bootstrap == nil {
		return nil, fmt.Errorf("bootstrap config is nil")
	}
	opts, err := DialOptionsFromBootstrap(bootstrap)
	if err != nil {
		return nil, err
	}
	return dialClient(ctx, DialAddress(bootstrap.ServerURI), bootstrap.Node, opts...)
}

// DialAddress converts a bootstrap server_uri into a grpc.Dial target.
func DialAddress(serverURI string) string {
	if strings.HasPrefix(serverURI, "unix://") {
		return "unix:" + strings.TrimPrefix(serverURI, "unix://")
	}
	return serverURI
}

// DialOptionsFromBootstrap returns dial options for the xDS management server
// using xds_servers[0].channel_creds.
func DialOptionsFromBootstrap(bootstrap *BootstrapConfig) ([]grpc.DialOption, error) {
	creds, err := TransportCredentialsFromBootstrap(bootstrap)
	if err != nil {
		return nil, err
	}
	opts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	if keepaliveOpt, ok, err := keepaliveDialOption(bootstrap.Keepalive); err != nil {
		return nil, err
	} else if ok {
		opts = append(opts, keepaliveOpt)
	}
	return opts, nil
}

func keepaliveDialOption(cfg *KeepaliveConfig) (grpc.DialOption, bool, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, false, nil
	}
	interval, err := parseKeepaliveDuration("time", cfg.Time, defaultKeepaliveTime)
	if err != nil {
		return nil, false, err
	}
	timeout, err := parseKeepaliveDuration("timeout", cfg.Timeout, defaultKeepaliveTimeout)
	if err != nil {
		return nil, false, err
	}
	return grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                interval,
		Timeout:             timeout,
		PermitWithoutStream: cfg.PermitWithoutStream,
	}), true, nil
}

func parseKeepaliveDuration(name, value string, fallback time.Duration) (time.Duration, error) {
	if strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	out, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse dubbo_grpc_keepalive.%s %q: %w", name, value, err)
	}
	return out, nil
}

// TransportCredentialsFromBootstrap builds transport credentials for the xDS
// management server connection from bootstrap channel_creds.
func TransportCredentialsFromBootstrap(bootstrap *BootstrapConfig) (credentials.TransportCredentials, error) {
	if bootstrap == nil {
		return nil, fmt.Errorf("bootstrap config is nil")
	}
	if strings.HasPrefix(bootstrap.ServerURI, "unix://") {
		return insecure.NewCredentials(), nil
	}
	for _, channelCreds := range bootstrap.ChannelCreds {
		switch channelCreds.Type {
		case "insecure":
			return insecure.NewCredentials(), nil
		case "tls":
			cfg := channelCreds.Config
			if cfg.isZero() {
				cfg = bootstrap.CertProviders["default"]
			}
			tlsConfig, err := tlsConfigFromFileWatcher(cfg)
			if err != nil {
				return nil, err
			}
			return credentials.NewTLS(tlsConfig), nil
		}
	}
	return insecure.NewCredentials(), nil
}

func tlsConfigFromFileWatcher(cfg FileWatcherCertConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CACertificateFile != "" {
		rootPEM, err := os.ReadFile(cfg.CACertificateFile)
		if err != nil {
			return nil, fmt.Errorf("read xDS CA certificate %s: %w", cfg.CACertificateFile, err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(rootPEM) {
			return nil, fmt.Errorf("parse xDS CA certificate %s: no certificates found", cfg.CACertificateFile)
		}
		tlsConfig.RootCAs = roots
	}
	if cfg.CertificateFile != "" || cfg.PrivateKeyFile != "" {
		if cfg.CertificateFile == "" || cfg.PrivateKeyFile == "" {
			return nil, fmt.Errorf("xDS TLS channel credentials require both certificate_file and private_key_file")
		}
		cert, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load xDS client certificate/key: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}
	return tlsConfig, nil
}

// DataPlaneTLSConfigFromBootstrap builds the outbound data-plane TLS config
// selected by a CDS UpstreamTlsContext.
func DataPlaneTLSConfigFromBootstrap(bootstrap *BootstrapConfig, upstream *tlsv1.UpstreamTlsContext, authority string) (*tls.Config, error) {
	if bootstrap == nil {
		return nil, fmt.Errorf("bootstrap config is nil")
	}
	if upstream == nil {
		return nil, fmt.Errorf("upstream TLS context is nil")
	}
	certProvider, rootProvider, err := fileWatcherConfigsForUpstreamTLS(bootstrap, upstream)
	if err != nil {
		return nil, err
	}
	if certProvider.CertificateFile == "" || certProvider.PrivateKeyFile == "" {
		return nil, fmt.Errorf("data-plane mTLS requires certificate_file and private_key_file")
	}
	if rootProvider.CACertificateFile == "" {
		return nil, fmt.Errorf("data-plane mTLS requires ca_certificate_file")
	}

	cert, err := tls.LoadX509KeyPair(certProvider.CertificateFile, certProvider.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load data-plane client certificate/key: %w", err)
	}
	rootPEM, err := os.ReadFile(rootProvider.CACertificateFile)
	if err != nil {
		return nil, fmt.Errorf("read data-plane CA certificate %s: %w", rootProvider.CACertificateFile, err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, fmt.Errorf("parse data-plane CA certificate %s: no certificates found", rootProvider.CACertificateFile)
	}

	serverName := upstream.Sni
	if serverName == "" {
		serverName = hostOnly(authority)
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         serverName,
		Certificates:       []tls.Certificate{cert},
		RootCAs:            roots,
		InsecureSkipVerify: true, // VerifyPeerCertificate performs CA-chain validation for SPIFFE URI SAN certs.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifyPeerCertificateChain(rawCerts, roots, subjectAltNames(upstream))
		},
	}
	if common := upstream.GetCommonTlsContext(); common != nil {
		cfg.NextProtos = append([]string(nil), common.AlpnProtocols...)
	}
	return cfg, nil
}

func fileWatcherConfigsForUpstreamTLS(bootstrap *BootstrapConfig, upstream *tlsv1.UpstreamTlsContext) (FileWatcherCertConfig, FileWatcherCertConfig, error) {
	common := upstream.GetCommonTlsContext()
	certInstance := "default"
	rootInstance := "default"
	if common != nil {
		if cert := common.GetTlsCertificateCertificateProviderInstance(); cert != nil && cert.InstanceName != "" {
			certInstance = cert.InstanceName
		}
		if combined := common.GetCombinedValidationContext(); combined != nil {
			if root := combined.GetValidationContextCertificateProviderInstance(); root != nil && root.InstanceName != "" {
				rootInstance = root.InstanceName
			}
		}
	}

	certProvider, ok := bootstrap.CertProviders[certInstance]
	if !ok {
		return FileWatcherCertConfig{}, FileWatcherCertConfig{}, fmt.Errorf("certificate_providers[%q] not found", certInstance)
	}
	rootProvider, ok := bootstrap.CertProviders[rootInstance]
	if !ok {
		return FileWatcherCertConfig{}, FileWatcherCertConfig{}, fmt.Errorf("certificate_providers[%q] not found", rootInstance)
	}
	return certProvider, rootProvider, nil
}

func subjectAltNames(upstream *tlsv1.UpstreamTlsContext) []string {
	if upstream == nil || upstream.GetCommonTlsContext() == nil {
		return nil
	}
	combined := upstream.GetCommonTlsContext().GetCombinedValidationContext()
	if combined == nil || combined.GetDefaultValidationContext() == nil {
		return nil
	}
	return append([]string(nil), combined.GetDefaultValidationContext().GetMatchSubjectAltNames()...)
}

func verifyPeerCertificateChain(rawCerts [][]byte, roots *x509.CertPool, allowedSANs []string) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("peer presented no certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse intermediate certificate: %w", err)
		}
		intermediates.AddCert(cert)
	}
	if _, err = leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}); err != nil {
		return err
	}
	if len(allowedSANs) == 0 {
		return nil
	}
	for _, uri := range leaf.URIs {
		if containsString(allowedSANs, uri.String()) {
			return nil
		}
	}
	for _, dnsName := range leaf.DNSNames {
		if containsString(allowedSANs, dnsName) {
			return nil
		}
	}
	return fmt.Errorf("peer certificate SAN is not in CDS allowlist %v", allowedSANs)
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func hostOnly(authority string) string {
	if host, _, err := net.SplitHostPort(authority); err == nil {
		return host
	}
	return authority
}

func (c FileWatcherCertConfig) isZero() bool {
	return c.CertificateFile == "" && c.PrivateKeyFile == "" && c.CACertificateFile == ""
}

func dialClient(ctx context.Context, addr string, node *corev1.Node, opts ...grpc.DialOption) (*Client, error) {
	conn, err := grpc.DialContext(ctx, addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial xDS server %s: %w", addr, err)
	}

	svcClient := discovery.NewAggregatedDiscoveryServiceClient(conn)
	stream, err := svcClient.StreamAggregatedResources(ctx)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to open ADS stream: %w", err)
	}

	// If no node provided from bootstrap, build a minimal one from env vars
	if node == nil {
		node = buildNodeFromEnv()
	}

	log.Printf("[xds-client] ADS stream established to %s (node.id=%s)", addr, node.Id)
	return &Client{
		conn:   conn,
		stream: stream,
		client: svcClient,
		node:   node,
	}, nil
}

// buildNodeFromEnv builds a minimal Node from environment variables.
func buildNodeFromEnv() *corev1.Node {
	nodeType := "inherent"

	podIP := os.Getenv("POD_IP")
	if podIP == "" {
		podIP = "127.0.0.1"
	}

	podName := os.Getenv("POD_NAME")
	if podName == "" {
		podName = os.Getenv("HOSTNAME")
	}
	if podName == "" {
		podName = "grpc-consumer"
	}

	namespace := os.Getenv("POD_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}

	nodeIDStr := fmt.Sprintf("%s.%s", podName, namespace)
	domain := fmt.Sprintf("%s.svc.cluster.local", namespace)

	return &corev1.Node{
		Id: fmt.Sprintf("%s~%s~%s~%s", nodeType, podIP, nodeIDStr, domain),
	}
}

// Subscribe sends a DiscoveryRequest for the given typeURL and resource names.
func (c *Client) Subscribe(typeURL string, resourceNames []string) error {
	return c.stream.Send(&discovery.DiscoveryRequest{
		Node:          c.node,
		TypeUrl:       typeURL,
		ResourceNames: resourceNames,
	})
}

// Recv receives the next DiscoveryResponse from the ADS stream.
func (c *Client) Recv() (*discovery.DiscoveryResponse, error) {
	return c.stream.Recv()
}

// Ack acknowledges a received DiscoveryResponse.
func (c *Client) Ack(resp *discovery.DiscoveryResponse) error {
	return c.stream.Send(&discovery.DiscoveryRequest{
		Node:          c.node,
		TypeUrl:       resp.TypeUrl,
		VersionInfo:   resp.VersionInfo,
		ResponseNonce: resp.Nonce,
	})
}

// Close shuts down the ADS stream and underlying connection.
func (c *Client) Close() {
	c.conn.Close()
}
