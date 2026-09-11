package resolver

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	clusterv1 "github.com/dubml/xds-api/cluster/v1"
	endpointv1 "github.com/dubml/xds-api/endpoint/v1"
	tlsv1 "github.com/dubml/xds-api/extensions/transport_sockets/tls/v1"
	listenerv1 "github.com/dubml/xds-api/listener/v1"
	routev1 "github.com/dubml/xds-api/route/v1"
	discovery "github.com/dubml/xds-api/service/discovery/v1"
	"google.golang.org/grpc/attributes"
	"google.golang.org/grpc/resolver"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	Scheme       = "xds"
	listenerType = "type.googleapis.com/listener.v1.Listener"
	routeType    = "type.googleapis.com/route.v1.RouteConfiguration"
	clusterType  = "type.googleapis.com/cluster.v1.Cluster"
	endpointType = "type.googleapis.com/endpoint.v1.ClusterLoadAssignment"
)

func init() {
	resolver.Register(&xdsResolverBuilder{})
}

type xdsResolverBuilder struct{}

func (*xdsResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	log.Printf("[xds-resolver] Building resolver for target: %+v", target)

	serviceName := strings.TrimPrefix(target.URL.Path, "/")
	if serviceName == "" {
		return nil, fmt.Errorf("invalid xDS target: empty service name")
	}

	bootstrapPath := os.Getenv("GRPC_XDS_BOOTSTRAP")
	if bootstrapPath == "" {
		return nil, fmt.Errorf("GRPC_XDS_BOOTSTRAP environment variable not set")
	}

	bootstrap, err := ParseBootstrap(bootstrapPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap: %w", err)
	}

	r := &xdsResolver{
		target:                serviceName,
		cc:                    cc,
		bootstrap:             bootstrap,
		closeCh:               make(chan struct{}),
		clusterWeights:        make(map[string]uint32),
		clusterAddrs:          make(map[string][]resolver.Address),
		clusterTLS:            make(map[string]*tlsv1.UpstreamTlsContext),
		clusterTLSFingerprint: make(map[string]string),
	}

	go r.watcher()
	return r, nil
}

func (*xdsResolverBuilder) Scheme() string { return Scheme }

type xdsResolver struct {
	target    string
	cc        resolver.ClientConn
	bootstrap *BootstrapConfig
	closeCh   chan struct{}
	mu        sync.Mutex
	client    *Client
	// cluster weight map from RDS: cluster_name -> weight
	clusterWeights map[string]uint32
	// cluster endpoint map from EDS: cluster_name -> []Address
	clusterAddrs    map[string][]resolver.Address
	pendingClusters []string
	// cluster TLS context from CDS: cluster_name -> UpstreamTlsContext (nil means plaintext)
	clusterTLS map[string]*tlsv1.UpstreamTlsContext
	// clusterTLSFingerprint tracks a stable string fingerprint of each cluster's TLS state.
	// Used to detect real TLS mode changes and avoid spurious EDS re-subscriptions.
	clusterTLSFingerprint map[string]string
}

func (r *xdsResolver) watcher() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client, err := NewClientWithBootstrap(ctx, r.bootstrap)
	if err != nil {
		log.Printf("[xds-resolver] Failed to connect to xDS server: %v", err)
		r.cc.ReportError(err)
		return
	}
	defer client.Close()

	r.mu.Lock()
	r.client = client
	r.mu.Unlock()

	listenerName := r.target
	if err := client.Subscribe(listenerType, []string{listenerName}); err != nil {
		log.Printf("[xds-resolver] Failed to subscribe to LDS: %v", err)
		r.cc.ReportError(err)
		return
	}
	log.Printf("[xds-resolver] Subscribed to LDS: %s", listenerName)

	for {
		select {
		case <-r.closeCh:
			log.Printf("[xds-resolver] Resolver closed")
			return
		default:
		}

		resp, err := client.Recv()
		if err != nil {
			log.Printf("[xds-resolver] Error receiving xDS response: %v", err)
			r.cc.ReportError(err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("[xds-resolver] Received response: TypeUrl=%s Resources=%d", resp.TypeUrl, len(resp.Resources))

		if err := client.Ack(resp); err != nil {
			log.Printf("[xds-resolver] Failed to ack: %v", err)
		}

		switch resp.TypeUrl {
		case listenerType:
			routeNames := extractRouteNamesFromLDS(resp)
			if len(routeNames) > 0 {
				log.Printf("[xds-resolver] LDS gave route names: %v", routeNames)
				if err := client.Subscribe(routeType, routeNames); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to RDS: %v", err)
				}
			} else {
				log.Printf("[xds-resolver] LDS gave no route names, falling back to direct CDS")
				clusterName := buildClusterName(r.target)
				r.clusterWeights[clusterName] = 1
				if err := client.Subscribe(clusterType, []string{clusterName}); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case routeType:
			// Extract clusters with weights from RDS.
			weights := extractClusterWeightsFromRDS(resp)
			if len(weights) > 0 {
				log.Printf("[xds-resolver] RDS gave cluster weights: %v", weights)
				r.mu.Lock()
				weightsChanged := !mapsEqual(r.clusterWeights, weights)
				r.clusterWeights = weights
				if weightsChanged {
					// Flush stale endpoint cache so old subset addresses are not reused.
					r.clusterAddrs = make(map[string][]resolver.Address)
				}
				r.mu.Unlock()
				clusters := make([]string, 0, len(weights))
				for c := range weights {
					clusters = append(clusters, c)
				}
				r.pendingClusters = clusters
				// Always re-subscribe to CDS so route-driven cluster changes are
				// observed after an RDS update.
				if err := client.Subscribe(clusterType, clusters); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to CDS: %v", err)
				}
			}

		case clusterType:
			// Parse TransportSocket from CDS and collect names of clusters that
			// were actually returned. An empty slice means the control plane sent
			// no matching resources.
			resolvedClusters, tlsChanged := r.updateClusterTLS(resp)

			var edsClusters []string
			switch {
			case len(resolvedClusters) > 0:
				// Normal path: CDS returned the requested subset clusters.
				edsClusters = resolvedClusters
			case len(r.clusterWeights) == 0:
				// No RDS weights at all — fall back to the plain default cluster.
				edsClusters = []string{buildClusterName(r.target)}
			default:
				// Skip EDS subscription when CDS returned no matching resources.
				// The next RDS push will re-trigger CDS subscription.
				log.Printf("[xds-resolver] CDS returned 0 matching clusters; "+
					"waiting for a route update (pending: %v)", r.pendingClusters)
				continue
			}
			// Re-subscribe on first resolution for a cluster, or when TLS changes.
			// Repeated identical CDS pushes still skip EDS to avoid SubConn churn.
			if tlsChanged || r.needsEndpointSubscription(edsClusters) {
				log.Printf("[xds-resolver] CDS requires EDS subscribe for: %v", edsClusters)
				if err := client.Subscribe(endpointType, edsClusters); err != nil {
					log.Printf("[xds-resolver] Failed to subscribe to EDS: %v", err)
				}
			} else {
				log.Printf("[xds-resolver] CDS received, TLS state unchanged, skipping EDS re-subscribe")
			}

		case endpointType:
			// Store endpoints per cluster.
			r.updateClusterAddrs(resp)
			// Build weighted address list and push with xds_weighted service config.
			// xds_weighted uses base.Balancer which deduplicates via AddressMapV2
			// using (Addr, Attributes) equality — so unique Attributes per slot
			// forces one SubConn per weighted slot even for repeated Addr values.
			addrs := r.buildWeightedAddresses()
			if len(addrs) > 0 {
				log.Printf("[xds-resolver] Updating %d weighted addresses for %s", len(addrs), r.target)
				state := resolver.State{
					Addresses:     addrs,
					ServiceConfig: r.cc.ParseServiceConfig(`{"loadBalancingConfig":[{"xds_weighted":{}}]}`),
				}
				if err := r.cc.UpdateState(state); err != nil {
					log.Printf("[xds-resolver] Failed to update state: %v", err)
				}
			}
		}
	}
}

// mapsEqual returns true when two weight maps have identical keys and values.
func mapsEqual(a, b map[string]uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// tlsFingerprint returns a stable string that uniquely identifies the TLS
// mode of an UpstreamTlsContext.  Two contexts with the same SNI and the same
// presence/absence of client-cert material are considered identical for the
// purpose of SubConn deduplication.
// Returns "" for plaintext (nil context).
func tlsFingerprint(ctx *tlsv1.UpstreamTlsContext) string {
	if ctx == nil {
		return ""
	}
	sni := ctx.Sni
	hasCert := ""
	if ctx.CommonTlsContext != nil && ctx.CommonTlsContext.TlsCertificateCertificateProviderInstance != nil {
		hasCert = ctx.CommonTlsContext.TlsCertificateCertificateProviderInstance.InstanceName
	}
	return fmt.Sprintf("mtls:sni=%s:cert=%s:sans=%s", sni, hasCert, strings.Join(subjectAltNames(ctx), ","))
}

// updateClusterTLS parses TransportSocket from a CDS response, stores the TLS
// context per cluster, and returns:
//   - the list of cluster names present in the response (empty = DR not yet created)
//   - whether any cluster's TLS state actually changed
func (r *xdsResolver) updateClusterTLS(resp *discovery.DiscoveryResponse) ([]string, bool) {
	var resolved []string
	tlsChanged := false
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, resource := range resp.Resources {
		c := &clusterv1.Cluster{}
		if err := proto.Unmarshal(resource.Value, c); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal Cluster: %v", err)
			continue
		}
		resolved = append(resolved, c.Name)
		var newTLS *tlsv1.UpstreamTlsContext
		if c.TransportSocket != nil {
			if typedConfig := c.TransportSocket.GetTypedConfig(); typedConfig != nil {
				upstreamTLS := &tlsv1.UpstreamTlsContext{}
				if err := anypb.UnmarshalTo(typedConfig, upstreamTLS, proto.UnmarshalOptions{}); err != nil {
					log.Printf("[xds-resolver] Cluster %s TransportSocket is not UpstreamTlsContext: %v", c.Name, err)
				} else {
					newTLS = upstreamTLS
					log.Printf("[xds-resolver] Cluster %s has mTLS TransportSocket (SNI=%s)", c.Name, upstreamTLS.Sni)
				}
			}
		}
		if newTLS == nil {
			log.Printf("[xds-resolver] Cluster %s has no TransportSocket (plaintext)", c.Name)
		}

		newFP := tlsFingerprint(newTLS)
		if r.clusterTLSFingerprint[c.Name] != newFP {
			log.Printf("[xds-resolver] Cluster %s TLS fingerprint changed: %q -> %q", c.Name, r.clusterTLSFingerprint[c.Name], newFP)
			r.clusterTLSFingerprint[c.Name] = newFP
			r.clusterTLS[c.Name] = newTLS
			tlsChanged = true
		}
	}

	// Publish to global index so consumer can query TLS config by target.
	globalTLSMu.Lock()
	if globalTLSIndex[r.target] == nil {
		globalTLSIndex[r.target] = make(map[string]*tlsv1.UpstreamTlsContext)
	}
	for k, v := range r.clusterTLS {
		globalTLSIndex[r.target][k] = v
	}
	globalTLSMu.Unlock()

	return resolved, tlsChanged
}

func (r *xdsResolver) needsEndpointSubscription(clusters []string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, cluster := range clusters {
		if _, found := r.clusterAddrs[cluster]; !found {
			return true
		}
	}
	return false
}

// TLSContextKey is the resolver.Address Attributes key used to carry the
// UpstreamTlsContext selected by CDS.
type TLSContextKey struct{}

// globalTLSIndex stores the latest TLS context per target URL for consumer lookup.
// Key: xds target service name (e.g. "provider.grpc-app.svc.cluster.local:7070")
// Value: map[clusterName]*UpstreamTlsContext
var (
	globalTLSMu    sync.RWMutex
	globalTLSIndex = map[string]map[string]*tlsv1.UpstreamTlsContext{}
)

// GetClusterTLSForTarget returns the UpstreamTlsContext for the given xDS target URL.
// Returns the first non-nil TLS context found across all clusters for that target,
// or nil if plaintext mode.
func GetClusterTLSForTarget(targetURL string) *tlsv1.UpstreamTlsContext {
	// Normalise: strip scheme prefix to get the service name used as resolver target.
	service := targetURL
	if idx := strings.Index(targetURL, ":///"); idx >= 0 {
		service = targetURL[idx+4:]
	}

	globalTLSMu.RLock()
	defer globalTLSMu.RUnlock()
	for target, clusters := range globalTLSIndex {
		if target == service || strings.HasSuffix(target, service) || strings.HasSuffix(service, target) {
			for _, ctx := range clusters {
				if ctx != nil {
					return ctx
				}
			}
		}
	}
	return nil
}

func (r *xdsResolver) updateClusterAddrs(resp *discovery.DiscoveryResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, resource := range resp.Resources {
		cla := &endpointv1.ClusterLoadAssignment{}
		if err := proto.Unmarshal(resource.Value, cla); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal ClusterLoadAssignment: %v", err)
			continue
		}
		var addrs []resolver.Address
		for _, localityEp := range cla.Endpoints {
			for _, lbEp := range localityEp.LbEndpoints {
				if lbEp.GetEndpoint() == nil {
					continue
				}
				endpoint := lbEp.GetEndpoint()
				if endpoint.Address == nil {
					continue
				}
				socketAddr := endpoint.Address.GetSocketAddress()
				if socketAddr == nil {
					continue
				}
				addr := socketAddr.Address
				port := socketAddr.GetPortValue()
				if addr != "" && port > 0 {
					addrs = append(addrs, resolver.Address{Addr: fmt.Sprintf("%s:%d", addr, port)})
				}
			}
		}
		log.Printf("[xds-resolver] Cluster %s has %d endpoints", cla.ClusterName, len(addrs))
		r.clusterAddrs[cla.ClusterName] = addrs
	}
}

// slotSeqKey is combined with weightAttrKey in Attributes to give each
// weighted slot a unique identity so AddressMapV2 creates distinct SubConns.
type slotSeqKey struct{}

// tlsFingerprintKey stores a stable string fingerprint of the TLS mode in
// Attributes so AddressMapV2 can compare addresses without pointer equality.
// Using a string (not *UpstreamTlsContext pointer) means the same TLS config
// produces the same Attributes.Equal() result across multiple CDS pushes,
// preventing spurious SubConn churn.
type tlsFingerprintKey struct{}

// buildWeightedAddresses builds a flat address list where each cluster's
// physical address appears once per slot, with Attributes carrying the
// normalised weight AND a unique sequence number.
//
// base.Balancer (used by xds_weighted) deduplicates via AddressMapV2 which
// keys on {Addr, ServerName} then checks Attributes.Equal(). The unique
// slotSeqKey ensures every slot is treated as a distinct SubConn even when
// multiple slots share the same Addr.  The picker reads weightAttrKey to
// expand picks proportionally.
func (r *xdsResolver) buildWeightedAddresses() []resolver.Address {
	if len(r.clusterAddrs) == 0 {
		return nil
	}

	// No weight info — return all addresses with weight=1.
	if len(r.clusterWeights) == 0 {
		var addrs []resolver.Address
		for cluster, clusterAddrs := range r.clusterAddrs {
			for i, a := range clusterAddrs {
				attrs := attributes.New(weightAttrKey{}, uint32(1)).WithValue(slotSeqKey{}, uint32(i))
				tlsCtx := r.clusterTLS[cluster]
				if tlsCtx != nil {
					attrs = attrs.
						WithValue(TLSContextKey{}, tlsCtx).
						WithValue(tlsFingerprintKey{}, r.clusterTLSFingerprint[cluster])
				}
				a.Attributes = attrs
				addrs = append(addrs, a)
			}
		}
		return addrs
	}

	// Normalise weights via GCD so we don't create excessive picker slots.
	weightSlice := make([]uint32, 0, len(r.clusterWeights))
	for _, w := range r.clusterWeights {
		weightSlice = append(weightSlice, w)
	}
	g := weightSlice[0]
	for _, w := range weightSlice[1:] {
		g = gcd(g, w)
	}
	if g == 0 {
		g = 1
	}

	seq := uint32(0)
	var addrs []resolver.Address
	for cluster, weight := range r.clusterWeights {
		clusterAddrs, ok := r.clusterAddrs[cluster]
		if !ok || len(clusterAddrs) == 0 {
			continue
		}
		normWeight := weight / g
		if normWeight == 0 {
			normWeight = 1
		}
		log.Printf("[xds-resolver] cluster=%s weight=%d normWeight=%d endpoints=%d",
			cluster, weight, normWeight, len(clusterAddrs))

		for _, a := range clusterAddrs {
			// Unique Attributes per slot: weight for the picker, seq for
			// AddressMapV2 dedup so each slot gets its own SubConn.
			// TLSContextKey is also stored in Attributes (NOT BalancerAttributes)
			// because gRPC transport only passes addr.Attributes into the
			// ClientHandshakeInfo context (see internal/transport/http2_client.go).
			// tlsFingerprintKey stores a stable string so Attributes.Equal()
			// returns true across CDS pushes with the same TLS mode, preventing
			// spurious SubConn recreation.
			attrs := attributes.New(weightAttrKey{}, normWeight).WithValue(slotSeqKey{}, seq)
			tlsCtx := r.clusterTLS[cluster]
			if tlsCtx != nil {
				attrs = attrs.
					WithValue(TLSContextKey{}, tlsCtx).
					WithValue(tlsFingerprintKey{}, r.clusterTLSFingerprint[cluster])
			}
			a.Attributes = attrs
			seq++
			addrs = append(addrs, a)
		}
	}
	return addrs
}

func gcd(a, b uint32) uint32 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// extractRouteNamesFromLDS extracts RDS route config names from LDS response.
func extractRouteNamesFromLDS(resp *discovery.DiscoveryResponse) []string {
	var routeNames []string
	for _, resource := range resp.Resources {
		lis := &listenerv1.Listener{}
		if err := proto.Unmarshal(resource.Value, lis); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal Listener: %v", err)
			continue
		}
		if lis.ApiListener == nil || lis.ApiListener.ApiListener == nil {
			continue
		}
		hcmBytes := lis.ApiListener.ApiListener.Value
		if name := extractRouteNameFromHCM(hcmBytes); name != "" {
			routeNames = append(routeNames, name)
		}
	}
	return routeNames
}

// extractRouteNameFromHCM scans HCM bytes for the route config name.
func extractRouteNameFromHCM(data []byte) string {
	s := string(data)
	const prefix = "outbound|"
	if idx := strings.Index(s, prefix); idx >= 0 {
		end := idx
		for end < len(s) && s[end] >= ' ' && s[end] <= '~' {
			end++
		}
		name := s[idx:end]
		parts := strings.Split(name, "|")
		if len(parts) == 4 && parts[0] == "outbound" {
			return name
		}
	}
	return ""
}

// extractClusterWeightsFromRDS extracts cluster names and their weights from RDS response.
func extractClusterWeightsFromRDS(resp *discovery.DiscoveryResponse) map[string]uint32 {
	weights := make(map[string]uint32)
	for _, resource := range resp.Resources {
		rc := &routev1.RouteConfiguration{}
		if err := proto.Unmarshal(resource.Value, rc); err != nil {
			log.Printf("[xds-resolver] Failed to unmarshal RouteConfiguration: %v", err)
			continue
		}
		log.Printf("[xds-resolver] RouteConfiguration: name=%s, virtual_hosts=%d", rc.Name, len(rc.VirtualHosts))
		for _, vh := range rc.VirtualHosts {
			for _, route := range vh.Routes {
				if route.GetRoute() == nil {
					continue
				}
				action := route.GetRoute()
				if c := action.GetCluster(); c != "" {
					weights[c] = 1
				}
				if wc := action.GetWeightedClusters(); wc != nil {
					for _, cw := range wc.Clusters {
						if cw.Name != "" {
							w := uint32(1)
							if cw.Weight != nil {
								w = cw.Weight.GetValue()
							}
							weights[cw.Name] = w
							log.Printf("[xds-resolver] cluster=%s weight=%d", cw.Name, w)
						}
					}
				}
			}
		}
	}
	return weights
}

// buildClusterName converts xds target (host:port) to Dubbo cluster name format.
func buildClusterName(target string) string {
	host := target
	port := ""
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		host = target[:idx]
		port = target[idx+1:]
	}
	if port == "" {
		return target
	}
	return fmt.Sprintf("outbound|%s||%s", port, host)
}

func (r *xdsResolver) ResolveNow(resolver.ResolveNowOptions) {
	log.Printf("[xds-resolver] ResolveNow called for %s", r.target)
}

func (r *xdsResolver) Close() {
	log.Printf("[xds-resolver] Closing resolver for %s", r.target)
	close(r.closeCh)
}
