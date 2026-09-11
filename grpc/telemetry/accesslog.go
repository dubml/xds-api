// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package telemetry

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	collectorlogsv1 "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	defaultAccessLogQueueSize = 1024
	accessLogExportTimeout    = 3 * time.Second
	maxAccessLogFilterLength  = 1024
	maxAccessLogFilterTerms   = 32
	maxAccessLogTags          = 64
	maxAccessLogTagKeyLength  = 128
	maxAccessLogTagValueSize  = 4096
)

var (
	numericAccessLogFilterPattern = regexp.MustCompile(`^(response\.code|grpc\.status_code)\s*(==|!=|>=|<=|>|<)\s*([0-9]{1,3})$`)
	stringAccessLogFilterPattern  = regexp.MustCompile(`^(status|reporter)\s*(==|!=)\s*['"]([A-Za-z][A-Za-z0-9_.-]{0,127})['"]$`)
)

// loggingConfig is immutable after parsing and is atomically swapped on a
// projected Secret update.
type loggingConfig struct {
	rules []accessLogRule
}

type accessLogRule struct {
	endpoint   otlpEndpoint
	client     bool
	server     bool
	filter     accessLogFilter
	staticTags map[string]string
}

type otlpEndpoint struct {
	key        string
	target     string
	serverName string
	useTLS     bool
}

type accessLogRecord struct {
	endpoint   otlpEndpoint
	reporter   string
	service    string
	method     string
	status     codes.Code
	duration   time.Duration
	timestamp  time.Time
	staticTags map[string]string
}

type otlpLogExporter struct {
	conn   *grpc.ClientConn
	client collectorlogsv1.LogsServiceClient
}

// parseLoggingConfig accepts the runtime contract emitted by dubbod:
// telemetry.logging is an array because multiple independent logging rules can
// target different reporter sides and collectors.
func parseLoggingConfig(telemetry *runtimeTelemetryConfig) (loggingConfig, error) {
	if telemetry == nil || len(telemetry.Logging) == 0 {
		return loggingConfig{}, nil
	}

	config := loggingConfig{rules: make([]accessLogRule, 0, len(telemetry.Logging))}
	for index, raw := range telemetry.Logging {
		hasOTel, err := hasOTelLoggingProvider(raw.Providers)
		if err != nil {
			return loggingConfig{}, fmt.Errorf("logging[%d]: %w", index, err)
		}
		if !hasOTel {
			continue
		}

		client, server, err := parseAccessLogMode(raw.Mode)
		if err != nil {
			return loggingConfig{}, fmt.Errorf("logging[%d]: %w", index, err)
		}
		filter, err := compileAccessLogFilter(raw.FilterExpression)
		if err != nil {
			return loggingConfig{}, fmt.Errorf("logging[%d]: %w", index, err)
		}
		tags, err := validateAccessLogTags(raw.Tags)
		if err != nil {
			return loggingConfig{}, fmt.Errorf("logging[%d]: %w", index, err)
		}
		if raw.Disabled {
			continue
		}

		endpoint, err := parseOTLPEndpoint(raw.Endpoint)
		if err != nil {
			return loggingConfig{}, fmt.Errorf("logging[%d]: %w", index, err)
		}
		config.rules = append(config.rules, accessLogRule{
			endpoint:   endpoint,
			client:     client,
			server:     server,
			filter:     filter,
			staticTags: tags,
		})
	}
	return config, nil
}

func hasOTelLoggingProvider(providers []string) (bool, error) {
	found := false
	for _, provider := range providers {
		switch strings.TrimSpace(provider) {
		case "":
			continue
		case "otel":
			found = true
		default:
			return false, fmt.Errorf("unsupported logging provider %q", provider)
		}
	}
	return found, nil
}

func parseAccessLogMode(mode string) (bool, bool, error) {
	switch strings.TrimSpace(mode) {
	case "", "MODE_UNSPECIFIED", "CLIENT_AND_SERVER":
		return true, true, nil
	case "CLIENT":
		return true, false, nil
	case "SERVER":
		return false, true, nil
	default:
		return false, false, fmt.Errorf("unsupported logging mode %q", mode)
	}
}

func validateAccessLogTags(tags map[string]string) (map[string]string, error) {
	if len(tags) == 0 {
		return nil, nil
	}
	if len(tags) > maxAccessLogTags {
		return nil, fmt.Errorf("too many logging tags: %d exceeds %d", len(tags), maxAccessLogTags)
	}
	result := make(map[string]string, len(tags))
	for name, value := range tags {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" || trimmed != name {
			return nil, fmt.Errorf("invalid logging tag name %q", name)
		}
		if len(name) > maxAccessLogTagKeyLength || !utf8.ValidString(name) {
			return nil, fmt.Errorf("invalid logging tag name %q", name)
		}
		if len(value) > maxAccessLogTagValueSize || !utf8.ValidString(value) {
			return nil, fmt.Errorf("invalid value for logging tag %q", name)
		}
		if _, reserved := reservedAccessLogAttributes[name]; reserved {
			return nil, fmt.Errorf("logging tag %q overrides a reserved access log attribute", name)
		}
		result[name] = value
	}
	return result, nil
}

var reservedAccessLogAttributes = map[string]struct{}{
	"service":              {},
	"method":               {},
	"status":               {},
	"duration_ms":          {},
	"reporter":             {},
	"response.code":        {},
	"grpc.status_code":     {},
	"rpc.system":           {},
	"rpc.service":          {},
	"rpc.method":           {},
	"rpc.grpc.status_code": {},
}

func parseOTLPEndpoint(value string) (otlpEndpoint, error) {
	endpoint := strings.TrimSpace(value)
	if endpoint == "" {
		return otlpEndpoint{}, fmt.Errorf("OTLP logging endpoint is empty")
	}
	if strings.HasPrefix(endpoint, "dns:///") {
		if strings.TrimPrefix(endpoint, "dns:///") == "" {
			return otlpEndpoint{}, fmt.Errorf("invalid OTLP logging endpoint %q", value)
		}
		return otlpEndpoint{key: endpoint, target: endpoint}, nil
	}
	if !strings.Contains(endpoint, "://") {
		if _, _, err := net.SplitHostPort(endpoint); err != nil {
			return otlpEndpoint{}, fmt.Errorf("invalid OTLP logging endpoint %q: %w", value, err)
		}
		return otlpEndpoint{key: "http://" + endpoint, target: endpoint}, nil
	}

	parsed, err := url.ParseRequestURI(endpoint)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return otlpEndpoint{}, fmt.Errorf("invalid OTLP logging endpoint %q", value)
	}
	switch parsed.Scheme {
	case "http":
		return otlpEndpoint{key: endpoint, target: parsed.Host}, nil
	case "https":
		return otlpEndpoint{key: endpoint, target: parsed.Host, serverName: parsed.Hostname(), useTLS: true}, nil
	default:
		return otlpEndpoint{}, fmt.Errorf("unsupported OTLP logging endpoint scheme %q", parsed.Scheme)
	}
}

// Access-log filters intentionally support a small, non-executable CEL subset:
// numeric comparisons on response.code and grpc.status_code; string equality
// on status and reporter; and && / || combinations without parentheses.
func compileAccessLogFilter(expression string) (accessLogFilter, error) {
	expression = strings.TrimSpace(expression)
	if expression == "" {
		return accessLogFilter{}, nil
	}
	if len(expression) > maxAccessLogFilterLength {
		return accessLogFilter{}, fmt.Errorf("logging filter exceeds %d bytes", maxAccessLogFilterLength)
	}

	filter := accessLogFilter{}
	termCount := 0
	for _, orGroup := range strings.Split(expression, "||") {
		orGroup = strings.TrimSpace(orGroup)
		if orGroup == "" {
			return accessLogFilter{}, unsupportedAccessLogFilter(expression)
		}
		conjunction := make([]accessLogPredicate, 0, 1)
		for _, term := range strings.Split(orGroup, "&&") {
			predicate, err := parseAccessLogPredicate(strings.TrimSpace(term))
			if err != nil {
				return accessLogFilter{}, unsupportedAccessLogFilter(expression)
			}
			termCount++
			if termCount > maxAccessLogFilterTerms {
				return accessLogFilter{}, fmt.Errorf("logging filter has more than %d terms", maxAccessLogFilterTerms)
			}
			conjunction = append(conjunction, predicate)
		}
		filter.any = append(filter.any, conjunction)
	}
	return filter, nil
}

func unsupportedAccessLogFilter(expression string) error {
	return fmt.Errorf("unsupported logging filter %q; supported fields are response.code, grpc.status_code, status, and reporter", expression)
}

type accessLogFilter struct {
	any [][]accessLogPredicate
}

type accessLogPredicate struct {
	field    string
	operator string
	number   int
	text     string
}

func parseAccessLogPredicate(term string) (accessLogPredicate, error) {
	if matches := numericAccessLogFilterPattern.FindStringSubmatch(term); len(matches) != 0 {
		var value int
		if _, err := fmt.Sscanf(matches[3], "%d", &value); err != nil {
			return accessLogPredicate{}, err
		}
		return accessLogPredicate{field: matches[1], operator: matches[2], number: value}, nil
	}
	if matches := stringAccessLogFilterPattern.FindStringSubmatch(term); len(matches) != 0 {
		return accessLogPredicate{field: matches[1], operator: matches[2], text: matches[3]}, nil
	}
	return accessLogPredicate{}, fmt.Errorf("unsupported predicate")
}

func (f accessLogFilter) matches(record accessLogRecord) bool {
	if len(f.any) == 0 {
		return true
	}
	for _, conjunction := range f.any {
		matches := true
		for _, predicate := range conjunction {
			if !predicate.matches(record) {
				matches = false
				break
			}
		}
		if matches {
			return true
		}
	}
	return false
}

func (p accessLogPredicate) matches(record accessLogRecord) bool {
	switch p.field {
	case "response.code":
		return compareAccessLogNumbers(grpcStatusHTTPCode(record.status), p.number, p.operator)
	case "grpc.status_code":
		return compareAccessLogNumbers(int(record.status), p.number, p.operator)
	case "status":
		return compareAccessLogStrings(record.status.String(), p.text, p.operator)
	case "reporter":
		return compareAccessLogStrings(record.reporter, p.text, p.operator)
	default:
		return false
	}
}

func compareAccessLogNumbers(left, right int, operator string) bool {
	switch operator {
	case "==":
		return left == right
	case "!=":
		return left != right
	case ">":
		return left > right
	case ">=":
		return left >= right
	case "<":
		return left < right
	case "<=":
		return left <= right
	default:
		return false
	}
}

func compareAccessLogStrings(left, right, operator string) bool {
	switch operator {
	case "==":
		return left == right
	case "!=":
		return left != right
	default:
		return false
	}
}

// grpcStatusHTTPCode keeps response.code compatible with the HTTP-oriented
// access-log CEL examples while grpc.status_code exposes the native gRPC code.
func grpcStatusHTTPCode(code codes.Code) int {
	switch code {
	case codes.OK:
		return 200
	case codes.Canceled:
		return 499
	case codes.Unknown, codes.Internal, codes.DataLoss:
		return 500
	case codes.InvalidArgument, codes.FailedPrecondition, codes.OutOfRange:
		return 400
	case codes.DeadlineExceeded:
		return 504
	case codes.NotFound:
		return 404
	case codes.AlreadyExists, codes.Aborted:
		return 409
	case codes.PermissionDenied:
		return 403
	case codes.ResourceExhausted:
		return 429
	case codes.Unimplemented:
		return 501
	case codes.Unavailable:
		return 503
	case codes.Unauthenticated:
		return 401
	default:
		return 500
	}
}

func (r *Runtime) recordAccessLogs(config *loggingConfig, reporter, service, method string, code codes.Code, duration time.Duration) {
	if config == nil || len(config.rules) == 0 || r.accessLogClosed.Load() {
		return
	}
	for _, rule := range config.rules {
		if (reporter == "client" && !rule.client) || (reporter == "server" && !rule.server) {
			continue
		}
		record := accessLogRecord{
			endpoint:   rule.endpoint,
			reporter:   reporter,
			service:    service,
			method:     method,
			status:     code,
			duration:   duration,
			timestamp:  time.Now(),
			staticTags: rule.staticTags,
		}
		if !rule.filter.matches(record) || !r.startAccessLogExporter() {
			continue
		}
		select {
		case <-r.accessLogStop:
			return
		case r.accessLogQueue <- record:
		default:
			r.accessLogDropped.Add(1)
		}
	}
}

func (r *Runtime) startAccessLogExporter() bool {
	if r.accessLogClosed.Load() {
		return false
	}
	r.accessLogStart.Do(func() {
		if r.accessLogClosed.Load() {
			return
		}
		r.accessLogStarted.Store(true)
		go r.runAccessLogExporter()
	})
	return r.accessLogStarted.Load()
}

func (r *Runtime) runAccessLogExporter() {
	defer close(r.accessLogDone)
	for {
		select {
		case <-r.accessLogStop:
			return
		case record := <-r.accessLogQueue:
			r.exportAccessLog(record)
		}
	}
}

func (r *Runtime) exportAccessLog(record accessLogRecord) {
	exporter, err := r.accessLogExporter(record.endpoint)
	if err != nil {
		r.accessLogFailed.Add(1)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), accessLogExportTimeout)
	defer cancel()
	if _, err := exporter.client.Export(ctx, buildOTLPAccessLogRequest(record)); err != nil {
		r.accessLogFailed.Add(1)
	}
}

func (r *Runtime) accessLogExporter(endpoint otlpEndpoint) (*otlpLogExporter, error) {
	r.accessLogExportersMu.Lock()
	defer r.accessLogExportersMu.Unlock()
	if exporter := r.accessLogExporters[endpoint.key]; exporter != nil {
		return exporter, nil
	}

	transportCredentials := insecure.NewCredentials()
	if endpoint.useTLS {
		transportCredentials = credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: endpoint.serverName,
		})
	}
	connection, err := grpc.NewClient(endpoint.target, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		return nil, fmt.Errorf("dial OTLP logging endpoint %q: %w", endpoint.target, err)
	}
	exporter := &otlpLogExporter{
		conn:   connection,
		client: collectorlogsv1.NewLogsServiceClient(connection),
	}
	r.accessLogExporters[endpoint.key] = exporter
	return exporter, nil
}

func buildOTLPAccessLogRequest(record accessLogRecord) *collectorlogsv1.ExportLogsServiceRequest {
	attributes := []*commonv1.KeyValue{
		stringAccessLogAttribute("service", record.service),
		stringAccessLogAttribute("method", record.method),
		stringAccessLogAttribute("status", record.status.String()),
		doubleAccessLogAttribute("duration_ms", float64(record.duration)/float64(time.Millisecond)),
		stringAccessLogAttribute("reporter", record.reporter),
		intAccessLogAttribute("response.code", int64(grpcStatusHTTPCode(record.status))),
		intAccessLogAttribute("grpc.status_code", int64(record.status)),
		stringAccessLogAttribute("rpc.system", "grpc"),
		stringAccessLogAttribute("rpc.service", record.service),
		stringAccessLogAttribute("rpc.method", record.method),
		intAccessLogAttribute("rpc.grpc.status_code", int64(record.status)),
	}
	tagNames := make([]string, 0, len(record.staticTags))
	for name := range record.staticTags {
		tagNames = append(tagNames, name)
	}
	sort.Strings(tagNames)
	for _, name := range tagNames {
		attributes = append(attributes, stringAccessLogAttribute(name, record.staticTags[name]))
	}

	timestamp := uint64(record.timestamp.UnixNano())
	return &collectorlogsv1.ExportLogsServiceRequest{ResourceLogs: []*logsv1.ResourceLogs{{
		ScopeLogs: []*logsv1.ScopeLogs{{
			Scope: &commonv1.InstrumentationScope{Name: "github.com/dubml/xds-api/grpc/telemetry"},
			LogRecords: []*logsv1.LogRecord{{
				TimeUnixNano:         timestamp,
				ObservedTimeUnixNano: timestamp,
				SeverityNumber:       logsv1.SeverityNumber_SEVERITY_NUMBER_INFO,
				SeverityText:         "INFO",
				EventName:            "grpc.access",
				Body: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{
					StringValue: "grpc access log",
				}},
				Attributes: attributes,
			}},
		}},
	}}}
}

func stringAccessLogAttribute(key, value string) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: value}}}
}

func intAccessLogAttribute(key string, value int64) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: value}}}
}

func doubleAccessLogAttribute(key string, value float64) *commonv1.KeyValue {
	return &commonv1.KeyValue{Key: key, Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_DoubleValue{DoubleValue: value}}}
}

// Close stops the asynchronous OTLP log worker and closes its collector
// connections. Applications normally call it during process shutdown.
func (r *Runtime) Close() {
	if r == nil {
		return
	}
	r.accessLogStopOnce.Do(func() {
		r.accessLogClosed.Store(true)
		close(r.accessLogStop)
		if r.accessLogStarted.Load() {
			<-r.accessLogDone
		}
		r.accessLogExportersMu.Lock()
		defer r.accessLogExportersMu.Unlock()
		for key, exporter := range r.accessLogExporters {
			_ = exporter.conn.Close()
			delete(r.accessLogExporters, key)
		}
	})
}
