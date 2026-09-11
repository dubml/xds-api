// Licensed to the Apache Software Foundation (ASF) under one or more
// contributor license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright ownership.
// The ASF licenses this file to You under the Apache License, Version 2.0.

package application

import (
	runtimetelemetry "github.com/dubml/xds-api/grpc/telemetry"
	"google.golang.org/grpc"
)

// NewServer creates an Inherent application server with runtime features,
// including Telemetry metrics, attached automatically.
func NewServer(options ...grpc.ServerOption) (*grpc.Server, error) {
	return runtimetelemetry.NewServer(options...)
}

// NewClient creates an Inherent application client with runtime features,
// including Telemetry metrics, attached automatically.
func NewClient(target string, options ...grpc.DialOption) (*grpc.ClientConn, error) {
	return runtimetelemetry.NewClient(target, options...)
}
