// Package kubehttp provides the shared in-cluster Kubernetes HTTP transport.
package kubehttp

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"time"
)

func Transport(rootCAs *x509.CertPool) *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			MinVersion: tls.VersionTLS12,
		},
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   20,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
}
