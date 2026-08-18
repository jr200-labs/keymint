package emergency

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	serviceAccountCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

type KubernetesIssuer struct {
	apiServer, bearer string
	http              *http.Client
}

func NewKubernetesIssuer() (*KubernetesIssuer, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("Kubernetes service environment is unavailable")
	}
	bearer, err := os.ReadFile(serviceAccountTokenPath)
	if err != nil {
		return nil, fmt.Errorf("read service account token: %w", err)
	}
	ca, err := os.ReadFile(serviceAccountCAPath)
	if err != nil {
		return nil, fmt.Errorf("read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("parse service account CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}}
	return &KubernetesIssuer{apiServer: "https://" + host + ":" + port, bearer: strings.TrimSpace(string(bearer)), http: &http.Client{Transport: transport, Timeout: 15 * time.Second}}, nil
}

func (issuer *KubernetesIssuer) Issue(ctx context.Context, namespace, serviceAccount string, ttl time.Duration, existingSecret string) (string, string, time.Time, error) {
	secret := existingSecret
	if secret == "" {
		name, err := randomKubernetesName()
		if err != nil {
			return "", "", time.Time{}, fmt.Errorf("create bound Secret name: %w", err)
		}
		secret = "keymint-emergency-" + name
		if err := issuer.createSecret(ctx, namespace, secret); err != nil {
			return "", "", time.Time{}, err
		}
	}
	uid, err := issuer.secretUID(ctx, namespace, secret)
	if err != nil {
		return "", secret, time.Time{}, err
	}
	seconds := int64(ttl.Seconds())
	// Kubernetes validates TokenRequest expirationSeconds with a 10-minute
	// minimum. The Secret binding still revokes it at the shorter session expiry.
	if seconds < 600 {
		seconds = 600
	}
	requestBody := map[string]any{
		"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
		"spec": map[string]any{
			"audiences":         []string{"https://kubernetes.default.svc"},
			"expirationSeconds": seconds,
			"boundObjectRef":    map[string]any{"apiVersion": "v1", "kind": "Secret", "name": secret, "uid": uid},
		},
	}
	var response struct {
		Status struct {
			Token               string    `json:"token"`
			ExpirationTimestamp time.Time `json:"expirationTimestamp"`
		} `json:"status"`
	}
	path := fmt.Sprintf("/api/v1/namespaces/%s/serviceaccounts/%s/token", namespace, serviceAccount)
	if err := issuer.request(ctx, http.MethodPost, path, requestBody, &response); err != nil {
		return "", secret, time.Time{}, fmt.Errorf("request Kubernetes emergency token: %w", err)
	}
	if response.Status.Token == "" {
		return "", secret, time.Time{}, errors.New("Kubernetes returned an empty token")
	}
	return response.Status.Token, secret, response.Status.ExpirationTimestamp, nil
}

func (issuer *KubernetesIssuer) Revoke(ctx context.Context, namespace, secret string) error {
	return issuer.request(ctx, http.MethodDelete, fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, secret), nil, nil)
}

func (issuer *KubernetesIssuer) createSecret(ctx context.Context, namespace, name string) error {
	body := map[string]any{"apiVersion": "v1", "kind": "Secret", "metadata": map[string]any{"name": name, "labels": map[string]string{"app.kubernetes.io/managed-by": "keymint"}}}
	return issuer.request(ctx, http.MethodPost, "/api/v1/namespaces/"+namespace+"/secrets", body, nil)
}

func (issuer *KubernetesIssuer) secretUID(ctx context.Context, namespace, name string) (string, error) {
	var response struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := issuer.request(ctx, http.MethodGet, fmt.Sprintf("/api/v1/namespaces/%s/secrets/%s", namespace, name), nil, &response); err != nil {
		return "", err
	}
	if response.Metadata.UID == "" {
		return "", errors.New("Kubernetes Secret has no UID")
	}
	return response.Metadata.UID, nil
}

func (issuer *KubernetesIssuer) request(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, issuer.apiServer+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+issuer.bearer)
	request.Header.Set("Content-Type", "application/json")
	response, err := issuer.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("Kubernetes returned %s: %s", response.Status, strings.TrimSpace(string(message)))
	}
	if output != nil {
		return json.NewDecoder(response.Body).Decode(output)
	}
	return nil
}

func randomKubernetesName() (string, error) {
	value := make([]byte, 9)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return strings.ToLower(base64.RawURLEncoding.EncodeToString(value)), nil
}
