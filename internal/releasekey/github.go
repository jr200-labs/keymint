package releasekey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// GitHubDestination obtains the encryption key from the authenticated repository
// endpoint. Callers cannot select the encryption recipient through API input.
func GitHubDestination(ctx context.Context, client *http.Client, base, token, owner, repository string) (Destination, error) {
	if base == "" {
		base = "https://api.github.com"
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Destination{}, errors.New("GitHub destination requires a trusted HTTPS API URL")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	// Never follow redirects with repository authentication or silently change
	// the authority from which the destination key is obtained.
	bounded := *client
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	request, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repository)+"/actions/secrets/public-key", nil)
	if err != nil {
		return Destination{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := bounded.Do(request)
	if err != nil {
		return Destination{}, fmt.Errorf("resolve repository encryption key: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Destination{}, fmt.Errorf("resolve repository encryption key: HTTP %d", response.StatusCode)
	}
	var result struct {
		ID  string `json:"key_id"`
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&result); err != nil {
		return Destination{}, errors.New("invalid repository encryption key response")
	}
	return Destination{KeyID: result.ID, PublicKey: result.Key}, nil
}
