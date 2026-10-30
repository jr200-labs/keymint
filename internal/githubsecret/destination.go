// Package githubsecret resolves Actions encryption keys from trusted GitHub
// endpoints. Callers select a target, never an encryption recipient.
package githubsecret

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/jr200-labs/keymint/internal/tracing"
)

type Scope string

const (
	Repository   Scope = "repository"
	Organization Scope = "organization"
)

func (scope Scope) Valid() bool { return scope == Repository || scope == Organization }

// Target retains the repository even for organization secrets: release policy
// authorizes a project, while Scope selects where its Actions secret is stored.
type Target struct {
	Owner      string `json:"github_owner"`
	Repository string `json:"github_repository"`
	Scope      Scope  `json:"secret_scope"`
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func (target Target) Canonical() (Target, error) {
	if target.Scope == "" {
		target.Scope = Repository // preserve requests from repository-only clients
	}
	if !target.Scope.Valid() || !identifier.MatchString(target.Owner) || !identifier.MatchString(target.Repository) ||
		target.Owner == "." || target.Owner == ".." || target.Repository == "." || target.Repository == ".." {
		return Target{}, errors.New("invalid Actions secret target")
	}
	return target, nil
}

type Destination struct {
	Target
	KeyID     string
	PublicKey string
}

// APIBase normalizes the trusted API authority, including an Enterprise path.
func APIBase(base string) (string, error) {
	if base == "" {
		base = "https://api.github.com"
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("Actions destination requires a trusted HTTPS API URL")
	}
	u.Host = strings.ToLower(u.Host)
	return strings.TrimRight(u.String(), "/"), nil
}

// Resolve authenticates the target-specific lookup and never follows redirects.
// Its result binds the selected scope, owner and project to the encryption key.
func Resolve(ctx context.Context, client *http.Client, base, token string, target Target) (Destination, error) {
	target, err := target.Canonical()
	if err != nil {
		return Destination{}, err
	}
	base, err = APIBase(base)
	if err != nil {
		return Destination{}, err
	}
	if client == nil {
		client = &http.Client{}
	}
	bounded := *client
	if bounded.Timeout == 0 {
		bounded.Timeout = 15 * time.Second
	}
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	path := "/orgs/" + url.PathEscape(target.Owner)
	if target.Scope == Repository {
		path = "/repos/" + url.PathEscape(target.Owner) + "/" + url.PathEscape(target.Repository)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path+"/actions/secrets/public-key", nil)
	if err != nil {
		return Destination{}, err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := tracing.HTTPClient(&bounded).Do(request)
	if err != nil {
		return Destination{}, fmt.Errorf("resolve Actions encryption key: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return Destination{}, fmt.Errorf("resolve Actions encryption key: HTTP %d", response.StatusCode)
	}
	var result struct {
		ID  string `json:"key_id"`
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8192)).Decode(&result); err != nil {
		return Destination{}, errors.New("invalid Actions encryption key response")
	}
	key, err := base64.StdEncoding.DecodeString(result.Key)
	if result.ID == "" || len(result.ID) > 128 || err != nil || len(key) != 32 {
		return Destination{}, errors.New("invalid Actions encryption key metadata")
	}
	return Destination{Target: target, KeyID: result.ID, PublicKey: result.Key}, nil
}
