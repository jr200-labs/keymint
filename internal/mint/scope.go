package mint

import (
	"errors"
	"regexp"
	"slices"
	"sort"
)

type Scope struct {
	Repositories []string          `json:"repositories,omitempty"`
	Permissions  map[string]string `json:"permissions,omitempty"`
}

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func (scope Scope) Validate() error {
	if len(scope.Repositories) > 100 {
		return errors.New("token scope exceeds 100 repositories")
	}
	seen := map[string]bool{}
	for _, repository := range scope.Repositories {
		if !repositoryName.MatchString(repository) || seen[repository] {
			return errors.New("token scope contains an invalid or duplicate repository")
		}
		seen[repository] = true
	}
	for permission, access := range scope.Permissions {
		if !repositoryName.MatchString(permission) || !slices.Contains([]string{"read", "write", "admin", "triage", "maintain"}, access) {
			return errors.New("token scope contains an invalid permission")
		}
	}
	sort.Strings(scope.Repositories)
	return nil
}
