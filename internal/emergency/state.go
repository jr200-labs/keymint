package emergency

import (
	"context"
	"errors"
	"fmt"
)

type operation string

const (
	idle     operation = ""
	polling  operation = "polling"
	issuing  operation = "issuing"
	revoking operation = "revoking"
)
const RevocationPending State = "revocation_pending"

func terminal(state State) bool { return state == Revoked || state == Expired || state == Invalidated }
func transitionAllowed(from, to State) bool {
	if terminal(from) {
		return from == to
	}
	switch to {
	case Active:
		return from == AwaitingGitHub || from == AwaitingTOTP || from == AwaitingPasskey
	case RevocationPending:
		return from == Active || from == AwaitingGitHub || from == AwaitingTOTP || from == AwaitingPasskey || from == RevocationPending
	case Revoked, Expired, Invalidated:
		return true
	default:
		return false
	}
}
func eventFor(state State) string {
	switch state {
	case Active:
		return "session.activated"
	case RevocationPending:
		return "session.revocation_pending"
	case Revoked:
		return "session.revoked"
	case Expired:
		return "session.expired"
	case Invalidated:
		return "session.invalidated"
	}
	return ""
}

// transitionLocked is the only publication point for lifecycle changes. Granting
// authority requires durable audit first; withdrawing authority fails closed
// even when storage is unavailable and the caller must retry its event.
func (service *Service) transitionLocked(ctx context.Context, session *Session, state State, event string) error {
	if !transitionAllowed(session.State, state) || eventFor(state) != event {
		return fmt.Errorf("invalid session transition %s -> %s", session.State, state)
	}
	copy := *session
	copy.State = state
	err := service.record(ctx, event, &copy)
	if err == nil || state != Active {
		session.State = state
	}
	return err
}

// beginOperation serializes side effects for one session, without holding the
// global registry lock across network I/O. It returns with mu held, matching the
// handler's short validation/update sections. All exits must unlock mu before
// calling release. Waiting for another operation respects cancellation.
func (service *Service) beginOperation(ctx context.Context, subject, id string, op operation) (*Session, func(), error) {
	service.mu.Lock()
	session, err := service.ownedSession(subject, id)
	if err != nil || service.closed {
		service.mu.Unlock()
		return nil, nil, errors.New("emergency session is unavailable")
	}
	if session.gate == nil {
		session.gate = make(chan struct{}, 1)
	}
	gate := session.gate
	service.mu.Unlock()
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	service.mu.Lock()
	if service.sessions[id] != session || service.closed {
		service.mu.Unlock()
		<-gate
		return nil, nil, errors.New("emergency session changed while waiting")
	}
	session.operation = op
	return session, func() { service.mu.Lock(); session.operation = idle; service.mu.Unlock(); <-gate }, nil
}
