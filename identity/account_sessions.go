package identity

import "errors"

var ErrInvalidSessionRevocation = errors.New("identity: invalid session revocation selection")

type SessionRevocationMode string

const (
	RevokeOtherSessions SessionRevocationMode = "others"
	RevokeAllSessions   SessionRevocationMode = "all"
	RevokeSingleSession SessionRevocationMode = "one"
)

type SessionRevocation struct {
	Mode      SessionRevocationMode
	SessionID string
}

func (selection SessionRevocation) valid() bool {
	switch selection.Mode {
	case RevokeOtherSessions, RevokeAllSessions:
		return selection.SessionID == ""
	case RevokeSingleSession:
		return selection.SessionID != ""
	default:
		return false
	}
}
