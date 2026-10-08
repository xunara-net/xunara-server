package control

import (
	"fmt"

	"github.com/xunara-net/xunara-server/state"
)

// validateKeyTags normalises ACL tags for a pre-auth key and checks them
// against the tailnet's policy.
//
// A tag that the policy does not define in tagOwners could never match an ACL
// selector, so accepting it would hide a typo behind a silently useless key.
// Key creation is an administrative action, so ownership is not re-checked
// here; ownership binds the human who advertises tags from a device (see
// [Server.authorizedTags]).
func (s *Server) validateKeyTags(tags []string) ([]string, error) {
	normalized, err := state.NormalizeTags(tags)
	if err != nil {
		return nil, fmt.Errorf("control: each tag must look like tag:name (letters, digits and dashes)")
	}
	if len(normalized) == 0 {
		return nil, nil
	}

	engine := s.policy.Load()
	if engine == nil {
		return nil, fmt.Errorf("control: this tailnet has no ACL policy, so no tag is defined")
	}
	for _, tag := range normalized {
		if !engine.TagExists(tag) {
			return nil, fmt.Errorf("control: tag %s is not defined in the policy's tagOwners", tag)
		}
	}
	return normalized, nil
}
