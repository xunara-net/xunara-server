package control

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

type deviceShareView struct {
	shareView
	Available bool   `json:"available"`
	CanDecide bool   `json:"can_decide"`
	CanRevoke bool   `json:"can_revoke"`
	IPv4      string `json:"ipv4,omitempty"`
	IPv6      string `json:"ipv6,omitempty"`
	DNSName   string `json:"dns_name,omitempty"`
	Online    bool   `json:"online"`
}

func (s *Server) requireDeviceShareSession(w http.ResponseWriter, r *http.Request, write bool) (apiPrincipal, bool) {
	principal, ok := s.requireAccountSession(w, r, write)
	if !ok {
		return apiPrincipal{}, false
	}
	if err := authorizeScope(principal, identity.ScopeRead); err != nil {
		writeAPIError(w, http.StatusForbidden, err.Error())
		return apiPrincipal{}, false
	}
	return principal, true
}

func (s *Server) deviceShareView(share Share, actor apiPrincipal) (deviceShareView, error) {
	direction := s.shareDirection(share)
	view := deviceShareView{shareView: s.shareView(share, direction)}
	source, _, node, bound := s.boundShareParties(share)
	view.Available = bound && !node.Expired(time.Now()) && !node.NodeKey.IsZero() && !node.MachineKey.IsZero()
	view.CanDecide = direction == "incoming" && share.Status == SharePending && view.Available && s.callerMatchesShare(share, actor)
	view.CanRevoke = share.Active() && ((direction == "outgoing" && actor.Role.CanWrite()) || (direction == "incoming" && s.callerMatchesShare(share, actor)))
	if direction == "incoming" && share.Status == ShareAccepted && view.Available {
		// 只返回接收网络中的投影地址，真实内网 IP 不跨租户进入 Web API。
		ipv4, ipv6, err := s.store.EnsureShareAddress(share.SourceOrg, shareNodeKey(node))
		if err != nil {
			return deviceShareView{}, err
		}
		if ipv4.IsValid() {
			view.IPv4 = ipv4.String()
		}
		if ipv6.IsValid() {
			view.IPv6 = ipv6.String()
		}
		if s.networkDomain() != "" {
			view.DNSName = shareHostname(strings.TrimSuffix(node.FQDN(""), "."), share.SourceOrg) + "." + strings.Trim(s.networkDomain(), ".")
		}
		view.Online = source.ShareOnline(node.ID)
	}
	return view, nil
}

func (s *Server) handleAPIDeviceShares(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireDeviceShareSession(w, r, false)
	if !ok {
		return
	}
	items := make([]deviceShareView, 0)
	if s.sharingEnabled() {
		filters := []ShareFilter{{TargetOrg: s.Organization().ID, TargetKind: ShareTargetAccount, TargetAccount: int64(actor.UserID)}}
		if actor.Role.CanWrite() {
			filters = append(filters, ShareFilter{SourceOrg: s.Organization().ID, TargetKind: ShareTargetAccount})
		}
		for _, filter := range filters {
			shares, err := s.shares.QueryShares(r.Context(), filter)
			if err != nil {
				writeDeviceShareError(w, err)
				return
			}
			for _, share := range shares {
				if s.shareDirection(share) == "outgoing" {
					if share.SourceGeneration != s.ShareGeneration() {
						continue
					}
				} else if !s.callerMatchesShare(share, actor) {
					continue
				}
				view, err := s.deviceShareView(share, actor)
				if err != nil {
					writeDeviceShareError(w, err)
					return
				}
				items = append(items, view)
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": s.sharingEnabled(), "can_manage": s.sharingEnabled() && actor.Role.CanWrite() && !s.ShareTKAEnabled(),
		"tailnet_locked": s.ShareTKAEnabled(), "csrf_token": csrfTokenFor(s.accountSessionToken(r)), "items": items})
}

func validShareLogin(login string) bool {
	return login != "" && len(login) <= 128 && !strings.ContainsFunc(login, func(character rune) bool { return unicode.IsControl(character) || unicode.IsSpace(character) })
}

func (s *Server) prepareAccountShare(ctx context.Context, actor apiPrincipal, reference, login string) (Share, error) {
	if !s.sharingEnabled() {
		return Share{}, errShareDisabled
	}
	directory, ok := s.shareDir.(AccountShareDirectory)
	if !ok {
		return Share{}, errShareDisabled
	}
	login = strings.TrimSpace(login)
	if !validShareLogin(login) {
		return Share{}, errShareAccountUnknown
	}
	node, ok := s.lookupAPINode(reference)
	if !ok {
		return Share{}, errShareNodeUnknown
	}
	target, recipient, err := directory.ResolveShareAccount(ctx, login)
	if err != nil {
		return Share{}, err
	}
	if target.Organization().ID == s.Organization().ID {
		return Share{}, errShareSelf
	}
	if s.ShareTKAEnabled() || target.ShareTKAEnabled() {
		return Share{}, errShareTKA
	}
	creator, err := s.identity.LookupUser(ctx, actor.UserID)
	if err != nil {
		return Share{}, err
	}
	share := Share{SourceOrg: s.Organization().ID, SourceNode: int64(node.ID), SourceGeneration: s.ShareGeneration(), SourceStableID: node.StableID,
		CreatedBy: int64(actor.UserID), SourceUserCreated: creator.CreatedAt.UnixNano(), TargetOrg: target.Organization().ID, TargetGeneration: target.ShareGeneration(),
		TargetKind: ShareTargetAccount, TargetAccount: int64(recipient.ID), TargetAccountCreated: recipient.CreatedAt.UnixNano()}
	if _, _, _, bound := s.boundShareParties(share); !bound || node.Expired(time.Now()) || node.NodeKey.IsZero() || node.MachineKey.IsZero() {
		return Share{}, errShareUnavailable
	}
	return share, nil
}

// 持有人类身份库写锁直到分享事务完成；不在锁内调用同库的布尔查询或审计。
func (s *Server) withShareActor(ctx context.Context, actor apiPrincipal, writer bool, change func() (Share, error)) (Share, error) {
	store, ok := s.store.(*state.SQLiteStore)
	if !ok || actor.Kind != "session" {
		return Share{}, errShareForbidden
	}
	transaction, err := store.DB().BeginTx(ctx, nil)
	if err != nil {
		return Share{}, err
	}
	defer transaction.Rollback()
	if err := identity.CheckAccountSession(ctx, transaction, actor.UserID, actor.Session.ID, time.Now()); err != nil {
		return Share{}, err
	}
	if writer {
		if err := identity.CheckNetworkWriter(ctx, transaction, actor.UserID, actor.Session.ID, "", time.Now()); err != nil {
			return Share{}, err
		}
	}
	return change()
}

func (s *Server) handleAPICreateDeviceShare(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireDeviceShareSession(w, r, true)
	if !ok {
		return
	}
	if !actor.Role.CanWrite() {
		writeDeviceShareError(w, errShareForbidden)
		return
	}
	var body struct {
		Node           string `json:"node"`
		RecipientLogin string `json:"recipient_login"`
	}
	if !decodeAPIBody(w, r, &body) {
		return
	}
	allowed, retry, err := s.store.AllowRate("device-share:"+actor.actor(), 20, time.Hour, time.Now())
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	if !allowed {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "SHARE_RATE_LIMITED: wait before sending more invitations", "retry_after": int(retry.Seconds()) + 1})
		return
	}
	prepared, err := s.prepareAccountShare(r.Context(), actor, body.Node, body.RecipientLogin)
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	share, err := s.withShareActor(r.Context(), actor, true, func() (Share, error) { return s.shares.CreateShare(r.Context(), prepared, time.Now()) })
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	s.audit(actor.actor(), identity.AuditShareCreated, shareTarget(share), "account-targeted device invitation created")
	s.notifyShareParties(share)
	s.writeDeviceShare(w, http.StatusCreated, share, actor)
}

func (s *Server) handleAPIAcceptDeviceShare(w http.ResponseWriter, r *http.Request) {
	s.changeDeviceShare(w, r, ShareAccepted)
}
func (s *Server) handleAPIRejectDeviceShare(w http.ResponseWriter, r *http.Request) {
	s.changeDeviceShare(w, r, ShareRejected)
}
func (s *Server) handleAPIRevokeDeviceShare(w http.ResponseWriter, r *http.Request) {
	s.changeDeviceShare(w, r, ShareRevoked)
}

func (s *Server) changeDeviceShare(w http.ResponseWriter, r *http.Request, status string) {
	actor, ok := s.requireDeviceShareSession(w, r, true)
	if !ok {
		return
	}
	if !s.sharingEnabled() {
		writeDeviceShareError(w, errShareDisabled)
		return
	}
	share, err := s.shares.LookupShare(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	if share.TargetKind != ShareTargetAccount {
		writeDeviceShareError(w, errShareNotMine)
		return
	}
	writer := share.SourceOrg == s.Organization().ID && share.SourceGeneration == s.ShareGeneration()
	if writer {
		if status != ShareRevoked || !actor.Role.CanWrite() {
			writeDeviceShareError(w, errShareNotMine)
			return
		}
	} else if share.TargetOrg != s.Organization().ID || !s.callerMatchesShare(share, actor) {
		writeDeviceShareError(w, errShareNotMine)
		return
	}
	if status == ShareAccepted {
		if _, _, node, bound := s.boundShareParties(share); !bound || node.Expired(time.Now()) {
			writeDeviceShareError(w, errShareUnavailable)
			return
		}
	}
	updated, err := s.withShareActor(r.Context(), actor, writer, func() (Share, error) {
		return s.shares.ChangeShare(r.Context(), share.ID, s.Organization().ID, int64(actor.UserID), status, time.Now())
	})
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	action := map[string]string{ShareAccepted: identity.AuditShareAccepted, ShareRejected: identity.AuditShareRejected, ShareRevoked: identity.AuditShareRevoked}[status]
	if share.Status != updated.Status {
		s.audit(actor.actor(), action, shareTarget(updated), "account-targeted device share "+status)
	}
	s.notifyShareParties(updated)
	s.writeDeviceShare(w, http.StatusOK, updated, actor)
}

func (s *Server) writeDeviceShare(w http.ResponseWriter, code int, share Share, actor apiPrincipal) {
	view, err := s.deviceShareView(share, actor)
	if err != nil {
		writeDeviceShareError(w, err)
		return
	}
	writeJSON(w, code, view)
}

func writeDeviceShareError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errShareForbidden), errors.Is(err, identity.ErrNetworkWriterForbidden):
		writeAPIError(w, http.StatusForbidden, "SHARE_FORBIDDEN: network administration or human session required")
	case errors.Is(err, identity.ErrSessionRevoked):
		writeAPIError(w, http.StatusUnauthorized, "SESSION_CHANGED: log in again before managing shares")
	case errors.Is(err, errShareDisabled):
		writeAPIError(w, http.StatusNotFound, "SHARING_DISABLED: platform sharing is not enabled")
	case errors.Is(err, errShareNodeUnknown), errors.Is(err, errShareNotMine), errors.Is(err, ErrShareNotFound), errors.Is(err, ErrShareTarget):
		writeAPIError(w, http.StatusNotFound, "SHARE_NOT_FOUND: share or device not found")
	case errors.Is(err, errShareAccountUnknown):
		writeAPIError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, errShareSelf):
		writeAPIError(w, http.StatusBadRequest, "SHARE_SAME_NETWORK: members of this network use its access policy; choose an account in another network")
	case errors.Is(err, ErrShareExists):
		writeAPIError(w, http.StatusConflict, "SHARE_EXISTS: an active invitation already exists for this device and account")
	case errors.Is(err, ErrShareState):
		writeAPIError(w, http.StatusConflict, "SHARE_CHANGED: invitation changed; refresh before retrying")
	case errors.Is(err, errShareTKA):
		writeAPIError(w, http.StatusConflict, "SHARE_TAILNET_LOCKED: sharing is unavailable with tailnet lock enabled")
	case errors.Is(err, errShareUnavailable):
		writeAPIError(w, http.StatusConflict, err.Error())
	default:
		writeAPIError(w, http.StatusServiceUnavailable, "SHARES_UNAVAILABLE: could not confirm sharing; refresh before retrying")
	}
}
