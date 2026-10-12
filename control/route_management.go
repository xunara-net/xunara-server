package control

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
)

const routeManagementLimit = 256
const routeOverviewLimit = 2048

type routeManagementNode struct {
	Machine  apiMachine `json:"machine"`
	Revision string     `json:"revision"`
}

type routeManagementLimits struct {
	MaxRoutes         int  `json:"max_routes"`
	AllowSubnetRouter bool `json:"allow_subnet_router"`
	AllowExitNode     bool `json:"allow_exit_node"`
}

type routeManagementView struct {
	routeManagementNode
	CSRFToken string                `json:"csrf_token"`
	CanManage bool                  `json:"can_manage"`
	Limits    routeManagementLimits `json:"limits"`
}

type routePlanDenied struct{ error }

var errRouteViewLarge = errors.New("route configuration exceeds the management view bound")

func (server *Server) routeManagementCapabilities(principal apiPrincipal, request *http.Request) (string, bool, routeManagementLimits) {
	entitlement := server.Plan()
	csrf := csrfTokenFor(server.accountSessionToken(request))
	if principal.Kind != "session" {
		csrf = ""
	}
	canManage := principal.Role.CanWrite() && principal.Scopes[identity.ScopeWrite] &&
		(principal.Kind == "session" || entitlement.AllowAPI)
	return csrf, canManage, routeManagementLimits{entitlement.MaxRoutes, entitlement.AllowSubnetRouter, entitlement.AllowExitNode}
}

func (server *Server) routeManagementNode(node state.Node) (routeManagementNode, error) {
	if len(node.ApprovedRoutes) > routeManagementLimit || len(node.AnnouncedRoutes()) > routeManagementLimit {
		return routeManagementNode{}, errRouteViewLarge
	}
	return routeManagementNode{server.apiMachineView(node), state.RouteApprovalRevision(node)}, nil
}

func (server *Server) handleAPIV2RouteConfiguration(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireScope(writer, request, identity.ScopeRead)
	if !ok {
		return
	}
	nodes, err := server.networkNodes(request.Context())
	if err != nil {
		server.writeRouteManagementError(writer, err)
		return
	}
	items := []routeManagementNode{}
	total := 0
	for _, node := range nodes {
		if len(node.ApprovedRoutes) == 0 && len(node.AnnouncedRoutes()) == 0 {
			continue
		}
		item, err := server.routeManagementNode(node)
		if err != nil {
			server.writeRouteManagementError(writer, err)
			return
		}
		total += len(node.ApprovedRoutes) + len(node.AnnouncedRoutes())
		if total > routeOverviewLimit {
			server.writeRouteManagementError(writer, errRouteViewLarge)
			return
		}
		items = append(items, item)
	}
	csrf, canManage, limits := server.routeManagementCapabilities(principal, request)
	writeJSON(writer, http.StatusOK, struct {
		Items     []routeManagementNode `json:"items"`
		CSRFToken string                `json:"csrf_token"`
		CanManage bool                  `json:"can_manage"`
		Limits    routeManagementLimits `json:"limits"`
	}{items, csrf, canManage, limits})
}

func (server *Server) handleAPIV2NodeRoutes(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	principal, ok := server.requireScope(writer, request, identity.ScopeRead)
	if !ok {
		return
	}
	node, err := server.networkConfig.RouteNode(request.Context(), chi.URLParam(request, "ref"))
	if err != nil {
		server.writeRouteManagementError(writer, err)
		return
	}
	item, err := server.routeManagementNode(node)
	if err != nil {
		server.writeRouteManagementError(writer, err)
		return
	}
	csrf, canManage, limits := server.routeManagementCapabilities(principal, request)
	writeJSON(writer, http.StatusOK, routeManagementView{item, csrf, canManage, limits})
}

func (server *Server) saveRouteApprovals(request *http.Request, reference string, update state.RouteApprovalUpdate, writerPrincipal apiPrincipal) (state.Node, error) {
	node, err := server.networkConfig.SaveNodeRoutes(request.Context(), reference, update, networkWriter(writerPrincipal),
		func(routes []netip.Prefix) error {
			if update.RequireAnnounced && len(routes) > routeManagementLimit {
				return errRouteViewLarge
			}
			if err := server.assertRouteApprovalAllowed(routes); err != nil {
				return routePlanDenied{err}
			}
			return nil
		})
	if err == nil {
		server.notifyWatchers()
	}
	return node, err
}

func (server *Server) handleAPIV2SaveNodeRoutes(writer http.ResponseWriter, request *http.Request) {
	principal, ok := server.requireNetworkWriter(writer, request)
	if !ok {
		return
	}
	var body struct {
		Revision  string   `json:"revision"`
		Approve   []string `json:"approve"`
		Unapprove []string `json:"unapprove"`
	}
	if !decodeAPIBody(writer, request, &body) {
		return
	}
	if len(body.Revision) != 64 || strings.Trim(body.Revision, "0123456789abcdef") != "" ||
		len(body.Approve)+len(body.Unapprove) > routeManagementLimit {
		writeAPIError(writer, http.StatusBadRequest, "ROUTES_INVALID: a current revision and a bounded change set are required")
		return
	}
	approve, err := parsePrefixes(body.Approve)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "ROUTES_INVALID: valid CIDR routes are required")
		return
	}
	unapprove, err := parsePrefixes(body.Unapprove)
	if err != nil {
		writeAPIError(writer, http.StatusBadRequest, "ROUTES_INVALID: valid CIDR routes are required")
		return
	}
	for _, prefix := range approve {
		for _, removed := range unapprove {
			if prefix == removed {
				writeAPIError(writer, http.StatusBadRequest, "ROUTES_INVALID: conflicting route actions")
				return
			}
		}
	}
	node, err := server.saveRouteApprovals(request, chi.URLParam(request, "ref"),
		state.RouteApprovalUpdate{Revision: body.Revision, Approve: approve, Unapprove: unapprove, RequireAnnounced: true, SnapshotLimit: routeManagementLimit}, principal)
	if err != nil {
		server.writeRouteManagementError(writer, err)
		return
	}
	item, err := server.routeManagementNode(node)
	if err != nil {
		server.writeRouteManagementError(writer, err)
		return
	}
	csrf, canManage, limits := server.routeManagementCapabilities(principal, request)
	writeJSON(writer, http.StatusOK, routeManagementView{item, csrf, canManage, limits})
}

func (server *Server) writeRouteManagementError(writer http.ResponseWriter, err error) {
	var denied routePlanDenied
	switch {
	case errors.Is(err, state.ErrRouteNodeNotFound):
		writeAPIError(writer, http.StatusNotFound, "ROUTE_DEVICE_NOT_FOUND: device not found")
	case errors.Is(err, state.ErrRouteConflict):
		writeAPIError(writer, http.StatusConflict, "ROUTES_CHANGED: route configuration changed; refresh and confirm again")
	case errors.Is(err, state.ErrRouteNotAnnounced):
		writeAPIError(writer, http.StatusConflict, "ROUTE_NOT_ANNOUNCED: new approval is no longer announced; refresh first")
	case errors.Is(err, errRouteViewLarge), errors.Is(err, state.ErrRouteSnapshotTooLarge):
		writeAPIError(writer, http.StatusRequestEntityTooLarge, "ROUTE_VIEW_TOO_LARGE: route configuration is too large; use bounded management operations")
	case errors.As(err, &denied):
		writeAPIError(writer, http.StatusForbidden, denied.Error())
	default:
		server.writeNetworkError(writer, err)
	}
}
