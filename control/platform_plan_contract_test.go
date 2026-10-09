package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/xunara-net/xunara-server/plan"
)

func TestPlatformPlanViewPreservesRelayQuota(t *testing.T) {
	for _, limit := range []int{plan.Unlimited, 0, 7} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			value := plan.UnlimitedPlan()
			value.MaxRelays = limit
			if actual, exists := planView(value, false)["max_relays"]; !exists || actual != limit {
				t.Fatalf("relay quota = %v, present = %v, want %d", actual, exists, limit)
			}
		})
	}
}

func TestPlatformPlanCatalogReadWriteRetainsRelayQuota(t *testing.T) {
	registry, _ := newTestPlanRegistry(t, t.TempDir())
	server, err := New(Config{StateDir: t.TempDir(), ServerURL: "http://login.test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	router := newTestRouter(t, RouterConfig{
		Orgs:  []OrgSite{{ID: "acme", Name: "Acme", Server: server}},
		Plans: registry, PlatformAdminToken: "platform-test-token",
	})
	endpoint := httptest.NewServer(router.Handler())
	t.Cleanup(endpoint.Close)
	response := apiRequest(t, endpoint.Client(), http.MethodGet, endpoint.URL+"/api/platform/v1/plans", "platform-test-token", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("catalog status = %d", response.StatusCode)
	}
	var catalog struct {
		Plans []plan.Plan `json:"plans"`
	}
	decodeTestBody(t, response, &catalog)
	var selected plan.Plan
	for _, candidate := range catalog.Plans {
		if candidate.ID == plan.FreeID {
			selected = candidate
		}
	}
	if selected.ID == "" || selected.MaxRelays != 1 {
		t.Fatalf("default plan relay quota = %d, want 1", selected.MaxRelays)
	}
	// 编辑器只提交套餐数据，不把 default/device_allowance 等只读派生字段送回写接口。
	selected.Name = "Free edited"
	response = apiRequest(t, endpoint.Client(), http.MethodPost, endpoint.URL+"/api/platform/v1/plans", "platform-test-token", selected)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("save plan status = %d", response.StatusCode)
	}
	var saved plan.Plan
	decodeTestBody(t, response, &saved)
	if saved.MaxRelays != selected.MaxRelays || registry.Plan(context.Background(), "acme").MaxRelays != selected.MaxRelays {
		t.Fatal("read/write round trip erased the relay quota")
	}
}
