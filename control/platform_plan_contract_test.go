package control

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/xunara-net/xunara-server/plan"
)

func TestPlatformPlanViewPreservesRelayQuota(test *testing.T) {
	for _, limit := range []int{plan.Unlimited, 0, 7} {
		test.Run(strconv.Itoa(limit), func(subtest *testing.T) {
			value := plan.UnlimitedPlan()
			value.MaxRelays = limit
			if actual, exists := planView(value, false)["max_relays"]; !exists || actual != limit {
				subtest.Fatalf("relay quota = %v, present = %v, want %d", actual, exists, limit)
			}
		})
	}
}

func TestPlatformPlanCatalogReadWriteRetainsRelayQuota(test *testing.T) {
	registry, _ := newTestPlanRegistry(test, test.TempDir())
	server, err := New(Config{StateDir: test.TempDir(), ServerURL: "http://login.test"})
	if err != nil {
		test.Fatalf("New: %v", err)
	}
	router := newTestRouter(test, RouterConfig{
		Orgs:  []OrgSite{{ID: "acme", Name: "Acme", Server: server}},
		Plans: registry, PlatformAdminToken: "platform-test-token",
	})
	endpoint := httptest.NewServer(router.Handler())
	test.Cleanup(endpoint.Close)
	response := apiRequest(test, endpoint.Client(), http.MethodGet, endpoint.URL+"/api/platform/v1/plans", "platform-test-token", nil)
	if response.StatusCode != http.StatusOK {
		test.Fatalf("catalog status = %d", response.StatusCode)
	}
	var catalog struct {
		Plans []plan.Plan `json:"plans"`
	}
	decodeTestBody(test, response, &catalog)
	var selected plan.Plan
	for _, candidate := range catalog.Plans {
		if candidate.ID == plan.FreeID {
			selected = candidate
		}
	}
	if selected.ID == "" || selected.MaxRelays != 1 {
		test.Fatalf("default plan relay quota = %d, want 1", selected.MaxRelays)
	}
	// 编辑器只提交套餐数据，不把 default/device_allowance 等只读派生字段送回写接口。
	selected.Name = "Free edited"
	response = apiRequest(test, endpoint.Client(), http.MethodPost, endpoint.URL+"/api/platform/v1/plans", "platform-test-token", selected)
	if response.StatusCode != http.StatusOK {
		test.Fatalf("save plan status = %d", response.StatusCode)
	}
	var saved plan.Plan
	decodeTestBody(test, response, &saved)
	if saved.MaxRelays != selected.MaxRelays || registry.Plan(context.Background(), "acme").MaxRelays != selected.MaxRelays {
		test.Fatal("read/write round trip erased the relay quota")
	}
}
