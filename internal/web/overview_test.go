package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// fakeStats stands in for Docker's usage readings.
type fakeStats struct {
	mu      sync.Mutex
	managed []node.Managed
	stats   map[string]node.ContainerStats
}

func (f *fakeStats) ListManaged(context.Context) ([]node.Managed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]node.Managed(nil), f.managed...), nil
}

func (f *fakeStats) ContainerStats(_ context.Context, id string) (node.ContainerStats, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats[id], nil
}

func (f *fakeStats) DiskUsage(context.Context) (node.DiskUsage, error) {
	return node.DiskUsage{}, nil
}

func (f *fakeStats) ReclaimDisk(context.Context) (node.Reclaimed, error) {
	return node.Reclaimed{}, nil
}

// runningWeb makes the lab's web container show up in the metrics with two
// readings, so it has a CPU figure.
func (e *env) runningWeb(t *testing.T, serviceID string) {
	t.Helper()
	e.stats.mu.Lock()
	e.stats.managed = []node.Managed{{ID: "c1", Name: "lab_web", ServiceID: serviceID, Project: "lab", Service: "web", State: "running"}}
	e.stats.stats = map[string]node.ContainerStats{"c1": {CPUTotal: 1e9, SystemCPU: 100e9, OnlineCPUs: 2, MemUsed: 64 << 20, MemLimit: 256 << 20}}
	e.stats.mu.Unlock()
	e.mc.Sample(context.Background())
	e.stats.mu.Lock()
	e.stats.stats["c1"] = node.ContainerStats{CPUTotal: 2e9, SystemCPU: 110e9, OnlineCPUs: 2, MemUsed: 80 << 20, MemLimit: 256 << 20}
	e.stats.mu.Unlock()
	e.mc.Sample(context.Background())
}

func TestOverviewShowsRealDataWithoutSampleBadge(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.runningWeb(t, id)
	c, _ := e.session(t, auth.RoleViewer)

	rec := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK {
		t.Fatalf("overview: status %d", rec.Code)
	}
	page := rec.Body.String()
	for _, gone := range []string{"dados de exemplo", "vulnerabilidades", "minhaloja", "212 req/s"} {
		if strings.Contains(page, gone) {
			t.Errorf("sample content %q is still on the overview", gone)
		}
	}
	if !strings.Contains(page, `href="/p/lab/s/web"`) || !strings.Contains(page, "lab_web") {
		t.Error("the managed container should be listed with a link to its service")
	}
	if !strings.Contains(page, "80 / 256 MB") {
		t.Error("the container's memory against its limit should be shown")
	}
	if !strings.Contains(page, "Serviço lab/web criado") {
		t.Errorf("the activity feed should come from the audit log")
	}
	if !strings.Contains(page, `value="1h" checked`) {
		t.Error("1 h is the default period")
	}

	page = e.do(req{method: "GET", target: "/?period=7d", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `value="7d" checked`) || strings.Contains(page, `value="1h" checked`) {
		t.Error("?period=7d should select 7 d")
	}
	if rec := e.do(req{method: "GET", target: "/?period=forever", cookies: []*http.Cookie{c}}); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `value="1h" checked`) {
		t.Error("an unknown period falls back to 1 h")
	}
}

func TestServiceMetricsTab(t *testing.T) {
	e := newEnv(t)
	id := e.labService(t)
	e.runningWeb(t, id)
	c, _ := e.session(t, auth.RoleViewer)

	rec := e.do(req{method: "GET", target: "/p/lab/s/web?tab=metrics&period=24h", cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics tab: status %d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, `aria-selected="true" href="/p/lab/s/web?tab=overview"`) {
		t.Error("the overview tab (metrics and deploys) should be selected")
	}
	if !strings.Contains(page, `name="tab" value="overview"`) || !strings.Contains(page, `value="24h" checked`) {
		t.Error("the period picker should keep the tab and select 24 h")
	}
	// 1 s of CPU over 10 s of host time on 2 cores = 0,2 CPU.
	if !strings.Contains(page, "0,2 CPU") || !strings.Contains(page, "80 MB") {
		t.Error("current CPU (cores) and memory should be shown")
	}
	if strings.Contains(page, "O serviço não está rodando") {
		t.Error("a running service must not say it is stopped")
	}
}
