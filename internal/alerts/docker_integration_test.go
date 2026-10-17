//go:build integration

package alerts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/docker"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// TestContainerDownAlertWithRealDocker is the Etapa 8 check "derrubar um
// container → alerta em menos de 1 min" against the local Docker: a real
// nginx service is deployed through the projects layer, its container is
// stopped behind the panel's back, and the monitor, on real time, must get
// a message to the (fake) Telegram within a minute. The project is named
// e2e-al-* and removed at the end.
func TestContainerDownAlertWithRealDocker(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	d, err := docker.New(ctx, "")
	if err != nil {
		t.Skipf("docker unavailable: %v", err)
	}
	defer func() { _ = d.Close() }()

	e := newTestEnv(t, func(o *Options) { o.Now = time.Now })
	e.telegram(t, "warning")
	pm := projects.New(e.st.DB, e.svc.box, d, e.al, discard)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	slug := "e2e-al-" + hex.EncodeToString(b)
	a := projects.Actor{UserID: "usr_it"}
	if _, err := pm.CreateProject(ctx, a, slug, "alert test"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_ = pm.DeleteService(c, a, slug, "web")
		pm.Wait()
		_ = pm.DeleteProject(c, a, slug)
	})
	if _, err := pm.CreateService(ctx, a, slug, projects.ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", MemoryMB: 64, CPUs: 0.25}); err != nil {
		t.Fatal(err)
	}
	pm.Wait()

	states := func(ctx context.Context) ([]ServiceState, error) {
		list, err := pm.WatchedServices(ctx)
		if err != nil {
			return nil, err
		}
		var out []ServiceState
		for _, w := range list {
			if strings.HasPrefix(w.Name, slug+"_") {
				out = append(out, ServiceState{
					ID: w.ServiceID, Name: w.Name, Exists: w.Status.Exists, Running: w.Status.Running,
					State: w.Status.State, RestartCount: w.Status.RestartCount, OOMKilled: w.Status.OOMKilled,
				})
			}
		}
		return out, nil
	}
	list, err := states(ctx)
	if err != nil || len(list) != 1 || !list[0].Running {
		t.Fatalf("service not running after deploy: %+v %v", list, err)
	}

	m := e.svc.NewMonitor(states, nil)
	m.Check(ctx)
	// "Crash": stopped outside the panel, so the wanted state stays running.
	down := time.Now()
	if err := d.Stop(ctx, slug, "web"); err != nil {
		t.Fatal(err)
	}
	for time.Since(down) < 70*time.Second && len(e.tg.messages()) == 0 {
		time.Sleep(2 * time.Second)
		m.Check(ctx)
	}
	took := time.Since(down)
	msgs := e.tg.messages()
	if len(msgs) != 1 || !strings.Contains(msgs[0].Text, slug+"_web") {
		t.Fatalf("no alert after %s: %+v", took, msgs)
	}
	if took >= time.Minute {
		t.Fatalf("alert took %s, want < 1 min", took)
	}
	t.Logf("container down → alert in %s", took.Round(time.Second))

	if err := d.Start(ctx, slug, "web"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)
	m.Check(ctx)
	if msgs := e.tg.messages(); len(msgs) != 2 || !strings.HasPrefix(msgs[1].Text, "🟢") {
		t.Fatalf("no recovery notice: %+v", msgs)
	}
}
