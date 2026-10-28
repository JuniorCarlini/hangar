package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/auth"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// The web fake node can switch volumes (node.VolumeBinder): none exists.
func (f *fakeNode) VolumeDevice(context.Context, string) (bool, string, error) { return false, "", nil }

func (f *fakeNode) SwitchVolume(context.Context, node.ServiceSpec, node.Volume, string) error {
	return nil
}

// limitsOn wires the volume limits with the root unit "installed" and runs
// the panel's side of them until the test ends.
func (e *env) limitsOn(t *testing.T) volumes.Paths {
	t.Helper()
	w := volumes.NewWriter(t.TempDir())
	e.pm.SetVolumeLimits(w, func(string) (int64, bool) { return 300 << 20, true })
	if err := w.Write(nil, true); err != nil {
		t.Fatal(err)
	}
	if err := volumes.WriteApplied(w.Paths, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.pm.RunVolumeLimits(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return w.Paths
}

// answer plays the root unit until the limit of name is in place.
func answer(t *testing.T, e *env, p volumes.Paths, s func() *projects.VolumeLimit) {
	t.Helper()
	for range 200 {
		var res []volumes.Result
		for _, en := range (&volumes.Writer{Paths: p}).Current().Volumes {
			res = append(res, volumes.Result{Name: en.Name, Op: en.Op, OK: true, Size: en.Size, Mounted: true, Used: 512 << 20, Total: uint64(en.Size)})
		}
		_ = volumes.WriteApplied(p, res)
		if l := s(); l != nil && l.Active() && !l.Pending {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the limit never got in place")
}

func TestVolumeLimitRoutes(t *testing.T) {
	e := newEnv(t)
	p := e.limitsOn(t)
	e.labService(t)
	ctx := context.Background()
	if err := e.pm.AddServiceVolume(ctx, projects.Actor{}, "lab", "web", "media", "/app/media"); err != nil {
		t.Fatal(err)
	}
	limit := func() *projects.VolumeLimit {
		_, s, _ := e.pm.GetService(ctx, "lab", "web")
		vols, _ := e.pm.ListServiceVolumes(ctx, "lab", s)
		return vols[0].Limit
	}

	// Usage of a disk without a limit; its size behind sudo.
	c, pr := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{"300 MB", "sem limite", `data-tuc-modal="#volume-edit-media"`, `id="volume-edit-media"`, "Definir tamanho"} {
		if !strings.Contains(page, want) {
			t.Errorf("page without sudo lacks %q", want)
		}
	}
	if strings.Contains(page, `id="volume-edit-media-size"`) {
		t.Error("size field without sudo")
	}
	form := url.Values{"csrf": {pr.CSRFToken}, "name": {"media"}, "path": {"/app/media"}, "size_gb": {"2"}, "size_was": {""}}
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/volumes/edit", form: form, cookies: []*http.Cookie{c}}); rec.Code == http.StatusSeeOther || limit() != nil {
		t.Fatalf("size without sudo: %d", rec.Code)
	}

	c, pr = e.sudo(t, c, pr)
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{`id="volume-edit-media-size"`, `name="size_gb"`, "Livre no servidor"} {
		if !strings.Contains(page, want) {
			t.Errorf("page with sudo lacks %q", want)
		}
	}
	form.Set("csrf", pr.CSRFToken)
	for _, bad := range []string{"0", "abc", "1.5", "99999"} {
		form.Set("size_gb", bad)
		rec := e.do(req{method: "POST", target: "/p/lab/s/web/volumes/edit", form: form, cookies: []*http.Cookie{c}})
		if rec.Code == http.StatusSeeOther || !strings.Contains(rec.Body.String(), "Escolha um tamanho entre 1 GB") {
			t.Errorf("size %q: %d", bad, rec.Code)
		}
	}
	form.Set("size_gb", "2")
	rec := e.do(req{method: "POST", target: "/p/lab/s/web/volumes/edit", form: form, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "ok=volume-edit") {
		t.Fatalf("limit: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	if l := limit(); l == nil || l.Size != 2*volumes.GiB {
		t.Fatalf("limit = %+v", l)
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, "Preparando o disco") {
		t.Error("the new limit is not shown as being prepared")
	}
	answer(t, e, p, limit)

	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	for _, want := range []string{"512 MB de 2 GB", `role="meter"`, `aria-valuenow="25"`, `name="size_was" value="2"`} {
		if !strings.Contains(page, want) {
			t.Errorf("limited disk page lacks %q", want)
		}
	}
	// Increasing (the same form, unchanged path); and the audit trail.
	form.Set("size_gb", "3")
	form.Set("size_was", "2")
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/volumes/edit", form: form, cookies: []*http.Cookie{c}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("grow: %d", rec.Code)
	}
	answer(t, e, p, limit)
	if l := limit(); l.Size != 3*volumes.GiB {
		t.Errorf("after growing: %+v", l)
	}
	form.Set("size_gb", "2")
	form.Set("size_was", "3")
	if rec := e.do(req{method: "POST", target: "/p/lab/s/web/volumes/edit", form: form, cookies: []*http.Cookie{c}}); !strings.Contains(rec.Body.String(), "Um limite só aumenta") {
		t.Errorf("shrink: %d", rec.Code)
	}
	var n int
	if err := e.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.volume.limit' AND outcome = 'ok'`).Scan(&n); err != nil || n < 2 {
		t.Errorf("audit records: %d %v", n, err)
	}

	// Others see the usage, not the buttons.
	if _, err := e.st.DB.Exec(`UPDATE users SET role = 'operator'`); err != nil {
		t.Fatal(err)
	}
	page = e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, "de 3 GB") || strings.Contains(page, "volume-edit-media") {
		t.Error("operator view of a limited disk")
	}
}

func TestTemplateFormOffersTheSuggestedLimit(t *testing.T) {
	e := newEnv(t)
	paths := e.limitsOn(t)
	e.labService(t)
	c, pr := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/new", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `id="tpl-postgres-limit-data" name="limit_data" value="1" disabled`) || !strings.Contains(page, "data → /var/lib/postgresql · limite de 10 GB") {
		t.Error("without sudo the suggested limit is shown but off")
	}
	c, pr = e.sudo(t, c, pr)
	page = e.do(req{method: "GET", target: "/p/lab/new", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `id="tpl-postgres-limit-data" name="limit_data" value="1" checked`) || !strings.Contains(page, `name="size_data" type="number" min="1" max="8192" step="1" required value="10"`) {
		t.Error("with sudo the suggested limit comes checked, at the template's size")
	}
	// Sent with the form: the disk is born limited.
	form := url.Values{"csrf": {pr.CSRFToken}, "template": {"postgres"}, "name": {"db"}, "limit_data": {"1"}, "size_data": {"12"}}
	rec := e.do(req{method: "POST", target: "/p/lab/templates", form: form, cookies: []*http.Cookie{c}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	_, s, err := e.pm.GetService(context.Background(), "lab", "db")
	if err != nil {
		t.Fatal(err)
	}
	vols, _ := e.pm.ListServiceVolumes(context.Background(), "lab", s)
	if len(vols) != 1 || vols[0].Limit == nil || vols[0].Limit.Size != 12*volumes.GiB {
		t.Fatalf("volumes = %+v", vols)
	}
	// The first deploy waits for the image; the unit makes it.
	answer(t, e, paths, func() *projects.VolumeLimit {
		vols, _ := e.pm.ListServiceVolumes(context.Background(), "lab", s)
		return vols[0].Limit
	})
	e.pm.Wait()
}

// The Resources card: admins change memory and CPU from Settings; an
// operator sees the values but cannot change them.
func TestServiceResourcesRoute(t *testing.T) {
	e := newEnv(t)
	e.labService(t)
	ctx := context.Background()

	c, p := e.session(t, auth.RoleAdmin)
	page := e.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `action="/p/lab/s/web/resources"`) || !strings.Contains(page, `name="memory_mb"`) {
		t.Fatal("the Resources card is missing for an admin")
	}
	post := func(e *env, c *http.Cookie, csrf, mem, cpus string) *httptest.ResponseRecorder {
		return e.do(req{
			method: "POST", target: "/p/lab/s/web/resources", cookies: []*http.Cookie{c},
			form: url.Values{"csrf": {csrf}, "memory_mb": {mem}, "cpus": {cpus}},
		})
	}
	rec := post(e, c, p.CSRFToken, "1024", "0,5")
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "ok=resources") {
		t.Fatalf("save: %d %s", rec.Code, rec.Header().Get("Location"))
	}
	_, s, _ := e.pm.GetService(ctx, "lab", "web")
	if s.MemoryBytes != 1024<<20 || s.NanoCpus != 5e8 {
		t.Errorf("stored %d bytes, %d nano CPUs", s.MemoryBytes, s.NanoCpus)
	}
	if rec = post(e, c, p.CSRFToken, "4", "1"); rec.Code == http.StatusSeeOther {
		t.Error("4 MB accepted")
	}

	e2 := newEnv(t)
	e2.labService(t)
	oc, op := e2.session(t, auth.RoleOperator)
	if !strings.Contains(e2.do(req{method: "GET", target: "/p/lab/s/web?tab=settings", cookies: []*http.Cookie{oc}}).Body.String(), "MB de memória") {
		t.Error("an operator should still see the limits")
	}
	if rec = post(e2, oc, op.CSRFToken, "2048", "2"); rec.Code != http.StatusForbidden {
		t.Errorf("operator changing resources: %d", rec.Code)
	}
}
