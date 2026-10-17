package projects

import (
	"context"
	"strings"
	"testing"
)

func TestHostLabelBase(t *testing.T) {
	long := strings.Repeat("a", 32)
	for _, c := range []struct{ project, service, name, want string }{
		{"lab", "web", "", "lab-web"},
		{"lab", "files", "console", "lab-files-console"},
		{"ab", "-x", "", "ab-x"},           // never "--" (Let's Encrypt refuses "ab--x")
		{"a", "b", "S3/CDN", "a-b-s3-cdn"}, // only [a-z0-9-]
	} {
		if got := hostLabelBase(c.project, c.service, c.name); got != c.want {
			t.Errorf("hostLabelBase(%q, %q, %q) = %q, want %q", c.project, c.service, c.name, got, c.want)
		}
	}
	got := hostLabelBase(long, long, "console")
	if len(got) > maxHostLabel || strings.HasSuffix(got, "-") {
		t.Errorf("long label %q (%d chars) must fit %d and not end in a dash", got, len(got), maxHostLabel)
	}
}

// Two services whose names join to the same label ("ab-cd"/"ef" and
// "ab"/"cd-ef")
// must not share an automatic link.
func TestHostLabelsAreUnique(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, p := range []string{"ab-cd", "ab"} {
		if _, err := f.m.CreateProject(ctx, f.who, p, ""); err != nil {
			t.Fatal(err)
		}
	}
	s1, err := f.m.CreateService(ctx, f.who, "ab-cd", ServiceInput{Slug: "ef", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	s2, err := f.m.CreateService(ctx, f.who, "ab", ServiceInput{Slug: "cd-ef", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	e1, _ := f.m.ListEndpoints(ctx, s1.ID)
	e2, _ := f.m.ListEndpoints(ctx, s2.ID)
	if len(e1) != 1 || len(e2) != 1 || e1[0].HostLabel != "ab-cd-ef" || e2[0].HostLabel != "ab-cd-ef-2" {
		t.Fatalf("labels: %+v / %+v", e1, e2)
	}
}

// Services older than endpoints get an internal one (and a link name) at
// startup; nothing becomes public by an upgrade.
func TestEnsureEndpointsBackfills(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	// As if it had been created before endpoints existed.
	if _, err := f.m.db.ExecContext(ctx, `DELETE FROM endpoints WHERE service_id = ?`, s.ID); err != nil {
		t.Fatal(err)
	}
	n, err := f.m.EnsureEndpoints(ctx)
	if err != nil || n != 1 {
		t.Fatalf("EnsureEndpoints = %d, %v", n, err)
	}
	eps, _ := f.m.ListEndpoints(ctx, s.ID)
	if len(eps) != 1 || eps[0].Public || eps[0].Port != 80 || eps[0].HostLabel != "lab-web" {
		t.Fatalf("backfilled endpoint: %+v", eps)
	}
	if n, err := f.m.EnsureEndpoints(ctx); err != nil || n != 0 {
		t.Errorf("a second run must change nothing: %d, %v", n, err)
	}
	// A database has no web endpoint: it is not counted on every start.
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	if n, err := f.m.EnsureEndpoints(ctx); err != nil || n != 0 {
		t.Errorf("a database counted as prepared on every start: %d, %v", n, err)
	}
}

// A domain older than endpoints answers on the service's port: after the
// upgrade it is tied to that endpoint, which shows as public.
func TestEnsureEndpointsBindsOldDomains(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "loja.exemplo.com.br", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.db.ExecContext(ctx, `UPDATE domains SET endpoint_id = NULL`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.db.ExecContext(ctx, `UPDATE endpoints SET public = 0, sslip_enabled = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.EnsureEndpoints(ctx); err != nil {
		t.Fatal(err)
	}
	eps, _ := f.m.ListEndpoints(ctx, s.ID)
	if len(eps) != 1 || !eps[0].Public || eps[0].SslipEnabled {
		t.Fatalf("endpoint with an old domain: %+v", eps)
	}
	var bound string
	if err := f.m.db.QueryRowContext(ctx, `SELECT endpoint_id FROM domains`).Scan(&bound); err != nil || bound != eps[0].ID {
		t.Errorf("old domain not tied to its endpoint: %q %v", bound, err)
	}
}

// A template born public (Uptime Kuma) goes on the internet only when its
// creator confirmed the password moments ago; otherwise it starts internal.
func TestBornPublicTemplateNeedsSudo(t *testing.T) {
	for _, sudo := range []bool{false, true} {
		f := newFixture(t)
		ctx := context.Background()
		if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
			t.Fatal(err)
		}
		who := f.who
		who.Sudo = sudo
		svcs, err := f.m.CreateFromTemplate(ctx, who, "lab", "uptime-kuma", "kuma", nil)
		if err != nil {
			t.Fatal(err)
		}
		eps, _ := f.m.ListEndpoints(ctx, svcs[0].ID)
		if len(eps) != 1 || eps[0].Public != sudo {
			t.Errorf("sudo=%v: endpoints %+v", sudo, eps)
		}
	}
}

// A custom domain and an automatic link never share a hostname: sslip.io
// names and "<label>.<base>" of an endpoint are refused as domains, and a
// new label skips the first label of an existing domain.
func TestDomainsAndAutomaticLinksDoNotClash(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.m.SetBaseDomain("apps.exemplo.com")
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"lab-web.203-0-113-10.sslip.io", "lab-web.apps.exemplo.com"} {
		if err := f.m.AddDomain(ctx, f.who, "lab", "web", host, ""); err == nil {
			t.Errorf("%s was accepted as a custom domain", host)
		}
	}
	// A domain that would be the next service's automatic link.
	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "lab-api.apps.exemplo.com", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	eps, _ := f.m.ListEndpoints(ctx, s.ID)
	if len(eps) != 1 || eps[0].HostLabel != "lab-api-2" {
		t.Errorf("label next to an existing domain: %+v", eps)
	}
}

// Endpoints belong to a template's main service: after an upgrade, a
// sidecar answering on the same port as the main one gets none.
func TestEnsureEndpointsSkipsSidecars(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "n8n", "flows", nil)
	if err != nil || len(svcs) < 2 {
		t.Fatalf("CreateFromTemplate = %d services, %v", len(svcs), err)
	}
	// As if both had been created before endpoints, with the sidecar on
	// the editor's port.
	if _, err := f.m.db.ExecContext(ctx, `DELETE FROM endpoints`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.db.ExecContext(ctx, `UPDATE services SET internal_port = 5678 WHERE slug = 'flows-db'`); err != nil {
		t.Fatal(err)
	}
	if n, err := f.m.EnsureEndpoints(ctx); err != nil || n != 1 {
		t.Fatalf("EnsureEndpoints = %d, %v", n, err)
	}
	for _, s := range svcs {
		eps, _ := f.m.ListEndpoints(ctx, s.ID)
		if want := s.Slug == "flows"; (len(eps) == 1) != want {
			t.Errorf("%s: endpoints %+v", s.Slug, eps)
		}
	}
}

// An older domain left on a service without a port would route to port 0:
// the edge leaves it out.
func TestPortlessOldDomainIsNotServed(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "web", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.m.AddDomain(ctx, f.who, "lab", "web", "loja.exemplo.com.br", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.db.ExecContext(ctx, `UPDATE domains SET endpoint_id = NULL`); err != nil {
		t.Fatal(err)
	}
	served := func() int {
		rows, err := f.m.q.ListAllDomains(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if served() != 1 {
		t.Fatal("an older domain on a service with a port must still be served")
	}
	if _, err := f.m.db.ExecContext(ctx, `UPDATE services SET internal_port = 0 WHERE id = ?`, s.ID); err != nil {
		t.Fatal(err)
	}
	if n := served(); n != 0 {
		t.Errorf("portless older domain served: %d", n)
	}
}
