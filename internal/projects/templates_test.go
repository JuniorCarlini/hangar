package projects

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/firewall"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

type fakeFirewall struct{ rules []firewall.Rule }

func (f *fakeFirewall) Write(r []firewall.Rule) error { f.rules = r; return nil }

func TestPostgresTemplateIsSecureByDefault(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.CreateFromTemplate(ctx, f.who, "loja", "postgres", "db", map[string]string{"database": "shop"})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, ok := f.n.spec("loja_db")
	if !ok {
		t.Fatal("postgres was not deployed")
	}
	pw := spec.Env["POSTGRES_PASSWORD"]
	if len(pw) < 40 || spec.Env["POSTGRES_DB"] != "shop" || spec.Env["POSTGRES_USER"] != "app" {
		t.Errorf("env: %v", spec.Env)
	}
	if len(spec.Volumes) != 1 || spec.Volumes[0].Path != "/var/lib/postgresql" || spec.Health == nil || len(spec.Ports) != 0 {
		t.Errorf("volume, healthcheck and no published port expected: %+v", spec)
	}
	env, _ := f.m.ListEnv(ctx, svcs[0].ID)
	for _, e := range env {
		if e.Key == "POSTGRES_PASSWORD" && (!e.Secret || e.Value != "") {
			t.Error("the generated password must be a secret variable")
		}
	}
	exps, _ := f.m.ListExports(ctx, svcs[0].ID)
	var host string
	for _, e := range exps {
		if e.Key == "HOST" {
			host = e.Value
		}
		if e.Key == "DATABASE_URL" && (!e.Secret || e.Value != "") {
			t.Error("DATABASE_URL carries the password and must be masked")
		}
	}
	if host != "loja_db" {
		t.Errorf("HOST export = %q", host)
	}
	url, _ := f.m.RevealExport(ctx, f.who, svcs[0].ID, "DATABASE_URL")
	if url != "postgres://app:"+pw+"@loja_db:5432/shop" {
		t.Errorf("DATABASE_URL = %q", url)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "loja", "postgres", "db", nil); !errors.Is(err, ErrExists) {
		t.Errorf("same name twice: %v", err)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "loja", "postgres", "db2", map[string]string{"database": "x; drop"}); err == nil {
		t.Error("input outside its pattern accepted")
	}
}

func TestReferencesResolveAtDeploy(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t) // project lab, service web
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if err := f.m.SetEnv(ctx, f.who, webID, "DATABASE_URL", "${{ db.DATABASE_URL }}", false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	if !strings.HasPrefix(spec.Env["DATABASE_URL"], "postgres://app:") || !strings.Contains(spec.Env["DATABASE_URL"], "@lab_db:5432/app") {
		t.Errorf("reference not resolved: %q", spec.Env["DATABASE_URL"])
	}

	// Another project's service is only reachable after connecting the projects.
	if _, err := f.m.CreateProject(ctx, f.who, "outro", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "outro", "redis-cache", "cache", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	_ = f.m.SetEnv(ctx, f.who, webID, "REDIS_URL", "${{outro.cache.REDIS_URL}}", false)
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err == nil {
		t.Fatal("reference to a project that is not connected must fail the deploy")
	}
	if err := f.m.LinkProjects(ctx, f.who, "lab", "outro"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ = f.n.spec("lab_web")
	if !strings.Contains(spec.Env["REDIS_URL"], "@outro_cache:6379/0") {
		t.Errorf("cross-project reference: %q", spec.Env["REDIS_URL"])
	}
	if len(spec.Linked) != 1 || spec.Linked[0] != "outro" {
		t.Errorf("linked networks: %v", spec.Linked)
	}

	_ = f.m.SetEnv(ctx, f.who, webID, "X", "${{db.NOPE}}", false)
	if _, err := f.m.Deploy(ctx, f.who, "lab", "web", "manual"); err == nil {
		t.Error("reference to a missing key must fail the deploy")
	}
}

func TestPortsAndFirewall(t *testing.T) {
	f := newFixture(t)
	fw := &fakeFirewall{}
	f.m.SetFirewall(fw)
	ctx := context.Background()
	f.service(t)

	bad := []PortInput{
		{HostPort: 22, ContainerPort: 80, Protocol: "tcp", Access: AccessAny},
		{HostPort: 443, ContainerPort: 80, Protocol: "tcp", Access: AccessAny},
		{HostPort: 8080, ContainerPort: 80, Protocol: "sctp", Access: AccessAny},
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", Access: AccessIPs},
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", Access: AccessIPs, IPs: []string{"not-an-ip"}},
		{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", Access: "everyone"},
	}
	for _, in := range bad {
		if err := f.m.AddPort(ctx, f.who, "lab", "web", in); err == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	if err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 8080, ContainerPort: 80, Protocol: "tcp", Access: AccessIPs, IPs: []string{"200.1.2.3", "10.0.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if len(fw.rules) != 1 || fw.rules[0].Port != 8080 || len(fw.rules[0].Allow) != 2 || fw.rules[0].Allow[0] != netip.MustParsePrefix("200.1.2.3/32") {
		t.Errorf("firewall rules: %+v", fw.rules)
	}
	if err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 8080, ContainerPort: 81, Protocol: "tcp", Access: AccessAny}); err == nil {
		t.Error("host port used twice")
	}
	if err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 9090, ContainerPort: 80, Protocol: "tcp", Access: AccessLocalhost, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_web")
	if len(spec.Ports) != 2 {
		t.Fatalf("published ports: %+v", spec.Ports)
	}
	for _, p := range spec.Ports {
		if p.HostPort == 9090 && p.HostIP != netip.MustParseAddr("127.0.0.1") {
			t.Error("'localhost only' must bind 127.0.0.1")
		}
		if p.HostPort == 8080 && p.HostIP.IsValid() {
			t.Error("an IP-restricted port binds every address; the firewall restricts it")
		}
	}
	if len(fw.rules) != 1 {
		t.Error("localhost ports need no firewall rule")
	}

	// While a deploy runs, nothing is stored (it could not be published).
	_, web, _ := f.m.GetService(ctx, "lab", "web")
	if err := f.m.q.CreateDeployment(ctx, dbq.CreateDeploymentParams{
		ID: "dep_running", ServiceID: web.ID, Image: web.Image, Trigger: "manual", StartedAt: time.Now().Unix(),
	}); err != nil {
		t.Fatal(err)
	}
	err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 7070, ContainerPort: 80, Protocol: "tcp", Access: AccessAny})
	_ = f.m.q.FinishDeployment(ctx, dbq.FinishDeploymentParams{Status: "failed", ID: "dep_running"})
	if !errors.Is(err, ErrDeployRunning) {
		t.Errorf("port during a deploy: %v", err)
	}
	if all, _ := f.m.ListAllPorts(ctx); len(all) != 2 {
		t.Errorf("a refused port must not be stored: %d ports", len(all))
	}

	// Expiry closes the port.
	f.m.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	f.m.expirePorts(ctx)
	f.m.Wait()
	all, _ := f.m.ListAllPorts(ctx)
	if len(all) != 1 || all[0].HostPort != 8080 {
		t.Errorf("after expiry: %+v", all)
	}
}

func TestBackupDownloadOnlyForPostgres(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t)
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "postgres", "db", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	// The download itself is the backup package's (DownloadPlain).
	for slug, want := range map[string]bool{"db": true, "web": false} {
		_, s, err := f.m.GetService(ctx, "lab", slug)
		if err != nil {
			t.Fatal(err)
		}
		if got := f.m.CanDownloadBackup(s.Template); got != want {
			t.Errorf("%s: CanDownloadBackup = %v, want %v", slug, got, want)
		}
	}
}

func TestTemplateEndpointsArePersisted(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.CreateFromTemplate(ctx, f.who, "loja", "rustfs", "files", nil)
	if err != nil {
		t.Fatal(err)
	}
	eps, err := f.m.q.ListEndpoints(ctx, svcs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(eps))
	}
	byName := map[string]dbq.Endpoint{}
	for _, e := range eps {
		byName[e.Name] = e
	}
	// The console administers every bucket: it starts internal (the
	// operator publishes it), with the automatic link ready for when it is.
	if c := byName["console"]; c.Port != 9001 || c.Public != 0 || c.SslipEnabled != 1 || c.HostLabel != "loja-files-console" {
		t.Errorf("console endpoint should start internal with sslip ready: %+v", c)
	}
	if cdn := byName["cdn"]; cdn.Port != 9000 || cdn.Public != 0 {
		t.Errorf("cdn endpoint should default to internal: %+v", cdn)
	}
}

func TestCustomDomainTogglesEndpointSslip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.CreateFromTemplate(ctx, f.who, "loja", "rustfs", "files", nil)
	if err != nil {
		t.Fatal(err)
	}
	var consoleID string
	eps, _ := f.m.q.ListEndpoints(ctx, svcs[0].ID)
	for _, e := range eps {
		if e.Name == "console" {
			consoleID = e.ID
			if e.SslipEnabled != 1 {
				t.Fatal("console sslip should start on")
			}
		}
	}
	sslip := func() int64 {
		rows, _ := f.m.q.ListEndpoints(ctx, svcs[0].ID)
		for _, e := range rows {
			if e.ID == consoleID {
				return e.SslipEnabled
			}
		}
		return -1
	}
	// The console starts internal: a domain publishes it, but removing the
	// domain must not then put a brand new automatic link on the internet.
	if err := f.m.AddDomain(ctx, f.who, "loja", "files", "admin0.exemplo.com", consoleID); err != nil {
		t.Fatal(err)
	}
	doms0, _ := f.m.ListDomains(ctx, svcs[0].ID)
	if err := f.m.RemoveDomain(ctx, f.who, svcs[0].ID, doms0[0].ID); err != nil {
		t.Fatal(err)
	}
	if sslip() != 0 {
		t.Fatal("removing the only domain of a port that was internal exposed its automatic link")
	}

	// A port that was already public: the domain takes over its link, and
	// the link comes back when the domain goes.
	if err := f.m.SetEndpointSslip(ctx, f.who, "loja", "files", consoleID, true); err != nil {
		t.Fatal(err)
	}
	if err := f.m.AddDomain(ctx, f.who, "loja", "files", "admin.exemplo.com", consoleID); err != nil {
		t.Fatal(err)
	}
	if sslip() != 0 {
		t.Error("a custom domain on the endpoint should turn its sslip off")
	}
	doms, _ := f.m.ListDomains(ctx, svcs[0].ID)
	if err := f.m.RemoveDomain(ctx, f.who, svcs[0].ID, doms[0].ID); err != nil {
		t.Fatal(err)
	}
	if sslip() != 1 {
		t.Error("removing the last custom domain should turn sslip back on")
	}

	// One the operator switched off stays off when a domain comes and goes.
	if err := f.m.SetEndpointSslip(ctx, f.who, "loja", "files", consoleID, false); err != nil {
		t.Fatal(err)
	}
	if err := f.m.AddDomain(ctx, f.who, "loja", "files", "admin2.exemplo.com", consoleID); err != nil {
		t.Fatal(err)
	}
	doms, _ = f.m.ListDomains(ctx, svcs[0].ID)
	if err := f.m.RemoveDomain(ctx, f.who, svcs[0].ID, doms[0].ID); err != nil {
		t.Fatal(err)
	}
	if sslip() != 0 {
		t.Error("a link the operator turned off must not come back with the domain's removal")
	}
}

// Editing a port keeps its own host port free for itself, can keep its
// closing time, and moves the firewall with the access in one redeploy.
func TestEditPort(t *testing.T) {
	f := newFixture(t)
	fw := &fakeFirewall{}
	f.m.SetFirewall(fw)
	ctx := context.Background()
	f.service(t)
	if err := f.m.AddPort(ctx, f.who, "lab", "web", PortInput{HostPort: 9090, ContainerPort: 80, Protocol: "tcp", Access: AccessLocalhost, ExpiresIn: time.Hour}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	all, _ := f.m.ListAllPorts(ctx)
	if len(all) != 1 {
		t.Fatalf("ports: %+v", all)
	}
	id, closes := all[0].ID, all[0].ExpiresAt
	// Same host port, now for two IPs, closing time kept.
	in := PortInput{HostPort: 9090, ContainerPort: 81, Protocol: "tcp", Access: AccessIPs, IPs: []string{"200.1.2.3"}, KeepExpiry: true}
	if err := f.m.UpdatePort(ctx, f.who, "lab", "web", id, in); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	all, _ = f.m.ListAllPorts(ctx)
	if len(all) != 1 || all[0].ContainerPort != 81 || all[0].Access != AccessIPs || all[0].ExpiresAt != closes {
		t.Errorf("after the edit: %+v", all)
	}
	if len(fw.rules) != 1 || fw.rules[0].Port != 9090 {
		t.Errorf("firewall after the edit: %+v", fw.rules)
	}
	if spec, _ := f.n.spec("lab_web"); len(spec.Ports) != 1 || spec.Ports[0].ContainerPort != 81 {
		t.Errorf("published: %+v", spec.Ports)
	}
	if err := f.m.UpdatePort(ctx, f.who, "lab", "web", "prt_nope", in); !errors.Is(err, ErrNotFound) {
		t.Errorf("editing a port that does not exist: %v", err)
	}
}
