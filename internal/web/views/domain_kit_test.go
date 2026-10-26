package views

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/edge"
)

// The snippets the kit hands to developers must compute the same code the
// edge checks. Each runs when its interpreter is installed.
func TestKitSnippetsMatchTheEdge(t *testing.T) {
	const secret, host = "3f9a0c1d2e", "loja.cliente.com.br"
	want := edge.OwnershipCode([]byte(secret), host)
	cases := []struct {
		bin, file, code, call string
	}{
		{"python3", "kit.py", txtSnippetPython, "\nprint(hangar_txt(\"" + host + "\"))\n"},
		{"node", "kit.js", txtSnippetNode, "\nconsole.log(hangarTxt(\"" + host + "\"));\n"},
		{"php", "kit.php", "<?php\n" + txtSnippetPHP, "\necho hangar_txt(\"" + host + "\");\n"},
	}
	for _, c := range cases {
		bin, err := exec.LookPath(c.bin)
		if err != nil {
			continue
		}
		path := filepath.Join(t.TempDir(), c.file)
		if err := os.WriteFile(path, []byte(c.code+c.call), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, path)
		cmd.Env = append(os.Environ(), "HANGAR_DOMAIN_CHECK_SECRET="+secret)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%s: %v\n%s", c.bin, err, out)
			continue
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s computes %q, the edge checks %q", c.bin, got, want)
		}
	}
}

// After a test the kit opens by itself with each check and the customer
// text carries that domain's code; only admins get the test form.
func TestKitShowsTheProbe(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "web", CSRF: "tok", Domains: DomainsSection{
		Dynamic: true, CheckPath: "/.well-known/hangar/domain-check", EntryHost: "entrada.203-0-113-10.sslip.io", RequireTXT: true,
	}}
	render := func(d ServiceData) string {
		var b strings.Builder
		if err := domainKit(d).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if html := render(d); strings.Contains(html, "/domains/probe") || strings.Contains(html, `data-open="true"`) {
		t.Error("a non-admin gets the test, or the kit opens without a test")
	}
	d.CanAdmin = true
	d.Domains.Probe = &DomainProbe{
		Host: "loja.cliente.com.br", Path: "cloudflare", TXTRequired: true, TXTRecord: "_hangar.loja.cliente.com.br",
		TXTCode: "hg-0123456789ab", App: "app_authorized",
	}
	html := render(d)
	for _, want := range []string{
		`data-open="true"`, `action="/p/lab/s/web/domains/probe"`, "_hangar.loja.cliente.com.br  →  hg-0123456789ab",
		"loja.cliente.com.br  →  entrada.203-0-113-10.sslip.io", `value="loja.cliente.com.br"`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("kit without %q", want)
		}
	}
}
