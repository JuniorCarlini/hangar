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
func TestKitExplainsWithoutTesting(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "web", CSRF: "tok", CanAdmin: true, Domains: DomainsSection{
		Dynamic: true, CheckPath: "/.well-known/hangar/domain-check", EntryHost: "entrada.203-0-113-10.sslip.io", RequireTXT: true,
	}}
	var b strings.Builder
	if err := domainKit(d).Render(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{
		"GET /.well-known/hangar/domain-check?domain=loja.cliente.com.br", "def hangar_txt(domain):",
		"loja.cliente.com.br  →  entrada.203-0-113-10.sslip.io", "_hangar.loja.cliente.com.br  →  hg-…",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("kit without %q", want)
		}
	}
	if strings.Contains(html, "/domains/probe") || strings.Contains(html, `data-open="true"`) {
		t.Error("the kit still has the domain test")
	}
}

// The Domains card is one table (links, fixed domains and the customers'
// row); the customers' settings live in their own modal, which opens by
// itself only after one of its changes.
func TestDomainsTabIsOneTable(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "web", CSRF: "tok", Port: 8000, CanAdmin: true, CanOperate: true, SudoActive: true, Domains: DomainsSection{
		EdgeEnabled: true, Dynamic: true, CheckPath: "/.well-known/hangar/domain-check",
		Endpoints: []EndpointRow{{ID: "e1", Label: "web", Port: 8000}},
		Fixed:     []DomainRow{{ID: "d1", Hostname: "loja.exemplo.com"}},
	}}
	render := func(d ServiceData) string {
		var b strings.Builder
		if err := tabDomains(d).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	html := render(d)
	card, modal, ok := strings.Cut(html, `id="domain-clients"`)
	if !ok {
		t.Fatal("no customer domains modal")
	}
	if n := strings.Count(card, "<table"); n != 1 {
		t.Errorf("%d tables in the card, want 1", n)
	}
	for _, want := range []string{"web", "loja.exemplo.com", `data-tuc-modal="#domain-clients"`} {
		if !strings.Contains(card, want) {
			t.Errorf("card without %q", want)
		}
	}
	for _, moved := range []string{"/domains/txt", "/domains/secret/rotate", "HANGAR_DOMAIN_CHECK_SECRET"} {
		if strings.Contains(card, moved) {
			t.Errorf("%q is still in the card", moved)
		}
		if !strings.Contains(modal, moved) {
			t.Errorf("%q is not in the modal", moved)
		}
	}
	if strings.Contains(modal[:200], `data-open="true"`) {
		t.Error("the modal opens on a plain visit")
	}
	d.Domains.ClientsOpen = true
	if _, modal, _ := strings.Cut(render(d), `id="domain-clients"`); !strings.Contains(modal[:200], `data-open="true"`) {
		t.Error("the modal does not reopen after a change")
	}
}
