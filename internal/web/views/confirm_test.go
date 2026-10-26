package views

import (
	"context"
	"strings"
	"testing"

	"github.com/a-h/templ"
)

// Every typed-name confirmation offers the name to copy, so it can be pasted
// instead of typed: deleting a service and overwriting it with a restore
// (deleting a project uses the same confirmName).
func TestTypedConfirmationsOfferTheNameToCopy(t *testing.T) {
	d := ServiceData{Project: "lab", Slug: "web", CSRF: "tok", CanAdmin: true, SudoActive: true, SudoCritical: true}
	for name, c := range map[string]templ.Component{
		"delete":  tabSettings(d),
		"restore": svcBackupRestore(d),
	} {
		var b strings.Builder
		if err := c.Render(context.Background(), &b); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if html := b.String(); !strings.Contains(html, `data-copy="web"`) || !strings.Contains(html, `name="confirm"`) {
			t.Errorf("%s: the confirmation lacks the name to copy", name)
		}
	}
}

// The base domain's wildcard set up in scale has one certificate from the
// DNS; any other wildcard gets one per subdomain on first visit.
func TestScaledWildcardBadge(t *testing.T) {
	b := EdgeBase{Domain: "checksafe.com.br", Provider: "cloudflare", Scaled: true}
	if !scaledWildcard(b, "*.checksafe.com.br") || !scaledWildcard(b, "*.CheckSafe.com.br") {
		t.Error("the base wildcard in scale is not recognised")
	}
	if scaledWildcard(b, "*.outro.com.br") || scaledWildcard(b, "lab.checksafe.com.br") {
		t.Error("another domain counted as the scaled wildcard")
	}
	if scaledWildcard(EdgeBase{Domain: "checksafe.com.br"}, "*.checksafe.com.br") {
		t.Error("a base without the DNS token counted as scaled")
	}
}
