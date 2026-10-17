package views

import (
	"context"
	"strings"
	"testing"
)

// The suggested variables card is for whoever can add variables; the
// editor's hidden source carries the lines "Add" appends.
func TestSuggestedVariablesCard(t *testing.T) {
	d := ServiceData{
		Project: "lab", Slug: "web", CSRF: "tok",
		EnvSuggest: &EnvSuggest{File: ".env.sample", Vars: []SuggestedVar{{Key: "PORT", Example: "8000"}, {Key: "API_KEY"}}},
	}
	render := func(d ServiceData) string {
		var b strings.Builder
		if err := tabVariables(d).Render(context.Background(), &b); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if html := render(d); strings.Contains(html, `id="env-suggested"`) || strings.Contains(html, "data-envsuggest") {
		t.Error("a viewer sees the suggestions card")
	}
	d.CanOperate = true
	html := render(d)
	for _, want := range []string{
		`id="env-suggested"`, ".env.sample", `action="/p/lab/s/web/env/suggestions/dismiss"`,
		`data-tuc-modal="#env-bulk" data-env-suggest`, `<span data-k="PORT">8000</span>`, `<span data-k="API_KEY"></span>`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("card lacks %q", want)
		}
	}
	d.EnvSuggest = nil
	if html := render(d); strings.Contains(html, `id="env-suggested"`) {
		t.Error("card shown with nothing to suggest")
	}
}
