package projects

import (
	"testing"

	"github.com/JuniorCarlini/hangar/internal/templates"
)

// useTemplate adds a template made of compose (main service "app") to the
// fixture's catalog under id.
func (f *fixture) useTemplate(t *testing.T, id, compose string) {
	t.Helper()
	tp, err := templates.Parse(id, map[string][]byte{
		templates.FileMeta: []byte(`id = "` + id + `"
version = 1
category = "other"
main = "app"
name = { en = "X", "pt-BR" = "X" }
description = { en = "X", "pt-BR" = "X" }
`),
		templates.FileCompose: []byte(compose),
		templates.FileLogo:    []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.m.SetTemplates(templates.NewRegistry(templates.Merge(templates.Builtin(), []*templates.Template{tp})))
}
