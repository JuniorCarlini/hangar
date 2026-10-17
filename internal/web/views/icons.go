package views

import (
	"context"
	"embed"
	"io"
	"regexp"
	"strings"

	"github.com/a-h/templ"
)

// Icons are Lucide (https://lucide.dev, ISC license, icons/LICENSE),
// version 1.57.0, embedded so the panel never loads them from elsewhere.
//
//go:embed icons/*.svg
var iconFS embed.FS

var (
	iconCache = map[string]string{}
	iconAttrs = regexp.MustCompile(`(?s)<svg[^>]*>`)
)

// All icons are read once at start: the map is then only read.
func init() {
	entries, _ := iconFS.ReadDir("icons")
	for _, e := range entries {
		raw, err := iconFS.ReadFile("icons/" + e.Name())
		if err != nil {
			continue
		}
		body := iconAttrs.ReplaceAllString(string(raw), "")
		iconCache[strings.TrimSuffix(e.Name(), ".svg")] = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(body), "</svg>"))
	}
}

func iconBody(name string) string { return iconCache[name] }

// Icon renders a Lucide icon at the size given by its classes (default
// size-4), in the current text color, hidden from screen readers (the
// button or link around it carries the label).
func Icon(name, class string) templ.Component {
	if class == "" {
		class = "size-4"
	}
	return templ.ComponentFunc(func(_ context.Context, w io.Writer) error {
		_, err := io.WriteString(w, `<svg class="lucide lucide-`+templ.EscapeString(name)+` shrink-0 `+templ.EscapeString(class)+`" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">`+iconBody(name)+`</svg>`)
		return err
	})
}
