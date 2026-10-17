package web

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/auth"
)

func TestLoginLanguageFromBrowserAndSwitch(t *testing.T) {
	e := newEnv(t)
	rec := e.do(req{method: "GET", target: "/login", header: map[string]string{"Accept-Language": "en-US,en;q=0.9"}})
	if !strings.Contains(rec.Body.String(), "Log in") || !strings.Contains(rec.Body.String(), `lang="en"`) {
		t.Fatalf("Accept-Language en should render English")
	}
	rec = e.do(req{method: "GET", target: "/login"})
	if !strings.Contains(rec.Body.String(), "Entrar") {
		t.Fatalf("without a preference the default is pt-BR")
	}

	rec = e.do(req{method: "GET", target: "/login?lang=en"})
	lang := cookie(rec, langCookie)
	if rec.Code != http.StatusSeeOther || lang == nil || lang.Value != "en" || !lang.Secure || !lang.HttpOnly {
		t.Fatalf("language switch: status %d, cookie %+v", rec.Code, lang)
	}
	rec = e.do(req{method: "GET", target: "/login", cookies: []*http.Cookie{lang}, header: map[string]string{"Accept-Language": "pt-BR"}})
	if !strings.Contains(rec.Body.String(), "Log in") {
		t.Fatal("the language cookie should beat Accept-Language")
	}

	rec = e.do(req{method: "GET", target: "/login?lang=xx"})
	if cookie(rec, langCookie) != nil {
		t.Fatal("an unsupported language must not be stored")
	}
}

func TestPreferencesChangeLanguageAndTheme(t *testing.T) {
	e := newEnv(t)
	c, p := e.session(t, auth.RoleViewer)

	page := e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if strings.Contains(page, "data-theme") {
		t.Error(`"system" theme must not write data-theme (the CSS follows the OS)`)
	}

	rec := e.do(req{
		method: "POST", target: "/account/preferences", cookies: []*http.Cookie{c},
		form: url.Values{"csrf": {p.CSRFToken}, "locale": {"en"}, "theme": {"light"}},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save preferences: status %d, body %s", rec.Code, rec.Body)
	}
	page = e.do(req{method: "GET", target: "/", cookies: []*http.Cookie{c}}).Body.String()
	if !strings.Contains(page, `data-theme="light"`) || !strings.Contains(page, "Projects") || !strings.Contains(page, `lang="en"`) {
		t.Fatal("light theme and English should apply on every page")
	}

	rec = e.do(req{
		method: "POST", target: "/account/preferences", cookies: []*http.Cookie{c},
		form: url.Values{"csrf": {p.CSRFToken}, "locale": {"klingon"}, "theme": {"neon"}},
	})
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid preferences: status %d", rec.Code)
	}
	p2, _ := e.svc.Authenticate(context.Background(), c.Value)
	if p2.Theme != "light" || p2.Locale != "en" {
		t.Errorf("invalid input must not change the stored preferences: %+v", p2)
	}
}

// No UI text written straight into a template: every visible string goes
// through t(ctx, ...), so every language gets it (docs/22).
var (
	templExprRE  = regexp.MustCompile(`\{[^{}]*\}`)
	textNodeRE   = regexp.MustCompile(`>([^<>]*)<`)
	literalAttrs = regexp.MustCompile(`\b(placeholder|aria-label|title|alt)="([^"{]*)"`)
	technicalRE  = regexp.MustCompile(`^[a-z0-9_:./@-]*$|^[A-Z0-9_]+$|^[0-9.]+$`)
	allowedText  = map[string]bool{"Hangar": true, "Logs": true}
)

func TestNoStrayTextInTemplates(t *testing.T) {
	files, err := filepath.Glob("views/*.templ")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates not found: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "//") || strings.HasPrefix(trim, "<svg") {
				continue
			}
			clean := templExprRE.ReplaceAllString(line, "")
			for _, m := range textNodeRE.FindAllStringSubmatch(clean, -1) {
				text := strings.TrimSpace(strings.Trim(m[1], "·/→•_,. "))
				if text == "" || allowedText[text] || technicalRE.MatchString(text) || !strings.ContainsAny(strings.ToLower(text), "abcdefghijklmnopqrstuvwxyz") {
					continue
				}
				t.Errorf("%s:%d: text %q is not translated (use t(ctx, ...))", f, i+1, text)
			}
			for _, m := range literalAttrs.FindAllStringSubmatch(line, -1) {
				if !technicalRE.MatchString(m[2]) {
					t.Errorf("%s:%d: attribute %s=%q is not translated", f, i+1, m[1], m[2])
				}
			}
		}
	}
}

var tokenRE = regexp.MustCompile(`--p-([a-z0-9-]+):\s*#([0-9a-fA-F]{6});`)

func tokens(t *testing.T, css, selector string) map[string]string {
	t.Helper()
	i := strings.Index(css, selector)
	if i < 0 {
		t.Fatalf("selector %q not found", selector)
	}
	block := css[i : i+strings.Index(css[i:], "}")]
	out := map[string]string{}
	for _, m := range tokenRE.FindAllStringSubmatch(block, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func luminance(hex string) float64 {
	ch := func(s string) float64 {
		v, _ := strconv.ParseUint(s, 16, 8)
		c := float64(v) / 255
		if c <= 0.04045 {
			return c / 12.92
		}
		return math.Pow((c+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(hex[0:2]) + 0.7152*ch(hex[2:4]) + 0.0722*ch(hex[4:6])
}

func contrast(a, b string) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

// Text tokens must reach WCAG AA (4.5:1) on the backgrounds they are used on,
// in both themes.
func TestThemeContrastAA(t *testing.T) {
	raw, err := os.ReadFile("tailwind/tokens.css")
	if err != nil {
		t.Fatal(err)
	}
	css := string(raw)
	shared := tokens(t, css, ":root {")
	pairs := [][2]string{
		{"fg", "bg"},
		{"fg", "surface"},
		{"fg", "surface-2"},
		{"muted", "surface"},
		{"subtle", "surface"},
		{"accent-text", "surface"},
		{"success", "surface"},
		{"info", "surface"},
		{"warning", "surface"},
		{"danger", "surface"},
		{"on-accent", "accent"},
		{"on-accent", "accent-hover"},
		{"on-accent", "danger-fill"},
		{"on-accent", "danger-fill-hover"},
	}
	for _, theme := range []string{`:root[data-theme="dark"] {`, `:root[data-theme="light"] {`} {
		tk := tokens(t, css, theme)
		if theme == `:root[data-theme="dark"] {` {
			tk = tokens(t, css, ":root,\n:root[data-theme=\"dark\"] {")
		}
		for _, p := range pairs {
			fg, bg := tk[p[0]], tk[p[1]]
			if fg == "" || bg == "" {
				t.Errorf("%s: token %s or %s missing", theme, p[0], p[1])
				continue
			}
			if c := contrast(fg, bg); c < 4.5 {
				t.Errorf("%s: %s on %s has contrast %.2f, below AA 4.5", theme, p[0], p[1], c)
			}
		}
	}
	for _, p := range [][2]string{{"log-fg", "log-bg"}, {"log-time", "log-bg"}, {"log-err", "log-bg"}} {
		if c := contrast(shared[p[0]], shared[p[1]]); c < 4.5 {
			t.Errorf("logs: %s on %s has contrast %.2f", p[0], p[1], c)
		}
	}
}

// Colors live only in the token blocks; a hard-coded color elsewhere would
// ignore the theme.
func TestNoHardcodedColorsOutsideTokens(t *testing.T) {
	color := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b|rgba?\(`)
	for _, file := range []string{"tailwind/tokens.css", "tailwind/components.css", "tailwind/input.css"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trim := strings.TrimSpace(line)
			if strings.HasPrefix(trim, "--p-") || strings.HasPrefix(trim, "/*") {
				continue
			}
			if color.MatchString(line) {
				t.Errorf("%s:%d: color outside tokens: %s", file, i+1, trim)
			}
		}
	}
	// Templates use the Tailwind palette, which only holds the tokens; an
	// arbitrary color (text-[#fff], bg-[rgb(...)]) would ignore the theme.
	arbitrary := regexp.MustCompile(`-\[(#|rgb|hsl|oklch)`)
	files, _ := filepath.Glob("views/*.templ")
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		if arbitrary.Match(raw) {
			t.Errorf("%s: arbitrary color in a class", f)
		}
	}
}
