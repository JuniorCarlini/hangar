// Package i18n translates user-facing text (docs/22). Catalogs live in
// locales/<locale>.toml, embedded in the binary. Keys are English and dotted
// ("login.title"); values may use {name} placeholders and one/other plurals.
//
// Logs and audit records are data, not UI: they stay in English and never go
// through this package.
package i18n

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

// Default is the fallback locale.
const Default = "pt-BR"

//go:embed locales/*.toml
var localesFS embed.FS

// entry is one translated message, plain or plural.
type entry struct {
	text  string
	one   string
	other string
}

var (
	loadOnce sync.Once
	catalogs map[string]map[string]entry
	loadErr  error
)

func load() {
	catalogs = map[string]map[string]entry{}
	files, err := fs.Glob(localesFS, "locales/*.toml")
	if err != nil {
		loadErr = err
		return
	}
	for _, f := range files {
		raw, err := localesFS.ReadFile(f)
		if err != nil {
			loadErr = err
			return
		}
		var tree map[string]any
		if err := toml.Unmarshal(raw, &tree); err != nil {
			loadErr = fmt.Errorf("%s: %w", f, err)
			return
		}
		cat := map[string]entry{}
		if err := flatten("", tree, cat); err != nil {
			loadErr = fmt.Errorf("%s: %w", f, err)
			return
		}
		catalogs[strings.TrimSuffix(path.Base(f), ".toml")] = cat
	}
	if _, ok := catalogs[Default]; !ok {
		loadErr = fmt.Errorf("default locale %s has no catalog", Default)
	}
}

// flatten turns nested TOML tables into dotted keys. A table holding only
// "one" and "other" is a plural entry, not a namespace.
func flatten(prefix string, tree map[string]any, out map[string]entry) error {
	for k, v := range tree {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch val := v.(type) {
		case string:
			out[key] = entry{text: val}
		case map[string]any:
			one, okOne := val["one"].(string)
			other, okOther := val["other"].(string)
			if okOne && okOther && len(val) == 2 {
				out[key] = entry{one: one, other: other}
				continue
			}
			if err := flatten(key, val, out); err != nil {
				return err
			}
		default:
			return fmt.Errorf("key %s: unsupported value %T", key, v)
		}
	}
	return nil
}

func catalog(locale string) map[string]entry {
	loadOnce.Do(load)
	if c, ok := catalogs[locale]; ok {
		return c
	}
	return catalogs[Default]
}

// Init loads the catalogs and reports a broken catalog at startup instead of
// on the first page view.
func Init() error {
	loadOnce.Do(load)
	return loadErr
}

// Locales lists the available locales, default first.
func Locales() []string {
	loadOnce.Do(load)
	out := make([]string, 0, len(catalogs))
	for l := range catalogs {
		if l != Default {
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return append([]string{Default}, out...)
}

// Supported reports whether a locale has a catalog.
func Supported(locale string) bool {
	loadOnce.Do(load)
	_, ok := catalogs[locale]
	return ok
}

// Keys returns every key of a locale (for tests).
func Keys(locale string) []string {
	c := catalog(locale)
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Tl translates key in locale. args are name/value pairs filling {name}; an
// int "n" also picks the plural form. A missing key returns the key itself,
// which tests catch.
func Tl(locale, key string, args ...any) string {
	e, ok := catalog(locale)[key]
	if !ok {
		if e, ok = catalog(Default)[key]; !ok {
			return key
		}
	}
	vars := map[string]string{}
	n, hasN := 0, false
	for i := 0; i+1 < len(args); i += 2 {
		name, _ := args[i].(string)
		if err, ok := args[i+1].(error); ok {
			// A nested error renders in the same language as its parent.
			vars[name] = Message(locale, err)
		} else {
			vars[name] = fmt.Sprint(args[i+1])
		}
		if name == "n" {
			if v, ok := args[i+1].(int); ok {
				n, hasN = v, true
			} else if v, ok := args[i+1].(int64); ok {
				n, hasN = int(v), true
			}
		}
	}
	text := e.text
	if text == "" {
		text = e.other
		if hasN && n == 1 {
			text = e.one
		}
	}
	if len(vars) == 0 || !strings.Contains(text, "{") {
		return text
	}
	var b strings.Builder
	for {
		i := strings.IndexByte(text, '{')
		if i < 0 {
			b.WriteString(text)
			break
		}
		j := strings.IndexByte(text[i:], '}')
		if j < 0 {
			b.WriteString(text)
			break
		}
		name := text[i+1 : i+j]
		b.WriteString(text[:i])
		if v, ok := vars[name]; ok {
			b.WriteString(v)
		} else {
			b.WriteString(text[i : i+j+1])
		}
		text = text[i+j+1:]
	}
	return b.String()
}

type localeKey struct{}

// WithLocale stores the request locale in ctx.
func WithLocale(ctx context.Context, locale string) context.Context {
	return context.WithValue(ctx, localeKey{}, locale)
}

// Locale returns the locale stored in ctx (Default if none).
func Locale(ctx context.Context) string {
	if l, ok := ctx.Value(localeKey{}).(string); ok && l != "" {
		return l
	}
	return Default
}

// T translates key in the locale stored in ctx.
func T(ctx context.Context, key string, args ...any) string {
	return Tl(Locale(ctx), key, args...)
}

// Match picks the best supported locale for an Accept-Language header.
func Match(acceptLanguage string) string {
	type cand struct {
		tag string
		q   float64
	}
	var cands []cand
	for _, part := range strings.Split(acceptLanguage, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		tag := strings.TrimSpace(fields[0])
		if tag == "" {
			continue
		}
		q := 1.0
		for _, f := range fields[1:] {
			if v, ok := strings.CutPrefix(strings.TrimSpace(f), "q="); ok {
				if p, err := strconv.ParseFloat(v, 64); err == nil {
					q = p
				}
			}
		}
		cands = append(cands, cand{tag, q})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].q > cands[j].q })
	for _, c := range cands {
		if l := Normalize(c.tag); l != "" {
			return l
		}
	}
	return Default
}

// Normalize maps a language tag to a supported locale ("pt", "pt-PT" ->
// "pt-BR"; "en-US" -> "en"), or "" when unsupported.
func Normalize(tag string) string {
	tag = strings.ReplaceAll(strings.TrimSpace(tag), "_", "-")
	if tag == "" {
		return ""
	}
	for _, l := range Locales() {
		if strings.EqualFold(l, tag) {
			return l
		}
	}
	primary := strings.ToLower(strings.SplitN(tag, "-", 2)[0])
	for _, l := range Locales() {
		if strings.ToLower(strings.SplitN(l, "-", 2)[0]) == primary {
			return l
		}
	}
	return ""
}

// Error is a user-facing error carried as a catalog key, so each screen can
// show it in the user's language. Error() renders English for logs.
type Error struct {
	Key  string
	Args []any
}

// E builds a translatable error.
func E(key string, args ...any) error { return &Error{Key: key, Args: args} }

func (e *Error) Error() string { return Tl("en", e.Key, e.Args...) }

// In renders the error in a locale.
func (e *Error) In(locale string) string { return Tl(locale, e.Key, e.Args...) }

// Message renders err for the user in locale: translatable errors in the
// locale, joined errors one per line, anything else as-is (English).
func Message(locale string, err error) string {
	if err == nil {
		return ""
	}
	if j, ok := err.(interface{ Unwrap() []error }); ok {
		parts := make([]string, 0, len(j.Unwrap()))
		for _, e := range j.Unwrap() {
			parts = append(parts, Message(locale, e))
		}
		return strings.Join(parts, "\n")
	}
	var e *Error
	if errors.As(err, &e) {
		return e.In(locale)
	}
	return err.Error()
}

// FromEnv picks the CLI locale from LC_ALL, LC_MESSAGES or LANG
// ("pt_BR.UTF-8" -> "pt-BR"), falling back to Default.
func FromEnv(getenv func(string) string) string {
	for _, v := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		val := getenv(v)
		if val == "" || val == "C" || val == "POSIX" {
			continue
		}
		tag, _, _ := strings.Cut(val, ".")
		if l := Normalize(tag); l != "" {
			return l
		}
	}
	return Default
}
