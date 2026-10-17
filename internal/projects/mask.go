package projects

import (
	"encoding/base64"
	"net/url"
	"slices"
	"strings"
)

// maskMinLen: shorter values ("1", "on") would blank out half the log and
// give nothing away anyway.
const maskMinLen = 4

const maskText = "••••"

// masker replaces known secret values in log text with ••••. Besides the
// value itself it hides the forms it usually takes in a log: URL-encoded,
// and inside HTTP Basic credentials (base64).
type masker struct {
	r *strings.Replacer
}

func newMasker(values ...string) *masker {
	seen := map[string]bool{}
	var all []string
	add := func(v string) {
		if len(v) >= maskMinLen && !seen[v] {
			seen[v] = true
			all = append(all, v)
		}
	}
	for _, v := range values {
		v = strings.TrimSpace(v)
		if len(v) < maskMinLen {
			continue
		}
		add(v)
		add(url.QueryEscape(v))
		add(url.PathEscape(v))
		add(base64.StdEncoding.EncodeToString([]byte(v)))
		// A URL with a password (DATABASE_URL): the password alone too.
		if u, err := url.Parse(v); err == nil && u.User != nil {
			if pw, ok := u.User.Password(); ok {
				add(pw)
			}
		}
	}
	if len(all) == 0 {
		return &masker{}
	}
	// Longest first, so a secret containing another is hidden whole.
	slices.SortFunc(all, func(a, b string) int { return len(b) - len(a) })
	pairs := make([]string, 0, 2*len(all))
	for _, v := range all {
		pairs = append(pairs, v, maskText)
	}
	return &masker{r: strings.NewReplacer(pairs...)}
}

func (m *masker) apply(s string) string {
	if m == nil || m.r == nil {
		return s
	}
	return m.r.Replace(s)
}
