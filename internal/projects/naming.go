package projects

import (
	"fmt"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

// Names: the user types (or accepts) a name such as "Loja API"; the service's
// identifier — its internal address on the project network, the container
// name — is derived from it. The browser shows the same derivation as a
// preview (assets/newservice.js mirrors Slugify); the server always derives
// it again and never trusts a slug sent by the form.

// maxSlug is the longest identifier node.SlugRE accepts.
const maxSlug = 32

// ErrNameTooShort: the name has fewer than two usable letters or digits.
var ErrNameTooShort = &i18n.Error{Key: "service.error.name"}

// accents folds the Latin letters with diacritics people type in names.
var accents = strings.NewReplacer(
	"á", "a", "à", "a", "â", "a", "ã", "a", "ä", "a", "å", "a",
	"é", "e", "è", "e", "ê", "e", "ë", "e",
	"í", "i", "ì", "i", "î", "i", "ï", "i",
	"ó", "o", "ò", "o", "ô", "o", "õ", "o", "ö", "o",
	"ú", "u", "ù", "u", "û", "u", "ü", "u",
	"ç", "c", "ñ", "n", "ý", "y", "ÿ", "y",
)

// Slugify turns a name into an identifier node.SlugRE accepts: lowercase,
// no accents, anything else becomes a hyphen, cut at the maximum length. A
// name starting with a digit gets an "s-" prefix. It returns "" when nothing
// usable is left (or only one character).
func Slugify(name string) string {
	s := accents.Replace(strings.ToLower(strings.TrimSpace(name)))
	var b strings.Builder
	dash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case b.Len() > 0 && !dash:
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out != "" && out[0] >= '0' && out[0] <= '9' {
		out = "s-" + out
	}
	if len(out) > maxSlug {
		out = strings.TrimRight(out[:maxSlug], "-")
	}
	if !node.SlugRE.MatchString(out) {
		return ""
	}
	return out
}

// slugFromName validates the typed name and derives its identifier.
func slugFromName(name string) (string, error) {
	if s := Slugify(name); s != "" {
		return s, nil
	}
	return "", ErrNameTooShort
}

// UniqueName returns base, or base-2, base-3… — the first one not taken.
func UniqueName(base string, taken map[string]bool) string {
	base = Slugify(base)
	if base == "" {
		base = "web"
	}
	if !taken[base] {
		return base
	}
	for i := 2; ; i++ {
		suffix := fmt.Sprintf("-%d", i)
		b := base
		if len(b)+len(suffix) > maxSlug {
			b = strings.TrimRight(b[:maxSlug-len(suffix)], "-")
		}
		if c := b + suffix; !taken[c] {
			return c
		}
	}
}

// NameFromRepo suggests a name from a repository URL:
// https://github.com/dono/loja-api → "loja-api". "" when none fits.
func NameFromRepo(repo string) string {
	d := strings.TrimRight(gitsrc.Display(strings.TrimSpace(repo)), "/")
	if i := strings.LastIndex(d, "/"); i >= 0 {
		d = d[i+1:]
	}
	return Slugify(strings.TrimSuffix(d, ".git"))
}

// NameFromImage suggests a name from an image reference:
// nginx:1.29 → "nginx", ghcr.io/dono/api:2 → "api". "" when none fits.
func NameFromImage(image string) string {
	name, _, _ := strings.Cut(strings.TrimSpace(image), "@")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	name, _, _ = strings.Cut(name, ":")
	return Slugify(name)
}

// TemplateName is the default name of a template's service: what it is
// ("db", "cache"), not which product it is.
func TemplateName(id string) string {
	switch id {
	case "postgres":
		return "db"
	case "redis-cache":
		return "cache"
	case "redis-queue":
		return "redis"
	}
	return id
}

// knownPorts are the ports well-known images listen on, so the form can
// fill the port in. Anything else is left to the user (or to the image's
// EXPOSE for a build).
var knownPorts = map[string]int{
	"nginx": 80, "httpd": 80, "caddy": 80, "traefik/whoami": 80, "nginxinc/nginx-unprivileged": 8080,
	"adminer": 8080, "grafana/grafana": 3000, "metabase/metabase": 3000, "n8nio/n8n": 5678,
	"minio/minio": 9000, "mysql": 3306, "mariadb": 3306, "mongo": 27017, "memcached": 11211,
	"rabbitmq": 5672, "valkey/valkey": 6379, "redis": 6379, "postgres": 5432, "elasticsearch": 9200,
	"getmeili/meilisearch": 7700, "uptime-kuma": 3001, "louislam/uptime-kuma": 3001, "wordpress": 80,
	"ghost": 2368, "node": 3000, "python": 8000,
}

// KnownImagePort is the port a well-known image listens on (0 = unknown).
func KnownImagePort(image string) int {
	name, _, _ := strings.Cut(strings.TrimSpace(image), "@")
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name = name[:i]
	}
	name = strings.TrimPrefix(strings.TrimPrefix(name, "docker.io/"), "library/")
	return knownPorts[name]
}

// exposedPort reads the first EXPOSE of a Dockerfile (0 = none or not a
// plain number, such as a build argument).
func exposedPort(dockerfile []byte) int {
	for _, line := range strings.Split(string(dockerfile), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || !strings.EqualFold(f[0], "EXPOSE") {
			continue
		}
		p, _, _ := strings.Cut(f[1], "/")
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err == nil && n > 0 && n <= 65535 && fmt.Sprint(n) == p {
			return n
		}
	}
	return 0
}
