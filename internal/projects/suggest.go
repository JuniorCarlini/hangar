package projects

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
)

// SuggestedCommand is a command the terminal offers for the app it found in
// the container (Django, Node, Laravel, Rails, a Makefile).
type SuggestedCommand struct {
	Name    string
	Command string
}

// probeTimeout bounds the look inside the container.
const probeTimeout = 5 * time.Second

// maxSuggestions keeps the list short enough to scan.
const maxSuggestions = 14

// probeScript lists the project files the suggestions come from, in the
// container's working directory. It only reads: no package manager runs.
const probeScript = `for f in manage.py package.json artisan bin/rails Makefile; do [ -f "$f" ] && echo "F:$f"; done; true`

var (
	makeTargetRE = regexp.MustCompile(`(?m)^([a-zA-Z0-9][a-zA-Z0-9_.-]*):`)
	npmScriptRE  = regexp.MustCompile(`^[a-zA-Z0-9:._-]{1,40}$`)
)

// cappedBuffer stops collecting after max bytes (what the container prints
// is not trusted to be small).
type cappedBuffer struct {
	bytes.Buffer
	max int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// SuggestCommands looks at the service's container for the usual project
// files and returns the commands people run there. Nothing is suggested
// when the container is not running or nothing is recognized.
func (m *Manager) SuggestCommands(ctx context.Context, projectSlug, serviceSlug string) []SuggestedCommand {
	if m.node == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	read := func(cmd ...string) (string, error) {
		out := &cappedBuffer{max: 64 << 10}
		err := m.node.Exec(ctx, projectSlug, serviceSlug, cmd, out)
		return out.String(), err
	}
	listing, err := read("sh", "-c", probeScript)
	if err != nil && listing == "" {
		return nil
	}
	has := map[string]bool{}
	for _, line := range strings.Split(listing, "\n") {
		if f, ok := strings.CutPrefix(strings.TrimSpace(line), "F:"); ok {
			has[f] = true
		}
	}
	var out []SuggestedCommand
	add := func(name, cmd string) {
		if len(out) < maxSuggestions {
			out = append(out, SuggestedCommand{Name: name, Command: cmd})
		}
	}
	if has["manage.py"] {
		for _, c := range []struct{ name, args string }{
			{"migrate", "migrate"},
			{"makemigrations", "makemigrations"},
			{"createsuperuser", "createsuperuser"},
			{"shell", "shell"},
			{"collectstatic", "collectstatic --noinput"},
			{"check --deploy", "check --deploy"},
			{"showmigrations", "showmigrations"},
		} {
			add("Django · "+c.name, "python manage.py "+c.args)
		}
	}
	if has["artisan"] {
		for _, c := range []string{"migrate", "tinker", "route:list", "cache:clear", "config:cache"} {
			add("Laravel · "+c, "php artisan "+c)
		}
	}
	if has["bin/rails"] {
		for _, c := range []string{"db:migrate", "console", "routes"} {
			add("Rails · "+c, "bin/rails "+c)
		}
	}
	if has["package.json"] {
		if raw, err := read("cat", "package.json"); err == nil || raw != "" {
			var pkg struct {
				Scripts map[string]string `json:"scripts"`
			}
			if json.Unmarshal([]byte(raw), &pkg) == nil {
				names := make([]string, 0, len(pkg.Scripts))
				for n := range pkg.Scripts {
					if npmScriptRE.MatchString(n) {
						names = append(names, n)
					}
				}
				sort.Strings(names)
				for _, n := range names {
					add("npm · "+n, "npm run "+n)
				}
			}
		}
	}
	if has["Makefile"] {
		if raw, err := read("cat", "Makefile"); err == nil || raw != "" {
			seen := map[string]bool{}
			for _, mt := range makeTargetRE.FindAllStringSubmatch(raw, -1) {
				t := mt[1]
				if seen[t] || strings.HasPrefix(t, ".") {
					continue
				}
				seen[t] = true
				add("make · "+t, "make "+t)
			}
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && len(out) == 0 {
		return nil
	}
	return out
}
