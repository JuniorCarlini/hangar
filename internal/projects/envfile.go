package projects

import (
	"strings"

	"github.com/JuniorCarlini/hangar/internal/i18n"
)

// EnvLine is one KEY=VALUE of a .env file.
type EnvLine struct {
	Key   string
	Value string
}

// parseEnvLine reads one line of a .env file. Blank lines and comments are
// skipped (skip); a leading "export " is dropped and surrounding quotes are
// removed. ok is false for a line that is not a valid KEY=VALUE.
func parseEnvLine(line string) (kv EnvLine, skip, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return EnvLine{}, true, true
	}
	line = strings.TrimPrefix(line, "export ")
	k, v, found := strings.Cut(line, "=")
	k = strings.TrimSpace(k)
	if !found || !envKeyRE.MatchString(k) {
		return EnvLine{}, false, false
	}
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		v = v[1 : len(v)-1]
	}
	return EnvLine{Key: k, Value: v}, false, true
}

// ParseEnvFile reads a .env file strictly: it stops at the first invalid
// line, so a paste is either imported whole or not at all.
func ParseEnvFile(text string) ([]EnvLine, error) {
	var out []EnvLine
	for i, line := range envLines(text) {
		kv, skip, ok := parseEnvLine(line)
		if !ok {
			return nil, i18n.E("env.error.bulk_line", "line", i+1)
		}
		if !skip {
			out = append(out, kv)
		}
	}
	return out, nil
}

// parseEnvFileLenient reads a .env file written by someone else (a
// repository's .env.example): invalid lines are skipped instead of failing
// the whole file, and a repeated key keeps its last value, as in a shell.
func parseEnvFileLenient(text string) []EnvLine {
	var out []EnvLine
	at := map[string]int{}
	for _, line := range envLines(text) {
		kv, skip, ok := parseEnvLine(line)
		if skip || !ok {
			continue
		}
		if i, seen := at[kv.Key]; seen {
			out[i] = kv
			continue
		}
		at[kv.Key] = len(out)
		out = append(out, kv)
	}
	return out
}

func envLines(text string) []string {
	return strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
}
