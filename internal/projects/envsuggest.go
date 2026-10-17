package projects

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Suggested variables (like Railway): a build reads the repository's
// example env file and the Variables tab offers the keys the service does
// not have yet. The repository is untrusted input: only these names, only
// regular files (never a symlink), size-capped, and never a plain .env.
var envExampleFiles = []string{".env.example", ".env.sample", ".env.template", "example.env"}

const (
	envExampleMax     = 64 << 10 // bytes read from the file
	envExampleMaxVars = 200      // same cap as a pasted .env
	envExampleMaxShow = 200      // an example value longer than this is dropped
)

// EnvSuggestion is what the Variables tab offers: the file the keys came
// from and the ones the service does not define yet. A Value is empty when
// the example looked like a secret (or there was none).
type EnvSuggestion struct {
	File string
	Vars []EnvLine
}

// readEnvExample looks for the first example env file in dir (the build
// context). ok is false when there is none, or it is not a regular file,
// too big, or not text.
func readEnvExample(dir string) (file string, vars []EnvLine, ok bool) {
	for _, name := range envExampleFiles {
		b, found := readRegularFile(filepath.Join(dir, name), envExampleMax)
		if !found {
			continue
		}
		if !utf8.Valid(b) || strings.ContainsRune(string(b), 0) {
			return "", nil, false
		}
		vars = parseEnvFileLenient(string(b))
		if len(vars) > envExampleMaxVars {
			vars = vars[:envExampleMaxVars]
		}
		for i := range vars {
			if !safeExample(vars[i].Key, vars[i].Value) {
				vars[i].Value = ""
			}
		}
		return name, vars, len(vars) > 0
	}
	return "", nil, false
}

// readRegularFile reads p only when it is a regular file (Lstat: a symlink
// is refused, not followed) of at most max bytes. The descriptor is
// checked against the Lstat so a swap between the two cannot sneak another
// file in.
func readRegularFile(p string, max int64) ([]byte, bool) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, false
	}
	f, err := os.Open(p) //nolint:gosec // a fixed name inside the build workspace
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !os.SameFile(fi, st) {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, false
	}
	return b, true
}

// secretPrefixRE matches values that start like a well-known credential:
// PEM blocks, GitHub/GitLab/Slack/Stripe/AWS/Google keys and JWTs.
var secretPrefixRE = regexp.MustCompile(`^(-----BEGIN|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|sk_(live|test)_|rk_(live|test)_|pk_live_|whsec_|AKIA|ASIA|AIza|eyJ)`)

// tokenRE: one word of key-like characters, no spaces or punctuation that
// ordinary examples (URLs, lists, sentences) carry.
var tokenRE = regexp.MustCompile(`^[A-Za-z0-9+/=_\-.]+$`)

// safeExample says whether an example value can be stored and shown. It is
// not, when the key names a secret (LooksSecret), or the value looks like
// real secret material: a known credential prefix, a URL with a password,
// or a long random-looking string. A placeholder such as "changeme" or
// "localhost" stays.
func safeExample(key, value string) bool {
	if value == "" || LooksSecret(key) || len(value) > envExampleMaxShow {
		return false
	}
	if secretPrefixRE.MatchString(value) {
		return false
	}
	if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err != nil {
			return false
		} else if _, has := u.User.Password(); has {
			return false
		}
	}
	return !looksRandom(value)
}

// looksRandom flags a long single token with letters and digits mixed and
// high entropy: an API key or a generated password pasted as an example.
func looksRandom(v string) bool {
	if len(v) < 20 || !tokenRE.MatchString(v) {
		return false
	}
	var letters, digits bool
	for _, r := range v {
		letters = letters || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z'
		digits = digits || r >= '0' && r <= '9'
	}
	return letters && digits && entropy(v) >= 3.5
}

// entropy is the Shannon entropy of s in bits per character.
func entropy(s string) float64 {
	n := map[rune]int{}
	for _, r := range s {
		n[r]++
	}
	var h float64
	total := float64(utf8.RuneCountInString(s))
	for _, c := range n {
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}

type suggestedVar struct {
	K string `json:"k"`
	V string `json:"v"`
}

func suggestionDigest(vars []EnvLine) string {
	h := sha256.New()
	for _, v := range vars {
		h.Write([]byte(v.Key))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// recordEnvSuggestions stores what the build context suggests, or forgets
// the old suggestion when the file is gone. It never fails the build.
func (m *Manager) recordEnvSuggestions(ctx context.Context, serviceID, contextDir string) {
	file, vars, ok := readEnvExample(contextDir)
	if !ok {
		if err := m.q.DeleteEnvSuggestions(ctx, serviceID); err != nil {
			m.log.Warn("forget suggested variables", "service", serviceID, "error", err)
		}
		return
	}
	rows := make([]suggestedVar, len(vars))
	for i, v := range vars {
		rows[i] = suggestedVar{K: v.Key, V: v.Value}
	}
	js, _ := json.Marshal(rows)
	if err := m.q.UpsertEnvSuggestions(ctx, dbq.UpsertEnvSuggestionsParams{
		ServiceID: serviceID, File: file, VarsJson: string(js), Digest: suggestionDigest(vars), UpdatedAt: m.now().Unix(),
	}); err != nil {
		m.log.Warn("store suggested variables", "service", serviceID, "error", err)
	}
}

// EnvSuggestions returns the repository's suggested variables the service
// does not define yet. ok is false when there are none, or the operator
// dismissed this set of keys.
func (m *Manager) EnvSuggestions(ctx context.Context, serviceID string) (EnvSuggestion, bool, error) {
	row, err := m.q.GetEnvSuggestions(ctx, serviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return EnvSuggestion{}, false, nil
	}
	if err != nil {
		return EnvSuggestion{}, false, err
	}
	if row.DismissedDigest == row.Digest {
		return EnvSuggestion{}, false, nil
	}
	var rows []suggestedVar
	if err := json.Unmarshal([]byte(row.VarsJson), &rows); err != nil {
		return EnvSuggestion{}, false, err
	}
	have, err := m.q.ListEnv(ctx, serviceID)
	if err != nil {
		return EnvSuggestion{}, false, err
	}
	defined := make(map[string]bool, len(have))
	for _, e := range have {
		defined[e.Key] = true
	}
	out := EnvSuggestion{File: row.File}
	for _, r := range rows {
		if !defined[r.K] {
			out.Vars = append(out.Vars, EnvLine{Key: r.K, Value: r.V})
		}
	}
	return out, len(out.Vars) > 0, nil
}

// DismissEnvSuggestions hides the suggested variables until the file's set
// of keys changes.
func (m *Manager) DismissEnvSuggestions(ctx context.Context, a Actor, serviceID string) error {
	n, err := m.q.DismissEnvSuggestions(ctx, serviceID)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	m.record(ctx, a, "service.env.suggestions_dismiss", "service", serviceID, audit.OK, nil)
	return nil
}
