package projects

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// HiddenValue stands for a secret the .env editor was not given (no
// reveal): "KEY=••••". Saving it keeps the variable's value as it is.
const HiddenValue = "••••"

// HiddenComment stands for a comment line of the .env shown below admin
// (SEC-024): people write passwords, URLs and notes there that the
// variables' "secret" mark never covers. Saving it keeps the comment that
// sat at that place (the n-th hidden comment is the n-th comment).
const HiddenComment = "# " + HiddenValue

func isComment(line string) bool { return strings.HasPrefix(strings.TrimSpace(line), "#") }

func envFileAD(serviceID string) string { return "services|" + serviceID + "|env_file" }

// EnvText is the service's .env as its operator wrote it: comments, blank
// lines and order kept, each KEY=VALUE line showing the variable's current
// value. Variables changed elsewhere (the connector, a template) are
// reconciled: a deleted one loses its line, a new one is added at the end.
// Without withSecrets a secret's value is HiddenValue. keys are the
// variables in the order the file shows them.
func (m *Manager) EnvText(ctx context.Context, serviceID string, withSecrets bool) (text string, keys []string, err error) {
	return m.EnvTextFor(ctx, serviceID, withSecrets, true)
}

// EnvTextFor is EnvText where, without withComments, every comment line
// shows as HiddenComment (below admin, SEC-024).
func (m *Manager) EnvTextFor(ctx context.Context, serviceID string, withSecrets, withComments bool) (text string, keys []string, err error) {
	vars, err := m.ListEnvValues(ctx, serviceID)
	if err != nil {
		return "", nil, err
	}
	cur := make(map[string]EnvVar, len(vars))
	for _, v := range vars {
		cur[v.Key] = v
	}
	stored, err := m.storedEnvFile(ctx, serviceID)
	if err != nil {
		return "", nil, err
	}
	var out []string
	seen := map[string]bool{}
	if stored != "" {
		for _, line := range envLines(strings.TrimRight(stored, "\n")) {
			kv, skip, ok := parseEnvLine(line)
			if skip || !ok {
				if !withComments && isComment(line) {
					line = HiddenComment
				}
				out = append(out, line)
				continue
			}
			v, exists := cur[kv.Key]
			if !exists || seen[kv.Key] {
				continue
			}
			seen[kv.Key] = true
			keys = append(keys, kv.Key)
			switch {
			case v.Secret && !withSecrets:
				out = append(out, kv.Key+"="+HiddenValue)
			case kv.Value == v.Value:
				out = append(out, line) // as written, quotes and all
			default:
				out = append(out, kv.Key+"="+v.Value)
			}
		}
	}
	for _, v := range vars {
		if seen[v.Key] {
			continue
		}
		keys = append(keys, v.Key)
		if v.Secret && !withSecrets {
			out = append(out, v.Key+"="+HiddenValue)
		} else {
			out = append(out, v.Key+"="+v.Value)
		}
	}
	if len(out) == 0 {
		return "", keys, nil
	}
	return strings.Join(out, "\n") + "\n", keys, nil
}

func (m *Manager) storedEnvFile(ctx context.Context, serviceID string) (string, error) {
	enc, err := m.q.GetEnvFile(ctx, serviceID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	plain, err := m.box.Open(enc, envFileAD(serviceID))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// unhide puts back the real value of every "KEY=••••" line (a secret the
// editor did not show), so the file stored and the variables set are the
// real ones. A hidden key that no longer exists loses its line.
func (m *Manager) unhide(ctx context.Context, serviceID, text string) (string, error) {
	if !strings.Contains(text, HiddenValue) {
		return text, nil
	}
	vars, err := m.ListEnvValues(ctx, serviceID)
	if err != nil {
		return "", err
	}
	cur := map[string]string{}
	for _, v := range vars {
		cur[v.Key] = v.Value
	}
	// The line as it was written (quotes and all), while its value holds;
	// and the comments, in order, for the hidden ones.
	written := map[string]string{}
	var comments []string
	if stored, err := m.storedEnvFile(ctx, serviceID); err == nil {
		for _, line := range envLines(stored) {
			if isComment(line) {
				comments = append(comments, line)
			}
			if kv, skip, ok := parseEnvLine(line); !skip && ok && kv.Value == cur[kv.Key] {
				written[kv.Key] = line
			}
		}
	}
	lines := envLines(text)
	out := lines[:0]
	hidden := 0
	for _, line := range lines {
		if strings.TrimSpace(line) == HiddenComment {
			// The comment that was at this place; one more than the file
			// had (a pasted placeholder) is dropped.
			if hidden < len(comments) {
				out = append(out, comments[hidden])
			}
			hidden++
			continue
		}
		kv, skip, ok := parseEnvLine(line)
		if skip || !ok || kv.Value != HiddenValue {
			out = append(out, line)
			continue
		}
		if line, ok := written[kv.Key]; ok {
			out = append(out, line)
		} else if real, exists := cur[kv.Key]; exists {
			out = append(out, kv.Key+"="+real)
		}
	}
	return strings.Join(out, "\n"), nil
}

// sortByFile orders vars as keys lists them (EnvText's order); any other
// keeps its place after them.
func sortByFile(vars []EnvVar, keys []string) {
	pos := make(map[string]int, len(keys))
	for i, k := range keys {
		pos[k] = i
	}
	slices.SortStableFunc(vars, func(a, b EnvVar) int {
		pa, oka := pos[a.Key]
		pb, okb := pos[b.Key]
		switch {
		case oka && okb:
			return pa - pb
		case oka:
			return -1
		case okb:
			return 1
		}
		return 0
	})
}

// EnvInFileOrder lists the variables as ListEnv (or ListEnvValues with
// withSecrets) does, in the order of the service's .env file.
func (m *Manager) EnvInFileOrder(ctx context.Context, serviceID string, withSecrets bool) ([]EnvVar, error) {
	list := m.ListEnv
	if withSecrets {
		list = m.ListEnvValues
	}
	vars, err := list(ctx, serviceID)
	if err != nil {
		return nil, err
	}
	_, keys, err := m.EnvText(ctx, serviceID, withSecrets)
	if err != nil {
		return nil, err
	}
	sortByFile(vars, keys)
	return vars, nil
}

func (m *Manager) storeEnvFile(ctx context.Context, serviceID, text string) error {
	enc, err := m.box.Seal([]byte(text), envFileAD(serviceID))
	if err != nil {
		return err
	}
	return m.q.UpsertEnvFile(ctx, dbq.UpsertEnvFileParams{ServiceID: serviceID, TextEnc: enc, UpdatedAt: m.now().Unix()})
}

// ResolvedEnvText is EnvText (with every value) where each reference is
// replaced by what it resolves to: the .env as the container gets it, to
// copy and paste outside Hangar. Comments and order are kept; a reference
// that cannot be resolved stays as written.
func (m *Manager) ResolvedEnvText(ctx context.Context, p dbq.Project, serviceID string) (string, error) {
	text, _, err := m.EnvText(ctx, serviceID, true)
	if err != nil || !strings.Contains(text, "${{") {
		return text, err
	}
	env := map[string]string{}
	for _, line := range envLines(text) {
		if kv, skip, ok := parseEnvLine(line); !skip && ok {
			env[kv.Key] = kv.Value
		}
	}
	resolved := m.ResolvedValues(ctx, p, env)
	lines := envLines(strings.TrimSuffix(text, "\n"))
	for i, line := range lines {
		kv, skip, ok := parseEnvLine(line)
		if skip || !ok || !strings.Contains(kv.Value, "${{") {
			continue
		}
		if v, ok := resolved[kv.Key]; ok {
			lines[i] = kv.Key + "=" + v
		}
	}
	return strings.Join(lines, "\n") + "\n", nil
}
