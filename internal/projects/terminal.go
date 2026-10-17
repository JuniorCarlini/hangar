package projects

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// ErrNoTerminal means the node cannot open shells.
var ErrNoTerminal = errors.New("node cannot open a terminal")

// Terminal shells. "bash" falls back to sh on images without bash (alpine);
// "custom" runs one command line through sh -c, and the session ends when
// it does.
const (
	ShellBash   = "bash"
	ShellSh     = "sh"
	ShellCustom = "custom"
)

// Limits of a saved or typed command.
const (
	maxCommandLen     = 1000
	maxCommandNameLen = 60
	maxSavedCommands  = 50
)

const bashOrSh = `if command -v bash >/dev/null 2>&1; then exec bash -l; else echo "bash não existe nesta imagem: usando sh"; exec sh -l; fi`

// ShellCommand is what the container runs for a shell choice. A custom
// command is one line of at most 1000 characters (no control characters);
// it goes to sh -c unchanged.
func ShellCommand(shell, custom string) ([]string, error) {
	switch shell {
	case "", ShellBash:
		return []string{"/bin/sh", "-c", bashOrSh}, nil
	case ShellSh:
		return []string{"/bin/sh", "-l"}, nil
	case ShellCustom:
		cmd, err := cleanCommand(custom)
		if err != nil {
			return nil, err
		}
		return []string{"/bin/sh", "-c", cmd}, nil
	}
	return nil, i18n.E("terminal.error.shell")
}

func cleanCommand(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", i18n.E("terminal.error.command_empty")
	}
	if len(s) > maxCommandLen || !utf8.ValidString(s) {
		return "", i18n.E("terminal.error.command_long", "n", maxCommandLen)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", i18n.E("terminal.error.command_line")
	}
	return s, nil
}

// OpenShell opens an interactive shell (or runs one command) in a
// service's container. It gives full access to the container, so it is
// audited with what was run (and the route needs sudo): who, when, from
// where and which shell or command.
func (m *Manager) OpenShell(ctx context.Context, a Actor, projectSlug, serviceSlug, shell, custom string, cols, rows uint) (node.Shell, error) {
	if err := m.requireNode(); err != nil {
		return nil, err
	}
	t, ok := m.node.(node.Terminal)
	if !ok {
		return nil, ErrNoTerminal
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return nil, err
	}
	cmd, err := ShellCommand(shell, custom)
	if err != nil {
		return nil, err
	}
	if shell == "" {
		shell = ShellBash
	}
	sh, err := t.OpenShell(ctx, p.Slug, s.Slug, cmd, cols, rows)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	meta := map[string]any{"service": p.Slug + "/" + s.Slug, "shell": shell}
	if shell == ShellCustom {
		meta["command"] = cmd[2]
	}
	m.record(ctx, a, "service.terminal.open", "service", s.ID, outcome, meta)
	return sh, err
}

// ListCommands lists a service's saved terminal commands.
func (m *Manager) ListCommands(ctx context.Context, serviceID string) ([]dbq.ServiceCommand, error) {
	return m.q.ListServiceCommands(ctx, serviceID)
}

// SaveCommand keeps a command for the service's terminal.
func (m *Manager) SaveCommand(ctx context.Context, a Actor, serviceID, name, command string) error {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > maxCommandNameLen || strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 }) {
		return i18n.E("terminal.error.name", "n", maxCommandNameLen)
	}
	cmd, err := cleanCommand(command)
	if err != nil {
		return err
	}
	n, err := m.q.CountServiceCommands(ctx, serviceID)
	if err != nil {
		return err
	}
	if n >= maxSavedCommands {
		return i18n.E("terminal.error.too_many", "n", maxSavedCommands)
	}
	if err := m.q.CreateServiceCommand(ctx, dbq.CreateServiceCommandParams{
		ID: ids.New("cmd_"), ServiceID: serviceID, Name: name, Command: cmd, CreatedAt: m.now().Unix(),
	}); err != nil {
		return err
	}
	m.record(ctx, a, "service.command.save", "service", serviceID, audit.OK, map[string]any{"name": name, "command": cmd})
	return nil
}

// DeleteCommand forgets a saved command.
func (m *Manager) DeleteCommand(ctx context.Context, a Actor, serviceID, id string) error {
	name, err := m.q.DeleteServiceCommand(ctx, dbq.DeleteServiceCommandParams{ID: id, ServiceID: serviceID})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	m.record(ctx, a, "service.command.delete", "service", serviceID, audit.OK, map[string]any{"name": name})
	return nil
}
