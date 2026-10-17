package docker

import (
	"context"
	"fmt"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

var _ node.Terminal = (*Local)(nil)

// OpenShell runs cmd on a TTY in the service container, as the container's
// own user (the caller picks the shell or command, projects.ShellCommand).
func (l *Local) OpenShell(ctx context.Context, project, service string, cmd []string, cols, rows uint) (node.Shell, error) {
	if len(cmd) == 0 {
		return nil, fmt.Errorf("exec: no command")
	}
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return nil, err
	}
	size := client.ConsoleSize{Height: rows, Width: cols}
	ex, err := l.c.ExecCreate(ctx, id, client.ExecCreateOptions{
		Cmd: cmd, TTY: true, ConsoleSize: size,
		AttachStdin: true, AttachStdout: true, AttachStderr: true,
		Env: []string{"TERM=xterm-256color"},
	})
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	att, err := l.c.ExecAttach(ctx, ex.ID, client.ExecAttachOptions{TTY: true, ConsoleSize: size})
	if err != nil {
		return nil, fmt.Errorf("exec: %w", err)
	}
	return &shell{l: l, id: ex.ID, att: att.HijackedResponse}, nil
}

type shell struct {
	l   *Local
	id  string
	att client.HijackedResponse
}

func (s *shell) Read(p []byte) (int, error)  { return s.att.Reader.Read(p) }
func (s *shell) Write(p []byte) (int, error) { return s.att.Conn.Write(p) }

func (s *shell) Close() error {
	s.att.Close()
	return nil
}

func (s *shell) Resize(ctx context.Context, cols, rows uint) error {
	_, err := s.l.c.ExecResize(ctx, s.id, client.ExecResizeOptions{Height: rows, Width: cols})
	return err
}
