package docker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// Exec runs a fixed command inside the service container (no TTY, no stdin)
// and streams its stdout to w. Used for things like pg_dump; the panel never
// runs commands typed by the user through here.
func (l *Local) Exec(ctx context.Context, project, service string, cmd []string, w io.Writer) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	ex, err := l.c.ExecCreate(ctx, id, client.ExecCreateOptions{Cmd: cmd, AttachStdout: true, AttachStderr: true})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	att, err := l.c.ExecAttach(ctx, ex.ID, client.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	defer att.Close()
	var stderr bytes.Buffer
	if _, err := stdcopy.StdCopy(w, &limitedBuffer{b: &stderr, max: 4 << 10}, att.Reader); err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	res, err := l.c.ExecInspect(ctx, ex.ID, client.ExecInspectOptions{})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("%s exited with %d: %s", cmd[0], res.ExitCode, strings.TrimSpace(stderr.String()))
	}
	return nil
}

type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// SetLinked makes the running container's networks match the linked
// projects: joins the missing ones and leaves the ones no longer linked. The
// container's own network and the edge network are never touched.
func (l *Local) SetLinked(ctx context.Context, project, service string, linked []string) error {
	res, err := l.c.ContainerInspect(ctx, node.ContainerName(project, service), client.ContainerInspectOptions{})
	if isNotFound(err) {
		return nil // not deployed: the next deploy joins them
	}
	if err != nil {
		return err
	}
	c := res.Container
	if c.Config == nil {
		return ErrNotManaged
	}
	if err := l.checkOwner(ctx, node.ContainerName(project, service), c.Config.Labels); err != nil {
		return err
	}
	want := map[string]bool{}
	for _, p := range linked {
		want[node.NetworkName(p)] = true
	}
	have := map[string]bool{}
	if c.NetworkSettings != nil {
		for name := range c.NetworkSettings.Networks {
			have[name] = true
		}
	}
	for name := range want {
		if !have[name] {
			if _, err := l.c.NetworkConnect(ctx, name, client.NetworkConnectOptions{Container: c.ID}); err != nil {
				return fmt.Errorf("join %s: %w", name, err)
			}
		}
	}
	own := node.NetworkName(project)
	for name := range have {
		if name == own || name == node.EdgeNetwork || want[name] || !strings.HasPrefix(name, node.NetworkPrefix) {
			continue
		}
		if _, err := l.c.NetworkDisconnect(ctx, name, client.NetworkDisconnectOptions{Container: c.ID}); err != nil && !isNotFound(err) {
			return fmt.Errorf("leave %s: %w", name, err)
		}
	}
	return nil
}
