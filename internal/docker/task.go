package docker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

var _ node.Tasker = (*Local)(nil)

// LabelTask marks helper containers and their scratch volumes.
const LabelTask = "hangar.task"

// RunTask runs a one-off helper container (docs/09: dump test, volume
// restore). It has no network, drops every capability but the default
// few, and is removed with its scratch volume however it ends.
func (l *Local) RunTask(ctx context.Context, spec node.TaskSpec, stdin io.Reader, stdout io.Writer) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	if err := l.pull(ctx, spec.Image); err != nil {
		return err
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	name := "hangar_task_" + hex.EncodeToString(suffix)
	labels := l.withInstance(map[string]string{node.LabelManaged: "true", LabelTask: "true"})

	hc := hostConfig(node.ServiceSpec{MemoryBytes: spec.MemoryBytes, NanoCPUs: spec.NanoCPUs, PidsLimit: spec.PidsLimit})
	hc.NetworkMode = "none"
	hc.RestartPolicy = container.RestartPolicy{Name: container.RestartPolicyDisabled}
	for _, m := range spec.Mounts {
		res, err := l.c.VolumeInspect(ctx, m.Volume, client.VolumeInspectOptions{})
		if err != nil {
			return fmt.Errorf("volume %s: %w", m.Volume, err)
		}
		if res.Volume.Labels[node.LabelManaged] != "true" {
			return fmt.Errorf("volume %s was not created by Hangar", m.Volume)
		}
		if err := l.checkOwner(ctx, m.Volume, res.Volume.Labels); err != nil {
			return err
		}
		hc.Mounts = append(hc.Mounts, mount.Mount{Type: mount.TypeVolume, Source: m.Volume, Target: m.Path, ReadOnly: m.ReadOnly})
	}
	if spec.Scratch != "" {
		if _, err := l.c.VolumeCreate(ctx, client.VolumeCreateOptions{Name: name, Labels: labels}); err != nil {
			return fmt.Errorf("scratch volume: %w", err)
		}
		defer func() {
			_, _ = l.c.VolumeRemove(context.WithoutCancel(ctx), name, client.VolumeRemoveOptions{Force: true})
		}()
		hc.Mounts = append(hc.Mounts, mount.Mount{Type: mount.TypeVolume, Source: name, Target: spec.Scratch})
	}
	cfg := &container.Config{
		Image: spec.Image, Cmd: spec.Cmd, Env: envList(spec.Env), Labels: labels,
		AttachStdout: true, AttachStderr: true,
		OpenStdin: stdin != nil, StdinOnce: stdin != nil, AttachStdin: stdin != nil,
	}
	res, err := l.c.ContainerCreate(ctx, client.ContainerCreateOptions{Name: name, Config: cfg, HostConfig: hc})
	if err != nil {
		return fmt.Errorf("create task: %w", err)
	}
	id := res.ID
	defer func() {
		// RemoveVolumes takes the anonymous volumes the image's VOLUME
		// lines made (a database image's data folder in a test restore);
		// named volumes are never removed by it.
		_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), id, client.ContainerRemoveOptions{Force: true, RemoveVolumes: true})
	}()
	att, err := l.c.ContainerAttach(ctx, id, client.ContainerAttachOptions{Stream: true, Stdin: stdin != nil, Stdout: true, Stderr: true})
	if err != nil {
		return fmt.Errorf("attach task: %w", err)
	}
	defer att.Close()
	wait := l.c.ContainerWait(ctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, err := l.c.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start task: %w", err)
	}
	return l.pump(ctx, &att.HijackedResponse, stdin, stdout, func() (int, error) {
		select {
		case r := <-wait.Result:
			if r.Error != nil && r.Error.Message != "" {
				return -1, errors.New(r.Error.Message)
			}
			return int(r.StatusCode), nil
		case err := <-wait.Error:
			return -1, err
		case <-ctx.Done():
			return -1, ctx.Err()
		}
	}, spec.Cmd[0])
}

// ExecIO runs a fixed command in the service container with stdin.
func (l *Local) ExecIO(ctx context.Context, project, service string, cmd []string, stdin io.Reader, stdout io.Writer) error {
	id, err := l.managedID(ctx, project, service)
	if err != nil {
		return err
	}
	ex, err := l.c.ExecCreate(ctx, id, client.ExecCreateOptions{Cmd: cmd, AttachStdin: stdin != nil, AttachStdout: true, AttachStderr: true})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	att, err := l.c.ExecAttach(ctx, ex.ID, client.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	defer att.Close()
	return l.pump(ctx, &att.HijackedResponse, stdin, stdout, func() (int, error) {
		res, err := l.c.ExecInspect(ctx, ex.ID, client.ExecInspectOptions{})
		if err != nil {
			return -1, err
		}
		return res.ExitCode, nil
	}, cmd[0])
}

// pump copies stdin into the hijacked connection (closing its write side
// at the end), demultiplexes the output, then asks exit for the code.
func (l *Local) pump(ctx context.Context, h *client.HijackedResponse, stdin io.Reader, stdout io.Writer, exit func() (int, error), what string) error {
	inErr := make(chan error, 1)
	if stdin != nil {
		go func() {
			_, err := io.Copy(h.Conn, stdin)
			if cerr := h.CloseWrite(); err == nil {
				err = cerr
			}
			inErr <- err
		}()
	} else {
		inErr <- nil
	}
	if stdout == nil {
		stdout = io.Discard
	}
	var stderr bytes.Buffer
	_, outErr := stdcopy.StdCopy(stdout, &limitedBuffer{b: &stderr, max: 8 << 10}, h.Reader)
	if outErr != nil {
		// The reader side failed (our stdout writer refused, or the
		// connection broke): stop feeding stdin.
		h.Close()
	}
	ierr := <-inErr
	code, err := exit()
	switch {
	case err != nil:
		return fmt.Errorf("%s: %w", what, err)
	case outErr != nil:
		return fmt.Errorf("%s: %w", what, outErr)
	case code != 0:
		return fmt.Errorf("%s exited with %d: %s", what, code, lastLines(stderr.String(), 6))
	case ierr != nil && ctx.Err() == nil:
		return fmt.Errorf("%s: write input: %w", what, ierr)
	}
	return nil
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, " | ")
}
