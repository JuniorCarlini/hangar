package node

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// TaskSpec is a one-off helper container: no network, the same hardening
// as services, removed when it ends. Backups use it to test a dump in a
// throwaway database and to fill or read a volume during a restore.
type TaskSpec struct {
	Image string
	Cmd   []string
	Env   map[string]string
	// Mounts are existing volumes created by Hangar (by full Docker name).
	Mounts []TaskMount
	// Scratch, when set, mounts a fresh volume at this path that is
	// deleted with the container (room for a test restore).
	Scratch     string
	MemoryBytes int64
	NanoCPUs    int64
	PidsLimit   int64
}

// TaskMount mounts a managed volume in a task.
type TaskMount struct {
	Volume   string // full Docker name, hangar_<project>_<service>_<name>
	Path     string
	ReadOnly bool
}

// Validate checks everything that becomes a Docker argument.
func (t TaskSpec) Validate() error {
	switch {
	case !ImageRE.MatchString(t.Image):
		return fmt.Errorf("invalid image: %q", t.Image)
	case len(t.Cmd) == 0:
		return fmt.Errorf("task without a command")
	case t.MemoryBytes < 6<<20 || t.NanoCPUs <= 0 || t.PidsLimit <= 0:
		return fmt.Errorf("task without resource limits")
	case t.Scratch != "" && !validMountPath(t.Scratch):
		return fmt.Errorf("invalid scratch path: %q", t.Scratch)
	}
	for _, m := range t.Mounts {
		if !strings.HasPrefix(m.Volume, NetworkPrefix) || strings.ContainsAny(m.Volume, "/:\x00 ") {
			return fmt.Errorf("invalid volume: %q", m.Volume)
		}
		if !validMountPath(m.Path) {
			return fmt.Errorf("invalid mount path: %q", m.Path)
		}
	}
	return nil
}

// Tasker is implemented by nodes that can run helper containers and feed a
// command's standard input. Like StatsReader, it is separate from Node so
// a node without it still runs services (backups then say so).
type Tasker interface {
	// RunTask runs spec to completion, streaming stdin in and stdout out.
	// A non-zero exit is an error carrying the end of stderr.
	RunTask(ctx context.Context, spec TaskSpec, stdin io.Reader, stdout io.Writer) error
	// ExecIO is Exec with standard input (pg_restore reading a dump).
	ExecIO(ctx context.Context, project, service string, cmd []string, stdin io.Reader, stdout io.Writer) error
}
