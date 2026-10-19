package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/moby/moby/api/pkg/stdcopy"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

const (
	preDeployTimeout = 15 * time.Minute
	// defaultValidateTimeout bounds the validation command when the
	// service sets none.
	defaultValidateTimeout = 5 * time.Minute
	stopGrace              = 30
	// nextSuffix names the new container while both versions run.
	nextSuffix      = "-next"
	preDeploySuffix = "-predeploy"
	// prevSuffix names the stopped previous container during a recreate,
	// kept until the new one is confirmed so it can come back.
	prevSuffix = "-prev"
	// validateLogLines caps what the validation command writes to the
	// deploy log (a test suite can print thousands of lines).
	validateLogLines = 400
)

// Deploy pulls the image, runs the pre-deploy command, and replaces the
// service container following opt.Strategy. With "rolling", the old
// container keeps serving until the new one is healthy (and validated); any
// failure before the switch leaves the old version untouched. With
// "recreate", the old container is stopped but kept until the new one is
// confirmed, and started again if the new one fails (see opt.Restore).
func (l *Local) Deploy(ctx context.Context, spec node.ServiceSpec, opt node.DeployOptions) (node.DeployResult, error) {
	if err := spec.Validate(); err != nil {
		return node.DeployResult{}, err
	}
	progress := opt.Progress
	if progress == nil {
		progress = func(string, string) {}
	}
	if opt.HealthTimeout <= 0 {
		opt.HealthTimeout = node.DefaultHealthTimeout
	}
	if opt.ValidateTimeout <= 0 {
		opt.ValidateTimeout = defaultValidateTimeout
	}
	name := node.ContainerName(spec.Project, spec.Service)

	old, err := l.inspectManaged(ctx, name)
	switch {
	case errors.Is(err, errNoContainer):
		old = ""
	case err != nil:
		return node.DeployResult{}, err
	}
	// Until the strategy touches the old container, it is still serving (if
	// it was serving at all: a stopped or crashed one is no version to keep).
	untouched := node.PreviousNone
	if old != "" && l.running(ctx, old) {
		untouched = node.PreviousLive
	}

	if !opt.LocalImage {
		progress(node.PhasePull, spec.Image)
		pull := l.pull
		if opt.Fresh {
			pull = l.pullRemote
		}
		if err := pull(ctx, spec.Image); err != nil {
			return node.DeployResult{Previous: untouched}, err
		}
	}
	ref, err := l.imageRef(ctx, spec.Image, opt.LocalImage)
	if err != nil {
		return node.DeployResult{Previous: untouched}, err
	}
	if !opt.LocalImage {
		progress(node.PhasePull, ref)
	}

	if len(opt.PreDeploy) > 0 {
		progress(node.PhasePreDeploy, strings.Join(opt.PreDeploy, " "))
		if err := l.preDeploy(ctx, spec, ref, opt.PreDeploy, progress); err != nil {
			return node.DeployResult{Previous: untouched}, err
		}
	}

	var res node.DeployResult
	if opt.Strategy == node.StrategyRecreate || old == "" {
		res, err = l.recreate(ctx, spec, ref, old, opt, progress)
	} else {
		res, err = l.rolling(ctx, spec, ref, old, opt, progress)
	}
	if err != nil && res.Previous == "" {
		res.Previous = untouched
	}
	return res, err
}

func (l *Local) recreate(ctx context.Context, spec node.ServiceSpec, ref, old string, opt node.DeployOptions, progress func(string, string)) (node.DeployResult, error) {
	name := node.ContainerName(spec.Project, spec.Service)
	prevName := name + prevSuffix
	// A previous version left stopped by an interrupted deploy is stale:
	// the panel's startup (RecoverDeploy) already brought back a lone one.
	if leftover, err := l.inspectManaged(ctx, prevName); err == nil {
		_, _ = l.c.ContainerRemove(ctx, leftover, client.ContainerRemoveOptions{Force: true})
	}
	// One that was not running is not worth bringing back: it goes away,
	// as before.
	if old != "" && !l.running(ctx, old) {
		if err := l.stopAndRemove(ctx, old); err != nil {
			return node.DeployResult{}, fmt.Errorf("remove previous container: %w", err)
		}
		old = ""
	}
	restore := false
	if old != "" {
		restore = l.mayRestore(ctx, old, ref, opt.Restore)
		progress(node.PhaseSwitch, "stopping the previous version (recreate)")
		if err := l.stopAndKeep(ctx, old, prevName); err != nil {
			return node.DeployResult{Previous: node.PreviousLive}, fmt.Errorf("stop previous version: %w", err)
		}
	}
	// fail undoes the switch: the new container goes away and the stopped
	// previous one takes the service name again.
	fail := func(id string, cause error) (node.DeployResult, error) {
		if old == "" {
			return node.DeployResult{ContainerID: id, Previous: node.PreviousNone}, cause
		}
		if !restore {
			// The new container stays (Docker keeps restarting it: a slow
			// data upgrade may still finish); the old one cannot come back.
			l.dropPrevious(ctx, old)
			progress(node.PhaseRestore, "the previous version was not started again: the image changed and this service keeps data the new image may have converted")
			return node.DeployResult{ContainerID: id, Previous: node.PreviousDown},
				fmt.Errorf("%w (the service is down: the previous version was not started again because the image changed and its data may have been converted)", cause)
		}
		progress(node.PhaseRestore, "the new version failed; starting the previous version again")
		if err := l.restorePrevious(ctx, spec, id, old, opt); err != nil {
			progress(node.PhaseRestore, "the previous version did not come back: "+err.Error())
			return node.DeployResult{Previous: node.PreviousDown},
				fmt.Errorf("%w; the previous version did not come back either (%w): the service is down", cause, err)
		}
		progress(node.PhaseRestore, "the previous version is back live")
		return node.DeployResult{ContainerID: old, Previous: node.PreviousRestored},
			fmt.Errorf("%w (the previous version is back live)", cause)
	}

	progress(node.PhaseStart, name)
	id, err := l.createContainer(ctx, spec, name, ref)
	if err != nil {
		return fail("", err)
	}
	if _, err := l.c.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return fail(id, fmt.Errorf("start container: %w", err))
	}
	progress(node.PhaseHealth, "")
	if err := l.waitHealthy(ctx, id, spec, opt); err != nil {
		l.tail(ctx, id, progress)
		return fail(id, err)
	}
	if len(opt.Validate) > 0 {
		progress(node.PhaseValidate, strings.Join(opt.Validate, " "))
		if err := l.validate(ctx, id, opt.Validate, opt.ValidateTimeout, progress); err != nil {
			return fail(id, err)
		}
	}
	if old != "" {
		l.dropPrevious(ctx, old)
	}
	return node.DeployResult{ContainerID: id, ImageRef: ref}, nil
}

// running reports whether the container is up (or restarting on its own).
func (l *Local) running(ctx context.Context, id string) bool {
	res, err := l.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil || res.Container.State == nil {
		return false
	}
	return res.Container.State.Running || res.Container.State.Restarting
}

// mayRestore decides, before the old container is stopped, whether it may
// come back if the new one fails (see node.RestoreSameImage).
func (l *Local) mayRestore(ctx context.Context, old, ref, policy string) bool {
	switch policy {
	case node.RestoreNever:
		return false
	case node.RestoreSameImage:
		c, err := l.c.ContainerInspect(ctx, old, client.ContainerInspectOptions{})
		if err != nil {
			return false
		}
		img, err := l.c.ImageInspect(ctx, ref)
		if err != nil {
			return false
		}
		return c.Container.Image != "" && c.Container.Image == img.ID
	default:
		return true
	}
}

// stopAndKeep stops the previous container and moves it out of the way
// under prevName, so the new one can take the service name.
func (l *Local) stopAndKeep(ctx context.Context, id, prevName string) error {
	timeout := stopGrace
	if _, err := l.c.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeout}); err != nil && !isNotFound(err) {
		return err
	}
	if _, err := l.c.ContainerRename(ctx, id, client.ContainerRenameOptions{NewName: prevName}); err != nil {
		// Without the rename the new container cannot be created: put the
		// old one back to work rather than leave the service down.
		_, _ = l.c.ContainerStart(context.WithoutCancel(ctx), id, client.ContainerStartOptions{})
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// dropPrevious removes the stopped previous container once it is no longer
// needed (or can no longer be used).
func (l *Local) dropPrevious(ctx context.Context, id string) {
	_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), id, client.ContainerRemoveOptions{Force: true})
}

// restorePrevious removes the failed new container and starts the previous
// one again under the service name, with everything it had (image,
// variables, command, volumes, networks), then waits for it to be healthy.
// It runs even when the deploy's context ran out: leaving the service down
// is the one outcome to avoid.
func (l *Local) restorePrevious(ctx context.Context, spec node.ServiceSpec, failed, prev string, opt node.DeployOptions) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), opt.HealthTimeout+2*time.Minute)
	defer cancel()
	name := node.ContainerName(spec.Project, spec.Service)
	if failed == "" {
		// Never created, or created without its ID coming back: whatever
		// holds the name now is the failed attempt.
		if id, err := l.inspectManaged(rctx, name); err == nil && id != prev {
			failed = id
		}
	}
	if failed != "" {
		// SIGTERM first: two processes on one volume must never overlap,
		// and a database that gets a clean shutdown recovers faster.
		if err := l.stopAndRemove(rctx, failed); err != nil {
			if _, ferr := l.c.ContainerRemove(rctx, failed, client.ContainerRemoveOptions{Force: true}); ferr != nil && !isNotFound(ferr) {
				return fmt.Errorf("remove the failed container: %w", ferr)
			}
		}
	}
	if _, err := l.c.ContainerRename(rctx, prev, client.ContainerRenameOptions{NewName: name}); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	if _, err := l.c.ContainerStart(rctx, prev, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	return l.waitHealthy(rctx, prev, spec, opt)
}

func (l *Local) rolling(ctx context.Context, spec node.ServiceSpec, ref, old string, opt node.DeployOptions, progress func(string, string)) (node.DeployResult, error) {
	name := node.ContainerName(spec.Project, spec.Service)
	next := name + nextSuffix
	// A leftover from an interrupted deploy never served traffic on its own.
	if leftover, err := l.inspectManaged(ctx, next); err == nil {
		_, _ = l.c.ContainerRemove(ctx, leftover, client.ContainerRemoveOptions{Force: true})
	}
	progress(node.PhaseStart, next)
	id, err := l.createContainer(ctx, spec, next, ref)
	if err != nil {
		return node.DeployResult{}, err
	}
	discard := func() {
		_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), id, client.ContainerRemoveOptions{Force: true})
	}
	if _, err := l.c.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		discard()
		return node.DeployResult{}, fmt.Errorf("start container: %w", err)
	}
	progress(node.PhaseHealth, "")
	if err := l.waitHealthy(ctx, id, spec, opt); err != nil {
		l.tail(ctx, id, progress)
		discard()
		return node.DeployResult{}, fmt.Errorf("%w (the previous version is still live)", err)
	}
	if len(opt.Validate) > 0 {
		progress(node.PhaseValidate, strings.Join(opt.Validate, " "))
		if err := l.validate(ctx, id, opt.Validate, opt.ValidateTimeout, progress); err != nil {
			discard()
			return node.DeployResult{}, fmt.Errorf("%w (the previous version is still live)", err)
		}
	}

	// Both answer for the service name now. SIGTERM lets the old one finish
	// what it is serving; Caddy retries refused connections on the new one.
	progress(node.PhaseSwitch, "stopping the previous version")
	if err := l.stopAndRemove(ctx, old); err != nil {
		return node.DeployResult{ContainerID: id, ImageRef: ref}, fmt.Errorf("stop previous version: %w", err)
	}
	if _, err := l.c.ContainerRename(ctx, id, client.ContainerRenameOptions{NewName: name}); err != nil {
		return node.DeployResult{ContainerID: id, ImageRef: ref}, fmt.Errorf("rename: %w", err)
	}
	return node.DeployResult{ContainerID: id, ImageRef: ref}, nil
}

// validate runs the service's validation command inside the new container
// and streams its output to the deploy log. A non-zero exit, or no exit
// within timeout, fails the deploy.
func (l *Local) validate(ctx context.Context, id string, cmd []string, timeout time.Duration, progress func(string, string)) error {
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ex, err := l.c.ExecCreate(vctx, id, client.ExecCreateOptions{Cmd: cmd, AttachStdout: true, AttachStderr: true})
	if err != nil {
		return fmt.Errorf("validation: %w", err)
	}
	att, err := l.c.ExecAttach(vctx, ex.ID, client.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("validation: %w", err)
	}
	defer att.Close()
	// The stream does not notice the deadline on its own.
	stop := context.AfterFunc(vctx, att.Close)
	defer stop()
	out := &lineWriter{emit: func(s string) { progress("log", s) }, max: validateLogLines}
	_, cerr := stdcopy.StdCopy(out, out, att.Reader)
	out.flush()
	if vctx.Err() != nil {
		return fmt.Errorf("the validation command did not finish within %s", timeout)
	}
	if cerr != nil {
		return fmt.Errorf("validation: %w", cerr)
	}
	// The exit code lands a moment after the stream ends.
	for range 50 {
		res, err := l.c.ExecInspect(ctx, ex.ID, client.ExecInspectOptions{})
		if err != nil {
			return fmt.Errorf("validation: %w", err)
		}
		if !res.Running {
			if res.ExitCode != 0 {
				return fmt.Errorf("the validation command exited with %d", res.ExitCode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("the validation command did not report an exit code")
}

// lineWriter turns a byte stream into log lines, up to max lines.
type lineWriter struct {
	emit  func(string)
	max   int
	n     int
	buf   []byte
	extra int
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		w.line(string(w.buf[:i]))
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > 4<<10 { // a very long line without a break
		w.line(string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}

func (w *lineWriter) line(s string) {
	if w.n >= w.max {
		w.extra++
		return
	}
	w.n++
	w.emit(strings.TrimRight(s, "\r"))
}

func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.line(string(w.buf))
		w.buf = nil
	}
	if w.extra > 0 {
		w.emit(fmt.Sprintf("… %d more lines", w.extra))
		w.extra = 0
	}
}

func (l *Local) stopAndRemove(ctx context.Context, id string) error {
	timeout := stopGrace
	if _, err := l.c.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeout}); err != nil && !isNotFound(err) {
		return err
	}
	if _, err := l.c.ContainerRemove(ctx, id, client.ContainerRemoveOptions{}); err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// imageRef pins the image: its repo digest when it came from a registry,
// otherwise (built on this server) its ID. A local build is always pinned by
// ID: with the containerd image store it also has a "repo digest", which
// names nothing a registry has.
func (l *Local) imageRef(ctx context.Context, image string, local bool) (string, error) {
	img, err := l.c.ImageInspect(ctx, image)
	if err != nil {
		return "", fmt.Errorf("inspect image %s: %w", image, err)
	}
	if local {
		return img.ID, nil
	}
	repo, _, _ := strings.Cut(image, "@")
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i] // drop the tag
	}
	for _, d := range img.RepoDigests {
		name, _, _ := strings.Cut(d, "@")
		if name == repo || name == "docker.io/library/"+repo || name == "docker.io/"+repo {
			return d, nil
		}
	}
	return img.ID, nil
}

// preDeploy runs the command once in a temporary container with the new
// image, the same variables, networks and volumes, and no published port.
func (l *Local) preDeploy(ctx context.Context, spec node.ServiceSpec, ref string, cmd []string, progress func(string, string)) error {
	name := node.ContainerName(spec.Project, spec.Service) + preDeploySuffix
	if leftover, err := l.inspectManaged(ctx, name); err == nil {
		_, _ = l.c.ContainerRemove(ctx, leftover, client.ContainerRemoveOptions{Force: true})
	}
	tmp := spec
	tmp.Command, tmp.Ports, tmp.Edge, tmp.Health = cmd, nil, false, nil
	id, err := l.createContainer(ctx, tmp, name, ref)
	if err != nil {
		return err
	}
	defer func() {
		_, _ = l.c.ContainerRemove(context.WithoutCancel(ctx), id, client.ContainerRemoveOptions{Force: true})
	}()
	// A one-shot command must not be restarted by Docker.
	if _, err := l.c.ContainerUpdate(ctx, id, client.ContainerUpdateOptions{RestartPolicy: &container.RestartPolicy{Name: container.RestartPolicyDisabled}}); err != nil {
		return fmt.Errorf("pre-deploy: %w", err)
	}
	wctx, cancel := context.WithTimeout(ctx, preDeployTimeout)
	defer cancel()
	wait := l.c.ContainerWait(wctx, id, client.ContainerWaitOptions{Condition: container.WaitConditionNextExit})
	if _, err := l.c.ContainerStart(ctx, id, client.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("pre-deploy: %w", err)
	}
	var code int64
	select {
	case res := <-wait.Result:
		code = res.StatusCode
	case err := <-wait.Error:
		return fmt.Errorf("pre-deploy: %w", err)
	}
	l.tail(ctx, id, progress)
	if code != 0 {
		return fmt.Errorf("pre-deploy command exited with %d", code)
	}
	return nil
}

// tail forwards the container's last log lines to the deploy log.
func (l *Local) tail(ctx context.Context, id string, progress func(string, string)) {
	rc, err := l.c.ContainerLogs(context.WithoutCancel(ctx), id, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "40"})
	if err != nil {
		return
	}
	defer func() { _ = rc.Close() }()
	_ = demux(rc, func(ln node.LogLine) error {
		progress("log", ln.Text)
		return nil
	})
}

// waitHealthy waits until the container is ready: Docker's healthcheck when
// the image or template has one, else an HTTP GET on HealthPath, else a TCP
// connect on the port, else a few seconds running without restarting. A
// container that exits fails at once.
func (l *Local) waitHealthy(ctx context.Context, id string, spec node.ServiceSpec, opt node.DeployOptions) error {
	deadline := time.Now().Add(opt.HealthTimeout)
	runningSince := time.Time{}
	httpc := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var last string
	for {
		res, err := l.c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
		if err != nil {
			return err
		}
		c := res.Container
		if c.State == nil || (!c.State.Running && !c.State.Restarting) || c.RestartCount > 0 {
			code := 0
			if c.State != nil {
				code = c.State.ExitCode
			}
			return fmt.Errorf("the new container stopped (exit code %d)", code)
		}
		switch {
		case c.State.Health != nil:
			switch c.State.Health.Status {
			case container.Healthy:
				return nil
			case container.Unhealthy:
				return errors.New("healthcheck reported unhealthy")
			}
			last = "waiting for the healthcheck"
		case opt.Port > 0:
			addr := containerAddr(c, spec, opt.Port)
			if addr == "" {
				last = "no address yet"
				break
			}
			if opt.HealthPath != "" {
				req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+opt.HealthPath, nil)
				req.Header.Set("User-Agent", "hangard-healthcheck")
				resp, err := httpc.Do(req)
				if err == nil {
					_ = resp.Body.Close()
					if resp.StatusCode < 400 {
						return nil
					}
					last = fmt.Sprintf("GET %s answered %d", opt.HealthPath, resp.StatusCode)
				} else {
					last = err.Error()
				}
			} else {
				conn, err := (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "tcp", addr)
				if err == nil {
					_ = conn.Close()
					return nil
				}
				last = err.Error()
			}
		default:
			if runningSince.IsZero() {
				runningSince = time.Now()
			} else if time.Since(runningSince) >= 5*time.Second {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("not healthy after %s: %s", opt.HealthTimeout, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

func containerAddr(c container.InspectResponse, spec node.ServiceSpec, port int) string {
	if c.NetworkSettings == nil {
		return ""
	}
	for _, n := range []string{node.NetworkName(spec.Project), node.EdgeNetwork} {
		if ep := c.NetworkSettings.Networks[n]; ep != nil && ep.IPAddress.IsValid() {
			return net.JoinHostPort(ep.IPAddress.String(), strconv.Itoa(port))
		}
	}
	return ""
}

// RecoverDeploy tidies what an interrupted deploy left behind (see
// node.Recoverer). The pre-deploy container never serves traffic and goes
// away. A "-next" container next to the live one was never confirmed: it
// goes away too, so the network alias stops sending visitors to it. A
// "-next" alone already passed the health check (the old one is only
// removed after that): it takes the service name, as the deploy would have.
// A "-prev" (the stopped previous version of a recreate) goes away when a
// new container holds the service name, as the deploy would have removed
// it; alone, it is the last version that worked and is started again.
func (l *Local) RecoverDeploy(ctx context.Context, project, service string) (string, error) {
	name := node.ContainerName(project, service)
	if pre, err := l.inspectManaged(ctx, name+preDeploySuffix); err == nil {
		if _, err := l.c.ContainerRemove(ctx, pre, client.ContainerRemoveOptions{Force: true}); err != nil && !isNotFound(err) {
			return "", fmt.Errorf("remove pre-deploy container: %w", err)
		}
	}
	if prev, err := l.inspectManaged(ctx, name+prevSuffix); err == nil {
		_, err := l.inspectManaged(ctx, name)
		switch {
		case err == nil:
			if _, err := l.c.ContainerRemove(ctx, prev, client.ContainerRemoveOptions{Force: true}); err != nil && !isNotFound(err) {
				return "", fmt.Errorf("remove previous container: %w", err)
			}
			return "removed-prev", nil
		case errors.Is(err, errNoContainer):
			if _, err := l.c.ContainerRename(ctx, prev, client.ContainerRenameOptions{NewName: name}); err != nil {
				return "", fmt.Errorf("rename: %w", err)
			}
			if _, err := l.c.ContainerStart(ctx, prev, client.ContainerStartOptions{}); err != nil {
				return "", fmt.Errorf("start previous version: %w", err)
			}
			return "restored-prev", nil
		default:
			return "", err
		}
	}
	next, err := l.inspectManaged(ctx, name+nextSuffix)
	switch {
	case errors.Is(err, errNoContainer):
		return "", nil
	case err != nil:
		return "", err
	}
	_, err = l.inspectManaged(ctx, name)
	switch {
	case err == nil:
		if _, err := l.c.ContainerRemove(ctx, next, client.ContainerRemoveOptions{Force: true}); err != nil && !isNotFound(err) {
			return "", fmt.Errorf("remove unconfirmed container: %w", err)
		}
		return "removed-next", nil
	case errors.Is(err, errNoContainer):
		if _, err := l.c.ContainerRename(ctx, next, client.ContainerRenameOptions{NewName: name}); err != nil {
			return "", fmt.Errorf("rename: %w", err)
		}
		return "promoted-next", nil
	default:
		return "", err
	}
}
