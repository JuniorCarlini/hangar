package docker

import (
	"archive/tar"
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/moby/moby/api/types/build"
	"github.com/moby/moby/client"
	"github.com/moby/patternmatcher"
	"github.com/moby/patternmatcher/ignorefile"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// maxContextBytes caps what one build sends to Docker: a repository bigger
// than this is almost always a mistake (build outputs or data committed).
const maxContextBytes = 2 << 30

var _ node.Builder = (*Local)(nil)

// Build sends the context directory to Docker and builds it with BuildKit.
// Each line of BuildKit's progress (step names, command output, errors) goes
// to log; the caller masks secrets before storing it.
func (l *Local) Build(ctx context.Context, spec node.BuildSpec, log func(string)) (string, error) {
	if log == nil {
		log = func(string) {}
	}
	if !node.ImageRE.MatchString(spec.Tag) || !strings.HasPrefix(spec.Tag, "hangar/") {
		return "", fmt.Errorf("invalid build tag: %q", spec.Tag)
	}
	if !filepath.IsAbs(spec.ContextDir) {
		return "", fmt.Errorf("build context must be an absolute path")
	}
	df := filepath.ToSlash(filepath.Clean(spec.Dockerfile))
	if df == "." || strings.HasPrefix(df, "../") || filepath.IsAbs(spec.Dockerfile) {
		return "", fmt.Errorf("invalid Dockerfile path: %q", spec.Dockerfile)
	}
	// The Dockerfile must be a regular file inside the context (a symlink
	// could point anywhere on this machine).
	if fi, err := os.Lstat(filepath.Join(spec.ContextDir, filepath.FromSlash(df))); err != nil || !fi.Mode().IsRegular() {
		return "", errDockerfileMissing
	}

	pr, pw := io.Pipe()
	go func() { pw.CloseWithError(writeContext(pw, spec.ContextDir, df)) }()
	defer func() { _ = pr.Close() }()

	labels := map[string]string{
		node.LabelManaged: "true", node.LabelProjectID: spec.ProjectID, node.LabelProject: spec.Project,
		node.LabelServiceID: spec.ServiceID, node.LabelService: spec.Service, node.LabelDeployment: spec.Deployment,
	}
	res, err := l.c.ImageBuild(ctx, pr, client.ImageBuildOptions{
		Tags:        []string{spec.Tag},
		Dockerfile:  df,
		Labels:      labels,
		Version:     build.BuilderBuildKit,
		Remove:      true,
		ForceRemove: true,
		BuildID:     spec.Deployment,
		// A build "from scratch": no cached layer, and the base images
		// fetched again even when a copy with the same tag is here.
		NoCache:    spec.Fresh,
		PullParent: spec.Fresh,
	})
	if err != nil {
		return "", fmt.Errorf("build: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	// Canceling the request does not always stop BuildKit; ask it to.
	stop := context.AfterFunc(ctx, func() {
		_, _ = l.c.BuildCancel(context.WithoutCancel(ctx), spec.Deployment, client.BuildCancelOptions{})
	})
	defer stop()

	id, err := readBuildStream(res.Body, log)
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("build: %w", ctx.Err())
		}
		return "", err
	}
	if id == "" {
		img, err := l.c.ImageInspect(ctx, spec.Tag)
		if err != nil {
			return "", fmt.Errorf("inspect built image: %w", err)
		}
		id = img.ID
	}
	return id, nil
}

var errDockerfileMissing = errors.New("Dockerfile not found in the repository (check the path and the subdirectory)") //nolint:staticcheck // the name is a file name

// buildMessage is one JSON message of the /build response.
type buildMessage struct {
	ID          string          `json:"id"`
	Stream      string          `json:"stream"`
	Aux         json.RawMessage `json:"aux"`
	Error       string          `json:"error"`
	ErrorDetail *struct {
		Message string `json:"message"`
	} `json:"errorDetail"`
}

// readBuildStream reads Docker's build output until the end and returns the
// image ID it announces.
func readBuildStream(r io.Reader, log func(string)) (string, error) {
	tr := newTraceLog(log)
	defer tr.flush()
	dec := json.NewDecoder(bufio.NewReaderSize(r, 64<<10))
	var imageID string
	for {
		var m buildMessage
		if err := dec.Decode(&m); err != nil {
			if errors.Is(err, io.EOF) {
				return imageID, nil
			}
			return imageID, fmt.Errorf("read build output: %w", err)
		}
		switch {
		case m.Error != "" || m.ErrorDetail != nil:
			msg := m.Error
			if m.ErrorDetail != nil && m.ErrorDetail.Message != "" {
				msg = m.ErrorDetail.Message
			}
			tr.flush()
			return "", fmt.Errorf("build failed: %s", msg)
		case m.ID == "moby.buildkit.trace":
			var b64 string
			if json.Unmarshal(m.Aux, &b64) == nil {
				if raw, err := base64.StdEncoding.DecodeString(b64); err == nil {
					tr.status(raw)
				}
			}
		case m.ID == "moby.image.id":
			var aux struct{ ID string }
			if json.Unmarshal(m.Aux, &aux) == nil {
				imageID = aux.ID
			}
		case m.Stream != "":
			for _, ln := range strings.Split(strings.TrimRight(m.Stream, "\n"), "\n") {
				log(ln)
			}
		}
	}
}

// writeContext writes the build context as a tar stream: every file under
// dir except .git and what .dockerignore excludes. Symlinks go as symlinks
// (BuildKit resolves them inside the context, never on this machine).
func writeContext(w io.Writer, dir, dockerfile string) error {
	var pm *patternmatcher.PatternMatcher
	if f, err := os.Open(filepath.Join(dir, ".dockerignore")); err == nil { //nolint:gosec // dir is the build workspace
		patterns, err := ignorefile.ReadAll(f)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf(".dockerignore: %w", err)
		}
		if pm, err = patternmatcher.New(patterns); err != nil {
			return fmt.Errorf(".dockerignore: %w", err)
		}
	}
	tw := tar.NewWriter(w)
	var total int64
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" {
			return filepath.SkipDir
		}
		keep := rel == dockerfile || rel == ".dockerignore"
		if pm != nil && !keep {
			skip, err := pm.MatchesOrParentMatches(rel)
			if err != nil {
				return err
			}
			if skip {
				if d.IsDir() && !pm.Exclusions() {
					return filepath.SkipDir
				}
				if !d.IsDir() {
					return nil
				}
			}
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		link := ""
		if info.Mode()&fs.ModeSymlink != 0 {
			if link, err = os.Readlink(p); err != nil {
				return err
			}
		} else if !info.Mode().IsRegular() && !info.IsDir() {
			return nil // sockets, devices: never part of a build
		}
		hdr, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		hdr.Name = rel
		if info.IsDir() {
			hdr.Name += "/"
		}
		hdr.Uid, hdr.Gid, hdr.Uname, hdr.Gname = 0, 0, "", ""
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		total += info.Size()
		if total > maxContextBytes {
			return fmt.Errorf("build context larger than %d GiB", maxContextBytes>>30)
		}
		f, err := os.Open(p) //nolint:gosec // p comes from walking the workspace
		if err != nil {
			return err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		return err
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

// PruneBuilds removes the service's built images that are not in keep.
// Images still used by a container are refused by Docker and stay.
func (l *Local) PruneBuilds(ctx context.Context, serviceID string, keep []string) error {
	res, err := l.c.ImageList(ctx, client.ImageListOptions{
		Filters: make(client.Filters).Add("label", node.LabelManaged+"=true").Add("label", node.LabelServiceID+"="+serviceID),
	})
	if err != nil {
		return err
	}
	// keep holds pinned references (an ID, or a name@digest from an older
	// deploy): compare by the image ID they resolve to.
	keepSet := map[string]bool{}
	for _, k := range keep {
		keepSet[k] = true
		if img, err := l.c.ImageInspect(ctx, k); err == nil {
			keepSet[img.ID] = true
		} else if !isNotFound(err) {
			return fmt.Errorf("inspect kept image %s: %w", k, err) // unsure what is in use: remove nothing
		}
	}
	var errs []error
	for _, img := range res.Items {
		if keepSet[img.ID] {
			continue
		}
		if _, err := l.c.ImageRemove(ctx, img.ID, client.ImageRemoveOptions{Force: true, PruneChildren: true}); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
