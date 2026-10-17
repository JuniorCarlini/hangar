package docker

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Real moby.buildkit.trace messages captured from Docker 29 (BuildKit):
// two vertexes starting, then the RUN step's output.
const (
	traceVertexes = "CsYBCkdzaGEyNTY6NTEzOTA3MTcwYWQ0M2YyNTJkZDg5MTg1NmM3ZWMzNTc3MDI5ZTRkODNjMzQxNWE3YmYxNzdiYWVlZjE4MjliMxJHc2hhMjU2Ojg0NzU4ZGMwNWQ1NTMwMjViODZiYWU2ZWZjNmZmOGQ2ZjE0YzY5YTJlODE1NWRlOGE5Y2JjMTQ5MmQ2YTI1YjYaMlsyLzJdIFJVTiBlY2hvIGhlbGxvLWZyb20tYnVpbGQgJiYgZWNobyBzZWNyZXQteHl6CrsBCkdzaGEyNTY6ODQ3NThkYzA1ZDU1MzAyNWI4NmJhZTZlZmM2ZmY4ZDZmMTRjNjlhMmU4MTU1ZGU4YTljYmMxNDkyZDZhMjViNhpwWzEvMl0gRlJPTSBkb2NrZXIuaW8vbGlicmFyeS9hbHBpbmU6My4yMkBzaGEyNTY6NTI5MTQ0OWMzZGY3M2NhZjZlZDg1ZTY0OWRlYzFiOWU4MThiMzlhNWQ4Yzg3MWU5N2FmYzEzZTljZDVlOGZhOA=="
	traceStarted  = "CtkBCkdzaGEyNTY6ODQ3NThkYzA1ZDU1MzAyNWI4NmJhZTZlZmM2ZmY4ZDZmMTRjNjlhMmU4MTU1ZGU4YTljYmMxNDkyZDZhMjViNhpwWzEvMl0gRlJPTSBkb2NrZXIuaW8vbGlicmFyeS9hbHBpbmU6My4yMkBzaGEyNTY6NTI5MTQ0OWMzZGY3M2NhZjZlZDg1ZTY0OWRlYzFiOWU4MThiMzlhNWQ4Yzg3MWU5N2FmYzEzZTljZDVlOGZhOCABKgwIiNrG1gYQ4Of43QIyDAiI2sbWBhD0lfrdAgrUAQpHc2hhMjU2OjUxMzkwNzE3MGFkNDNmMjUyZGQ4OTE4NTZjN2VjMzU3NzAyOWU0ZDgzYzM0MTVhN2JmMTc3YmFlZWYxODI5YjMSR3NoYTI1Njo4NDc1OGRjMDVkNTUzMDI1Yjg2YmFlNmVmYzZmZjhkNmYxNGM2OWEyZTgxNTVkZThhOWNiYzE0OTJkNmEyNWI2GjJbMi8yXSBSVU4gZWNobyBoZWxsby1mcm9tLWJ1aWxkICYmIGVjaG8gc2VjcmV0LXh5eioMCIjaxtYGEKzU+90C"
	traceLogs     = "GncKR3NoYTI1Njo1MTM5MDcxNzBhZDQzZjI1MmRkODkxODU2YzdlYzM1NzcwMjllNGQ4M2MzNDE1YTdiZjE3N2JhZWVmMTgyOWIzEgwIiNrG1gYQzKvpmwMYASIcaGVsbG8tZnJvbS1idWlsZApzZWNyZXQteHl6Cg=="
)

func TestReadBuildStreamDecodesBuildKit(t *testing.T) {
	stream := `{"id":"moby.buildkit.trace","aux":"` + traceVertexes + `"}
{"id":"moby.buildkit.trace","aux":"` + traceStarted + `"}
{"id":"moby.buildkit.trace","aux":"` + traceLogs + `"}
{"id":"moby.buildkit.trace","aux":"bm90IHByb3RvYnVm"}
{"id":"moby.image.id","aux":{"ID":"sha256:952982a0b92d"}}
`
	var lines []string
	id, err := readBuildStream(strings.NewReader(stream), func(s string) { lines = append(lines, s) })
	if err != nil || id != "sha256:952982a0b92d" {
		t.Fatalf("id %q err %v", id, err)
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{"[1/2] FROM docker.io/library/alpine:3.22", "CACHED", "[2/2] RUN echo hello-from-build", "hello-from-build", "secret-xyz"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	// Output lines carry their step number, each on its own line.
	if !slices.Contains(lines, "#1 secret-xyz") && !slices.Contains(lines, "#2 secret-xyz") {
		t.Errorf("output not split into lines:\n%s", text)
	}
}

func TestReadBuildStreamError(t *testing.T) {
	stream := `{"errorDetail":{"message":"process \"/bin/sh -c exit 3\" did not complete successfully: exit code: 3"},"error":"x"}`
	_, err := readBuildStream(strings.NewReader(stream), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "exit code: 3") {
		t.Fatalf("error not reported: %v", err)
	}
}

func TestWriteContextHonorsDockerignoreAndSkipsGit(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"Dockerfile":         "FROM alpine\n",
		".dockerignore":      "node_modules\n*.log\n!keep.log\n",
		"app/main.py":        "print(1)\n",
		"node_modules/x.js":  "x",
		"debug.log":          "x",
		"keep.log":           "x",
		".git/config":        "[core]",
		"docker/Dockerfile2": "FROM alpine\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil { //nolint:gosec // test fixture
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := writeContext(&buf, dir, "Dockerfile"); err != nil {
		t.Fatal(err)
	}
	got := map[string]*tar.Header{}
	tr := tar.NewReader(&buf)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got[h.Name] = h
	}
	for _, want := range []string{"Dockerfile", ".dockerignore", "app/main.py", "keep.log", "docker/Dockerfile2", "link"} {
		if got[want] == nil {
			t.Errorf("missing %s", want)
		}
	}
	for _, not := range []string{"node_modules/x.js", "debug.log", ".git/config", ".git/"} {
		if got[not] != nil {
			t.Errorf("%s should not be in the context", not)
		}
	}
	if h := got["link"]; h != nil && (h.Typeflag != tar.TypeSymlink || h.Size != 0) {
		t.Error("a symlink must go as a link, never with the target's content")
	}
}
