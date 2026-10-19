package templates

import (
	"strings"
	"testing"
)

// sharedFolder is a template whose main service (app) and a helper (tool)
// mount the same volume; the helper is written first in the file.
func sharedFolder(toolMount, toolExtra string) map[string][]byte {
	f := folder()
	f[FileCompose] = []byte(`services:
  tool:
    image: busybox:1.37
    volumes: ["` + toolMount + `"]
` + toolExtra + `    deploy:
      resources:
        limits: { memory: 32M, cpus: "0.1" }
  app:
    image: nginx:1.29-alpine
    environment:
      PASS: ${password}
    volumes: ["world:/srv/world"]
    healthcheck:
      test: ["CMD", "true"]
    expose: ["8080"]
    deploy:
      resources:
        limits: { memory: 64M, cpus: "0.5" }
volumes:
  world:
`)
	return f
}

func TestSharedVolumeBelongsToTheMainService(t *testing.T) {
	tp, err := Parse("xy", sharedFolder("world:/data:ro", ""))
	if err != nil {
		t.Fatal(err)
	}
	app, tool := tp.Services[0], tp.Services[1]
	if app.Name != "app" || app.Volumes[0].Owner != "" || !app.Stateful {
		t.Errorf("main service must own the volume: %+v", app)
	}
	if tool.Volumes[0].Owner != "app" || !tool.Volumes[0].ReadOnly || tool.Stateful {
		t.Errorf("helper must mount the main service's volume, read-only and stateless: %+v", tool)
	}
	r, err := tp.Render(sampleVals(tp))
	if err != nil {
		t.Fatal(err)
	}
	if v := r.Services[0].Volumes[0]; v.Service != "" {
		t.Errorf("owner volume rendered as another's: %+v", v)
	}
	if v := r.Services[1].Volumes[0]; v.Service != "svc" || v.Name != "world" || v.Path != "/data" {
		t.Errorf("shared volume rendered: %+v", v)
	}

	// A helper that writes to the shared volume is stateful: it needs a
	// healthcheck like any service that keeps data.
	if _, err := Parse("xy", sharedFolder("world:/data", "")); err == nil || !strings.Contains(err.Error(), "services.tool.healthcheck: required") {
		t.Errorf("a writer without a healthcheck: %v", err)
	}
	if _, err := Parse("xy", sharedFolder("world:/data", "    healthcheck:\n      test: [\"CMD\", \"true\"]\n")); err != nil {
		t.Errorf("a writer with a healthcheck: %v", err)
	}
	if _, err := Parse("xy", sharedFolder(`world:/data:ro", "world:/more:ro`, "")); err == nil || !strings.Contains(err.Error(), "mounted twice") {
		t.Errorf("one volume twice in a service: %v", err)
	}
	// Still only volumes declared in this compose.yaml.
	if _, err := Parse("xy", sharedFolder("other:/data:ro", "")); err == nil || !strings.Contains(err.Error(), "declare it") {
		t.Errorf("an undeclared volume: %v", err)
	}
}
