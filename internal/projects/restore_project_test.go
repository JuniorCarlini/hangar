package projects

import (
	"errors"
	"testing"
)

// A value of the original project points at the copy: references that
// name the project itself, and its containers by name. Other projects'
// references, names that only look alike and the copy's own references
// stay as they are.
func TestRewriteRefs(t *testing.T) {
	svcs := []string{"db", "web", "web-api"}
	for in, want := range map[string]string{
		"${{db.DATABASE_URL}}":                      "${{db.DATABASE_URL}}",
		"${{lab.db.USER}}":                          "${{db.USER}}",
		"${{ lab.web-api.PORT }}":                   "${{web-api.PORT}}",
		"${{other.db.USER}}":                        "${{other.db.USER}}",
		"${{lab.cache.URL}}":                        "${{lab.cache.URL}}",
		"postgres://u:p@lab_db:5432/app":            "postgres://u:p@copia_db:5432/app",
		"http://lab_web-api:8080 http://lab_web:80": "http://copia_web-api:8080 http://copia_web:80",
		"lab_dbx mylab_db lab_db,lab_db":            "lab_dbx mylab_db copia_db,copia_db",
		"lab_cache":                                 "lab_cache",
	} {
		if got := RewriteRefs(in, "lab", "copia", svcs); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	if got := RewriteRefs("lab_db", "lab", "lab", svcs); got != "lab_db" {
		t.Errorf("same project: %q", got)
	}
}

// A file from a browser goes through the bounds of a form: names, images,
// limits, capabilities, volumes, variables.
func TestCheckSnapshots(t *testing.T) {
	ok := func() ServiceSnapshot {
		return ServiceSnapshot{
			Service: "web", Image: "nginx:1.29", Port: 80,
			Res:  SnapshotLimits{MemoryBytes: 256 << 20, NanoCPUs: 5e8, Pids: 256},
			Vols: []SnapshotVolume{{Name: "data", Path: "/data"}},
			Env:  []SnapshotVar{{Key: "A", Value: "1"}},
		}
	}
	if err := checkSnapshots([]ServiceSnapshot{ok()}); err != nil {
		t.Fatalf("a good snapshot: %v", err)
	}
	user := ok()
	user.Service = "worker"
	user.Vols = []SnapshotVolume{{Name: "data", Path: "/shared", From: "web"}}
	if err := checkSnapshots([]ServiceSnapshot{ok(), user}); err != nil {
		t.Fatalf("a shared volume of a service in the file: %v", err)
	}
	for name, edit := range map[string]func(*ServiceSnapshot){
		"slug":       func(s *ServiceSnapshot) { s.Service = "Web!" },
		"image":      func(s *ServiceSnapshot) { s.Image = "nginx; rm -rf /" },
		"no image":   func(s *ServiceSnapshot) { s.Image = "" },
		"memory":     func(s *ServiceSnapshot) { s.Res.MemoryBytes = 1 },
		"cpus":       func(s *ServiceSnapshot) { s.Res.NanoCPUs = 1e12 },
		"capability": func(s *ServiceSnapshot) { s.Res.CapAdd = []string{"SYS_ADMIN"} },
		"path":       func(s *ServiceSnapshot) { s.Vols[0].Path = "/../etc" },
		"reserved":   func(s *ServiceSnapshot) { s.Vols[0].Path = "/proc" },
		"shared":     func(s *ServiceSnapshot) { s.Vols[0].From = "ghost" },
		"env key":    func(s *ServiceSnapshot) { s.Env[0].Key = "A=B" },
		"port":       func(s *ServiceSnapshot) { s.Endpoints = []SnapshotEndpoint{{Port: 70000}} },
		"health":     func(s *ServiceSnapshot) { s.Check = []byte("{") },
		"grace":      func(s *ServiceSnapshot) { s.Deploy = &SnapshotDeploy{StartupGraceS: 24 * 3600} },
	} {
		s := ok()
		edit(&s)
		if err := checkSnapshots([]ServiceSnapshot{s}); !errors.Is(err, errBadSnapshot) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := checkSnapshots([]ServiceSnapshot{ok(), ok()}); !errors.Is(err, errBadSnapshot) {
		t.Error("the same service twice")
	}
	if err := checkSnapshots(nil); !errors.Is(err, errBadSnapshot) {
		t.Error("no services")
	}
}
