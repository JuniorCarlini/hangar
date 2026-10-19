package projects

import (
	"context"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestComposeStopGracePeriod(t *testing.T) {
	plan, err := ParseCompose([]byte(`
services:
  game:
    image: ghcr.io/acme/server:2.1
    stop_grace_period: 45s
  slow:
    image: ghcr.io/acme/server:2.1
    stop_grace_period: 1h
  odd:
    image: ghcr.io/acme/server:2.1
    stop_grace_period: later
  db:
    image: postgres:18-alpine
    stop_grace_period: 90s
`), false)
	if err != nil {
		t.Fatal(err)
	}
	if s := svcByName(t, plan, "game"); s.StopGrace != 45 || !hasNote(s, NoteOK, "compose.note.stop_grace") {
		t.Errorf("game: %d %+v", s.StopGrace, s.Notes)
	}
	if s := svcByName(t, plan, "slow"); s.StopGrace != 120 || !hasNote(s, NoteWarn, "compose.note.stop_grace_clamped") {
		t.Errorf("slow: %d %+v", s.StopGrace, s.Notes)
	}
	if s := svcByName(t, plan, "odd"); s.StopGrace != 0 || !hasNote(s, NoteWarn, "compose.note.stop_grace_invalid") {
		t.Errorf("odd: %d %+v", s.StopGrace, s.Notes)
	}
	if s := svcByName(t, plan, "db"); s.StopGrace != 0 || !hasNote(s, NoteInfo, "compose.note.template_keeps") {
		t.Errorf("a catalog database keeps its template's settings: %d %+v", s.StopGrace, s.Notes)
	}

	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	plan, err = f.m.PlanCompose(ctx, "lab", []byte("services:\n  game:\n    image: ghcr.io/acme/server:2.1\n    stop_grace_period: 45s\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromCompose(ctx, f.who, "lab", plan, nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if spec, _ := f.n.spec("lab_game"); spec.StopGrace != 45*time.Second {
		t.Errorf("deploy spec stop grace: %s", spec.StopGrace)
	}
}

func TestTemplateStopGracePeriod(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.useTemplate(t, "slowstop", `services:
  app:
    image: nginx:1.29-alpine
    stop_grace_period: 100s
    deploy:
      resources:
        limits: { memory: 64M, cpus: "0.5" }
`)
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateFromTemplate(ctx, f.who, "lab", "slowstop", "srv", nil); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	spec, _ := f.n.spec("lab_srv")
	if spec.StopGrace != 100*time.Second {
		t.Errorf("stop grace: %s", spec.StopGrace)
	}
	if err := spec.Validate(); err != nil {
		t.Error(err)
	}
	// The copy a restore makes keeps it.
	c, err := f.m.CloneService(ctx, f.who, "lab", "srv", "srv-copy")
	if err != nil {
		t.Fatal(err)
	}
	if c.StopGraceS != 100 {
		t.Errorf("clone stop grace: %d", c.StopGraceS)
	}
	spec.StopGrace = node.MaxStopGrace + time.Second
	if err := spec.Validate(); err == nil {
		t.Error("the node must refuse more than the cap")
	}
}
