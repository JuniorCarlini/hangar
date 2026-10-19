package app

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func TestInstanceIDIsStable(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "h.db"), filepath.Join(dir, "b"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	first, err := InstanceID(ctx, st.Q)
	if err != nil || !strings.HasPrefix(first, "hgi_") {
		t.Fatalf("InstanceID = %q, %v", first, err)
	}
	again, err := InstanceID(ctx, st.Q)
	if err != nil || again != first {
		t.Fatalf("the id must never change: %q then %q (%v)", first, again, err)
	}

	adopt := adoptFunc(st.Q)
	if err := st.Q.CreateProject(ctx, dbq.CreateProjectParams{ID: "prj_a", Slug: "a", Name: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Q.CreateService(ctx, dbq.CreateServiceParams{ID: "svc_a", ProjectID: "prj_a", Slug: "web", Image: "nginx:1", CommandJson: "[]"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		project, service string
		want             bool
	}{
		{"prj_a", "", true}, {"prj_a", "svc_a", true}, {"prj_b", "", false}, {"prj_b", "svc_a", false}, {"prj_a", "svc_b", false},
	} {
		if got := adopt(ctx, c.project, c.service); got != c.want {
			t.Errorf("adopt(%s, %s) = %v", c.project, c.service, got)
		}
	}
}
