package audit_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(context.Background(), filepath.Join(dir, "hangar.db"), filepath.Join(dir, "backups"),
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func record(t *testing.T, l *audit.Logger, action string) {
	t.Helper()
	err := l.Record(context.Background(), audit.Entry{
		ActorID: "user-1", IP: "189.10.20.30", Action: action, Outcome: audit.OK,
		TargetType: "service", TargetID: "svc-1", Summary: map[string]any{"key": "SECRET_KEY"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestChainVerifies(t *testing.T) {
	s := openStore(t)
	l := audit.New(s.DB)
	for _, a := range []string{"login.ok", "sudo.ok", "secret.reveal"} {
		record(t, l, a)
	}

	n, err := audit.Verify(context.Background(), s.Q, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("checked %d records, want 3", n)
	}
}

func TestUpdateAndDeleteAreBlocked(t *testing.T) {
	s := openStore(t)
	record(t, audit.New(s.DB), "login.ok")

	if _, err := s.DB.Exec(`UPDATE audit_log SET action = 'nada'`); err == nil {
		t.Error("UPDATE on audit_log should fail")
	}
	if _, err := s.DB.Exec(`DELETE FROM audit_log`); err == nil {
		t.Error("DELETE on audit_log should fail")
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		tamper string
		wantID int64
	}{
		{"content changed", `UPDATE audit_log SET action = 'login.ok' WHERE id = 2`, 2},
		{"record removed", `DELETE FROM audit_log WHERE id = 2`, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := openStore(t)
			l := audit.New(s.DB)
			for _, a := range []string{"login.ok", "secret.reveal", "service.delete"} {
				record(t, l, a)
			}

			// Simulate someone who bypassed the triggers by editing the file.
			if _, err := s.DB.Exec(`DROP TRIGGER audit_log_no_update; DROP TRIGGER audit_log_no_delete;`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.DB.Exec(c.tamper); err != nil {
				t.Fatal(err)
			}

			_, err := audit.Verify(context.Background(), s.Q, nil)
			var te *audit.TamperError
			if !errors.As(err, &te) {
				t.Fatalf("expected TamperError, got %v", err)
			}
			if te.ID != c.wantID {
				t.Errorf("break reported at record %d, want %d", te.ID, c.wantID)
			}
		})
	}
}

func TestRecordRejectsInvalidEntry(t *testing.T) {
	l := audit.New(openStore(t).DB)
	if err := l.Record(context.Background(), audit.Entry{Outcome: audit.OK}); err == nil {
		t.Error("empty action should be refused")
	}
	if err := l.Record(context.Background(), audit.Entry{Action: "x", Outcome: "talvez"}); err == nil {
		t.Error("invalid outcome should be refused")
	}
	big := map[string]any{"x": strings.Repeat("a", audit.MaxSummaryBytes)}
	if err := l.Record(context.Background(), audit.Entry{Action: "x", Outcome: audit.OK, Summary: big}); err == nil {
		t.Error("summary over the limit should be refused")
	}
}
