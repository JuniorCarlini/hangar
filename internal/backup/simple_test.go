package backup

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// In the simple mode a destination is enough: backups are encrypted to
// the server's own key, which the panel uses itself to open them.
func TestSimpleModeNeedsNoKit(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	// The fixture pins the kit; unset, a panel without a kit is simple.
	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `""`}); err != nil {
		t.Fatal(err)
	}
	if got := f.m.Mode(ctx); got != ModeSimple {
		t.Fatalf("a new panel starts in %q", got)
	}
	var ie *i18n.Error
	if err := f.m.SetMode(ctx, f.who, ModeKit); !errors.As(err, &ie) || ie.Key != "backup.error.mode_kit" {
		t.Errorf("kit mode without a confirmed key: %v", err)
	}
	if _, err := f.m.AddTarget(ctx, f.who, validTarget()); err != nil {
		t.Fatal(err)
	}
	if !f.m.Ready(ctx) {
		t.Fatal("a destination should be enough")
	}
	rs, err := f.m.recipients(ctx)
	if err != nil || len(rs) != 1 {
		t.Fatalf("recipients: %v %v", rs, err)
	}
	var sealed bytes.Buffer
	w, _ := age.Encrypt(&sealed, rs...)
	_, _ = io.WriteString(w, "dump")
	_ = w.Close()
	r, err := age.Decrypt(&sealed, f.m.withServerIdentity(ctx, nil)...)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(r); string(b) != "dump" {
		t.Errorf("opened %q", b)
	}
	key, err := f.m.ServerKey(ctx, f.who)
	if err != nil || len(key) < 20 || key[:15] != "AGE-SECRET-KEY-" {
		t.Errorf("server key: %v", err)
	}
	if f.m.KitCheckDue(ctx) {
		t.Error("no kit to check in the simple mode")
	}
}

// The panel's backup carries the master key and the whole database: in the
// simple mode the server could open it for anyone with the admin download,
// handing over every secret kept for the owner. Only an owner gets it.
func TestPanelBackupDownloadIsOwnerOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if err := f.m.q.SetSetting(ctx, dbq.SetSettingParams{Key: settingMode, ValueJson: `""`}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.AddTarget(ctx, f.who, validTarget()); err != nil {
		t.Fatal(err)
	}
	runID, err := f.m.backupPanel(ctx, f.who, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.m.OpenRun(ctx, f.who, runID, false); err == nil {
		t.Fatal("an admin must not get the panel backup decrypted")
	}
	rc, _, err := f.m.OpenRun(ctx, f.who, runID, true)
	if err != nil {
		t.Fatalf("the owner opens the panel backup: %v", err)
	}
	_ = rc.Close()
}
