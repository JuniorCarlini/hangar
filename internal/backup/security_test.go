package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// reseal decrypts an age file with from and encrypts it again to to only.
func reseal(t *testing.T, data []byte, from age.Identity, to age.Recipient) []byte {
	t.Helper()
	r, err := age.Decrypt(bytes.NewReader(data), from)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w, err := age.Encrypt(&out, to)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// rebuild applies edit to the files of a project backup and writes a
// manifest whose sizes and sums match the edited files, as a forger would.
func rebuild(t *testing.T, zipped []byte, edit func(name string, data []byte) []byte) []byte {
	t.Helper()
	files, _ := unzip(t, zipped)
	man := manifestOf(t, files)
	edited := map[string][]byte{}
	for name, data := range files {
		if name != ManifestName {
			edited[name] = edit(name, data)
		}
	}
	fix := func(parts []ManifestPart) {
		for i := range parts {
			d := edited[parts[i].Path]
			sum := sha256.Sum256(d)
			parts[i].Size, parts[i].SHA256 = int64(len(d)), hex.EncodeToString(sum[:])
		}
	}
	fix(man.Parts)
	for i := range man.Services {
		fix(man.Services[i].Parts)
	}
	rawMan, _ := json.Marshal(man)
	return rezip(t, zipped, func(name string, data []byte) []byte {
		if name == ManifestName {
			return rawMan
		}
		return edited[name]
	})
}

// SEC-001: a file sealed only to the server's own key (as the panel's
// backups made in the simple mode are) must not open in a project
// restore, whatever kit comes with it: the server's key would decrypt
// it and hand the plaintext to a container the bundle names.
func TestProjectRestoreNeverUsesTheServerKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.projectLab(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	if _, err := f.m.backupDump(ctx, f.who, s, TriggerManual); err != nil {
		t.Fatal(err)
	}
	zipped := f.takeProject(t)
	sid, err := f.m.serverIdentity(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	forged := rebuild(t, zipped, func(name string, data []byte) []byte {
		if strings.HasSuffix(name, ".age") {
			return reseal(t, data, f.id, sid.Recipient())
		}
		return data
	})
	attacker, _ := age.GenerateX25519Identity()
	_, _, err = f.startRestore(t, forged, attacker)
	var ie *i18n.Error
	if !errors.As(err, &ie) || ie.Key != "project.restore.error.wrong_key" {
		t.Fatalf("a file only the server's key opens must be refused, got %v", err)
	}
	// The owner's own file, with the owner's kit, still restores.
	slug, _, err := f.startRestore(t, zipped, f.id)
	if err != nil {
		t.Fatal(err)
	}
	if r := f.finished(t, slug); r.Status != "ok" {
		t.Fatalf("legitimate restore: %+v", r)
	}
}

// SEC-001: in the kit mode the download of an older backup is a signed
// link to the bucket; for the panel's own backup only an owner gets it,
// and the refusal is audited.
func TestPanelBackupLinkIsOwnerOnly(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.ready(t)
	runID, err := f.m.backupPanel(ctx, f.who, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.RunDownloadURL(ctx, f.who, runID, false); !errors.Is(err, projects.ErrNotFound) {
		t.Fatalf("an admin must not get a link to the panel backup: %v", err)
	}
	var denied int
	if err := f.m.db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE action = 'backup.download_link' AND outcome = 'denied'`).Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if denied != 1 {
		t.Fatalf("denied downloads audited: %d", denied)
	}
	if u, err := f.m.RunDownloadURL(ctx, f.who, runID, true); err != nil || u == "" {
		t.Fatalf("the owner gets the link: %q %v", u, err)
	}
	// A service's backup still downloads for an admin.
	f.postgres(t)
	s, _ := f.m.ref(ctx, "lab", "db")
	dumpRun, err := f.m.backupDump(ctx, f.who, s, TriggerManual)
	if err != nil {
		t.Fatal(err)
	}
	if u, err := f.m.RunDownloadURL(ctx, f.who, dumpRun, false); err != nil || u == "" {
		t.Fatalf("an admin downloads a service backup: %q %v", u, err)
	}
}
