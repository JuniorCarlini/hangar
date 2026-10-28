package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func newKey(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func seal(t *testing.T, data []byte, compress bool, ids ...*age.X25519Identity) []byte {
	t.Helper()
	var pubs []string
	for _, id := range ids {
		pubs = append(pubs, id.Recipient().String())
	}
	rs, err := ParseRecipients(pubs)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := Seal(&buf, rs, compress)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(t *testing.T, sealed []byte, lim Limits, ids ...*age.X25519Identity) ([]byte, error) {
	t.Helper()
	r, err := Open(bytes.NewReader(sealed), Identities(ids), lim)
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}

func TestSealOpenRoundTripBothRecipients(t *testing.T) {
	mine, spare, stranger := newKey(t), newKey(t), newKey(t)
	data := bytes.Repeat([]byte("pedido 42; "), 10000)
	for _, compress := range []bool{false, true} {
		sealed := seal(t, data, compress, mine, spare)
		if bytes.Contains(sealed, []byte("pedido 42")) {
			t.Fatal("ciphertext contains the plaintext")
		}
		if compress && len(sealed) > len(data)/4 {
			t.Errorf("compressed size %d is not smaller", len(sealed))
		}
		for _, id := range []*age.X25519Identity{mine, spare} {
			got, err := open(t, sealed, DefaultLimits, id)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("compress=%v: round trip failed: %v", compress, err)
			}
		}
		if _, err := open(t, sealed, DefaultLimits, stranger); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("a stranger's key must not open it: %v", err)
		}
	}
	if _, err := ParseRecipients([]string{"age1naoexiste"}); err == nil {
		t.Fatal("a broken public key must fail")
	}
}

func TestOpenRefusesBombs(t *testing.T) {
	id := newKey(t)
	big := make([]byte, 80<<20) // zeros compress thousands of times
	sealed := seal(t, big, true, id)
	if _, err := open(t, sealed, Limits{MaxRatio: 200}, id); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("ratio limit: %v", err)
	}
	if _, err := open(t, seal(t, []byte(strings.Repeat("x", 2000)), false, id), Limits{MaxBytes: 1000}, id); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("size limit: %v", err)
	}
}

func kitText(id *age.X25519Identity) string {
	return "# Hangar - Kit de recuperação\r\n# Chave pública: " + id.Recipient().String() + "\r\n\r\n" + id.String() + "\r\n"
}

func TestParseKitPlainAndProtected(t *testing.T) {
	id := newKey(t)
	keys, err := ParseKit([]byte(kitText(id)), "")
	if err != nil || len(keys) != 1 || keys[0].String() != id.String() {
		t.Fatalf("plain kit: %v", err)
	}
	if !KitMatches(keys, id.Recipient().String()) || KitMatches(keys, newKey(t).Recipient().String()) {
		t.Fatal("KitMatches")
	}
	prot, err := ProtectKit([]byte(kitText(id)), "uma frase longa o bastante")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(prot, []byte("AGE-SECRET-KEY")) {
		t.Fatal("protected kit leaks the key")
	}
	if _, err := ParseKit(prot, ""); !errors.Is(err, ErrKitPassphrase) {
		t.Fatalf("no passphrase: %v", err)
	}
	if _, err := ParseKit(prot, "errada errada errada"); !errors.Is(err, ErrKitPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	keys, err = ParseKit(prot, "uma frase longa o bastante")
	if err != nil || keys[0].String() != id.String() {
		t.Fatalf("protected kit: %v", err)
	}
	if _, err := ParseKit([]byte("# nada aqui\n"), ""); err == nil {
		t.Fatal("a kit without a key must fail")
	}
}

// KnownKey and KnownCode pin the confirmation code algorithm; the browser
// (kit.js) must produce the same code, which kit_test.go checks with node.
const (
	KnownKey  = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
	KnownCode = "R3P2-2O4K-NDNI"
)

func TestConfirmCodeIsStable(t *testing.T) {
	id, err := age.ParseX25519Identity(KnownKey)
	if err != nil {
		t.Fatal(err)
	}
	code := ConfirmCode(id)
	if len(code) != 14 || code[4] != '-' || code[9] != '-' {
		t.Fatalf("format: %q", code)
	}
	if CodeHash(code) != CodeHash(strings.ToLower(strings.ReplaceAll(code, "-", " "))) {
		t.Fatal("typed variants must hash the same")
	}
	if code != KnownCode {
		t.Fatalf("code changed: %q (kit.js must change too)", code)
	}
}

func TestKeysRoundTrip(t *testing.T) {
	ts := time.Date(2026, 10, 15, 14, 32, 5, 0, time.UTC)
	cases := []struct {
		key  string
		kind string
	}{
		{DumpKey(ClassWeekly, "loja", "db", ts), KindDump},
		{BaseKey("loja", "db", ts, "000000010000000000000003"), KindBase},
		{WALKey("loja", "db", "000000010000000000000004"), KindWAL},
		{WALKey("loja", "db", "00000002.history"), KindWAL},
		{PanelKey(ts), KindPanel},
	}
	for _, c := range cases {
		o, ok := ParseKey(c.key)
		if !ok || o.Kind != c.kind {
			t.Fatalf("%s: %+v %v", c.key, o, ok)
		}
		if c.kind != KindWAL && !o.Time.Equal(ts) {
			t.Errorf("%s: time %v", c.key, o.Time)
		}
	}
	if o, _ := ParseKey(DumpKey(ClassWeekly, "loja", "db", ts)); o.Class != ClassWeekly || !strings.HasPrefix(o.Key, "semanal/") {
		t.Errorf("weekly folder: %+v", o)
	}
	for _, bad := range []string{"../x", "diario/loja/db/x.dump.age", "wal/loja/db/seg/../../x.zst.age", "wal/loja/db/seg/0000.zst.age"} {
		if _, ok := ParseKey(bad); ok {
			t.Errorf("%q must not parse", bad)
		}
	}
	if !WALNameRE.MatchString("000000010000000000000004") || WALNameRE.MatchString("x; rm -rf /") || WALNameRE.MatchString("000000010000000000000004.partial") {
		t.Error("WALNameRE")
	}
}

func TestPlanRecovery(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	objs := []Listed{
		{Key: BaseKey("lab", "db", t0.Add(-24*time.Hour), "000000010000000000000001"), LastModified: t0.Add(-24 * time.Hour)},
		{Key: BaseKey("lab", "db", t0, "000000010000000000000005"), LastModified: t0.Add(time.Minute)},
		{Key: WALKey("lab", "db", "000000010000000000000004"), LastModified: t0.Add(-time.Hour)},
		{Key: WALKey("lab", "db", "000000010000000000000006"), LastModified: t0.Add(2 * time.Hour)},
		{Key: WALKey("lab", "db", "000000010000000000000005"), LastModified: t0.Add(time.Hour)},
		{Key: WALKey("lab", "db", "00000002.history"), LastModified: t0.Add(time.Hour)},
		{Key: "lixo/qualquer", LastModified: t0},
	}
	p, err := PlanRecovery(objs, t0.Add(90*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if p.BaseObj.StartSegment != "000000010000000000000005" || p.ToEnd {
		t.Fatalf("plan: %+v", p)
	}
	var names []string
	for _, w := range p.WAL {
		names = append(names, walName(w.Key))
	}
	if strings.Join(names, ",") != "000000010000000000000005,000000010000000000000006,00000002.history" {
		t.Fatalf("wal: %v", names)
	}
	if s := RecoverySettings(p); !strings.Contains(s, "recovery_target_time = '2026-10-15 04:30:00+00'") {
		t.Fatalf("settings: %s", s)
	}
	// After everything archived: replay to the end.
	if p, _ := PlanRecovery(objs, t0.Add(5*time.Hour)); !p.ToEnd || strings.Contains(RecoverySettings(p), "recovery_target_time") {
		t.Fatalf("to end: %+v", p)
	}
	// Before the second base finished: the first one is used.
	if p, _ := PlanRecovery(objs, t0.Add(30*time.Second)); p.BaseObj.StartSegment != "000000010000000000000001" {
		t.Fatalf("older base: %+v", p.BaseObj)
	}
	if _, err := PlanRecovery(objs, t0.Add(-48*time.Hour)); !errors.Is(err, ErrNoBase) {
		t.Fatalf("no base: %v", err)
	}
}

func tarOf(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range entries {
		body := ""
		if h.Typeflag == tar.TypeReg {
			body = strings.Repeat("x", int(h.Size))
			if h.Name == "backup_label" {
				body = "START WAL LOCATION: 0/5000028 (file 000000010000000000000005)\n"
				h.Size = int64(len(body))
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func reg(name string, size int64) *tar.Header {
	return &tar.Header{Name: name, Size: size, Mode: 0o600, Typeflag: tar.TypeReg}
}

func TestCheckBaseAndUnsafeEntries(t *testing.T) {
	good := tarOf(t, reg("PG_VERSION", 3), reg("backup_label", 0), &tar.Header{Name: "base/", Typeflag: tar.TypeDir, Mode: 0o700}, reg("base/1/123", 10))
	var out bytes.Buffer
	info, err := CheckBase(bytes.NewReader(good), &out)
	if err != nil || info.StartSegment != "000000010000000000000005" || info.Files != 3 {
		t.Fatalf("good base: %+v %v", info, err)
	}
	if _, err := CheckBase(bytes.NewReader(tarOf(t, reg("base/1/123", 10))), io.Discard); err == nil {
		t.Fatal("a tar without PG_VERSION must fail")
	}
	for _, bad := range []*tar.Header{
		reg("../../etc/passwd", 1),
		reg("/etc/passwd", 1),
		{Name: "pg_tblspc/1", Typeflag: tar.TypeSymlink, Linkname: "/etc"},
		{Name: "a/link", Typeflag: tar.TypeSymlink, Linkname: "../../x"},
		{Name: "dev", Typeflag: tar.TypeChar},
	} {
		b := tarOf(t, reg("PG_VERSION", 3), bad)
		if _, err := CheckBase(bytes.NewReader(b), io.Discard); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("%s: %v", bad.Name, err)
		}
		if err := Extract(bytes.NewReader(b), t.TempDir(), DefaultTarLimits); !errors.Is(err, ErrUnsafePath) {
			t.Errorf("extract %s: %v", bad.Name, err)
		}
	}
}

func TestExtract(t *testing.T) {
	dir := t.TempDir()
	b := tarOf(t, &tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755}, reg("data/hangar.db", 5), reg("master.key", 32))
	if err := Extract(bytes.NewReader(b), dir, DefaultTarLimits); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(filepath.Join(dir, "master.key")); err != nil || st.Size() != 32 || st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("master.key: %v %v", st, err)
	}
	// Extracting twice never overwrites.
	if err := Extract(bytes.NewReader(b), dir, DefaultTarLimits); err == nil {
		t.Fatal("must not overwrite existing files")
	}
	if err := Extract(bytes.NewReader(tarOf(t, reg("a", 600), reg("b", 600))), t.TempDir(), TarLimits{MaxBytes: 1000}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
}

// Chained links pass the lexical target check one by one ("d" -> "x" is
// inside, "d/e" -> "../.." looks inside too) but a tar program that follows
// existing links on extraction would land "d/e" outside. An entry beneath an
// earlier symlink is refused; ordinary relative links still pass.
func TestTarRefusesEntriesBeneathALink(t *testing.T) {
	chained := tarOf(t,
		reg("PG_VERSION", 3),
		&tar.Header{Name: "d", Typeflag: tar.TypeSymlink, Linkname: "base"},
		&tar.Header{Name: "d/e", Typeflag: tar.TypeSymlink, Linkname: ".."},
	)
	if _, err := CheckBase(bytes.NewReader(chained), io.Discard); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("copy: %v", err)
	}
	if err := Extract(bytes.NewReader(chained), t.TempDir(), DefaultTarLimits); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("extract: %v", err)
	}
	ok := tarOf(t,
		reg("PG_VERSION", 3), reg("backup_label", 3),
		&tar.Header{Name: "node_modules/.bin/", Typeflag: tar.TypeDir, Mode: 0o755},
		&tar.Header{Name: "node_modules/.bin/tool", Typeflag: tar.TypeSymlink, Linkname: "../pkg/bin/tool"},
	)
	if _, err := CheckBase(bytes.NewReader(ok), io.Discard); err != nil {
		t.Errorf("an ordinary relative link was refused: %v", err)
	}
}
