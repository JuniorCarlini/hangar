package templates

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFolders lays template folders out on disk, as the community
// repository does.
func writeFolders(t *testing.T, folders map[string]map[string][]byte) string {
	t.Helper()
	root := t.TempDir()
	for id, files := range folders {
		if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
			t.Fatal(err)
		}
		for name, data := range files {
			if err := os.WriteFile(filepath.Join(root, id, name), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}

// community returns a folder with id and version, from the minimal valid
// template.
func community(id string, version, extra string) map[string][]byte {
	f := folder()
	meta := strings.Replace(string(f[FileMeta]), `id = "xy"`, `id = "`+id+`"`, 1)
	meta = strings.Replace(meta, "version = 1", "version = "+version+extra, 1)
	f[FileMeta] = []byte(meta)
	return f
}

func TestPackIsDeterministicAndRoundTrips(t *testing.T) {
	root := writeFolders(t, map[string]map[string][]byte{"aa": community("aa", "1", ""), "bb": community("bb", "2", "")})
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("repo readme"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := Pack(root)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Pack(root)
	if !bytes.Equal(a, b) {
		t.Error("packing the same folders twice must give the same bytes")
	}
	folders, err := Unpack(a)
	if err != nil {
		t.Fatal(err)
	}
	ok, skipped := Accept(folders, "v1.0.0")
	if len(ok) != 2 || len(skipped) != 0 || !ok[0].Remote {
		t.Errorf("accepted %d, skipped %v", len(ok), skipped)
	}

	bad := writeFolders(t, map[string]map[string][]byte{"aa": with(FileCompose, "nginx:1.29-alpine", "nginx:latest")})
	if _, err := Pack(bad); err == nil {
		t.Error("pack must refuse an invalid template")
	}
}

func TestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	data := []byte("catalog")
	sig := SignCatalog(data, priv)
	if err := VerifyCatalog(pub, data, sig); err != nil {
		t.Errorf("good signature refused: %v", err)
	}
	for name, c := range map[string]struct {
		pub  ed25519.PublicKey
		data []byte
		sig  string
	}{
		"other key":   {otherPub, data, sig},
		"changed":     {pub, []byte("catalog!"), sig},
		"unsigned":    {pub, data, ""},
		"garbage sig": {pub, data, "not base64"},
		"no key":      {nil, data, sig},
	} {
		if err := VerifyCatalog(c.pub, c.data, c.sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUnpackRefusesUnsafeArchives(t *testing.T) {
	build := func(hdrs ...*tar.Header) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		for _, h := range hdrs {
			if h.Typeflag == tar.TypeReg {
				h.Size = 1
			}
			_ = tw.WriteHeader(h)
			if h.Typeflag == tar.TypeReg {
				_, _ = tw.Write([]byte("x"))
			}
		}
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}
	cases := map[string]*tar.Header{
		"traversal": {Name: "../etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644},
		"absolute":  {Name: "/etc/passwd", Typeflag: tar.TypeReg, Mode: 0o644},
		"nested":    {Name: "aa/sub/file", Typeflag: tar.TypeReg, Mode: 0o644},
		"symlink":   {Name: "aa/logo.svg", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		"root file": {Name: "file", Typeflag: tar.TypeReg, Mode: 0o644},
	}
	for name, h := range cases {
		if _, err := Unpack(build(h)); err == nil {
			t.Errorf("%s: archive accepted", name)
		}
	}
	if _, err := Unpack(bytes.Repeat([]byte{1}, MaxCatalogBytes+1)); err == nil {
		t.Error("an oversized tarball must be refused")
	}
}

func TestAcceptSkipsInvalidAndTooNew(t *testing.T) {
	folders := map[string]map[string][]byte{
		"good":   community("good", "1", ""),
		"unsafe": with(FileCompose, "    environment:\n", "    privileged: true\n    environment:\n"),
		"future": community("future", "1", "\nmin_hangar = \"v9.0.0\""),
		"now":    community("now", "1", "\nmin_hangar = \"v1.2.0\""),
	}
	folders["unsafe"][FileMeta] = []byte(strings.Replace(string(folders["unsafe"][FileMeta]), `"xy"`, `"unsafe"`, 1))
	ok, skipped := Accept(folders, "v1.2.3")
	var ids []string
	for _, tp := range ok {
		ids = append(ids, tp.ID)
	}
	if strings.Join(ids, ",") != "good,now" || len(skipped) != 2 {
		t.Errorf("accepted %v, skipped %v", ids, skipped)
	}
	// A development build is not held back by min_hangar.
	if ok, _ := Accept(map[string]map[string][]byte{"future": folders["future"]}, "dev"); len(ok) != 1 {
		t.Error("dev builds accept any min_hangar")
	}
	if !runsOn("v1.2.0", "v1.2.0-3-gabcdef-dirty") || runsOn("v1.3.0", "v1.2.9") {
		t.Error("runsOn")
	}
}

func TestMergeHigherVersionWinsEmbeddedWinsTies(t *testing.T) {
	base := NewCatalog([]*Template{{ID: "postgres", Version: 2}, {ID: "redis-cache", Version: 1}})
	merged := Merge(base, []*Template{
		{ID: "postgres", Version: 2, Remote: true},    // tie: embedded stays
		{ID: "redis-cache", Version: 3, Remote: true}, // newer: remote wins
		{ID: "n8n", Version: 1, Remote: true},         // new id: added
	})
	pg, _ := merged.Get("postgres")
	rc, _ := merged.Get("redis-cache")
	_, hasN8n := merged.Get("n8n")
	if pg.Remote || !rc.Remote || rc.Version != 3 || !hasN8n || len(merged.List()) != 3 {
		t.Errorf("merge: postgres remote=%v redis v%d remote=%v n8n=%v", pg.Remote, rc.Version, rc.Remote, hasN8n)
	}
	if merged.List()[0].ID != "n8n" {
		t.Error("merged catalog must be sorted")
	}
}
