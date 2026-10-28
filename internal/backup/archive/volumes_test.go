package archive

import (
	"archive/tar"
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestVolumesKey(t *testing.T) {
	at := time.Date(2026, 10, 28, 3, 0, 0, 0, time.UTC)
	key := VolumesKey(ClassWeekly, "lobot", "rustfs", at)
	if key != "semanal/lobot/rustfs/20261028T030000Z.volumes.tar.zst.age" {
		t.Fatalf("key: %s", key)
	}
	o, ok := ParseKey(key)
	if !ok || o.Kind != KindVolume || o.Class != ClassWeekly || o.Project != "lobot" || o.Service != "rustfs" || !o.Time.Equal(at) {
		t.Fatalf("parsed: %+v %v", o, ok)
	}
	if !IsPoint(o.Kind) || IsPoint(KindWAL) || RolesKey(key) != "" {
		t.Fatal("a copy of volumes is a restore point with no roles")
	}
	if LimitsFor(key).MaxRatio != 0 || LimitsFor(DumpKey(ClassDaily, "a-b", "c-d", at)).MaxRatio == 0 {
		t.Fatal("only volumes may compress past the dump ratio")
	}
	if _, ok := ParseKey("diario/lobot/rustfs/20261028T030000Z.volumes.tar.age"); ok {
		t.Fatal("an unknown extension")
	}
}

func TestVolumeMetaRoundTrip(t *testing.T) {
	m := VolumeManifest{Volumes: []VolumeStat{{Name: "data", Entries: 7, Bytes: 12017, Need: 32768}, {Name: "uploads", Entries: 1, Need: 4096}}}
	got, ok := ParseVolumeMeta(m.Meta())
	if !ok || got.Entries != 8 || got.Bytes != 12017 || len(got.Volumes) != 2 || got.Volumes[1] != m.Volumes[1] {
		t.Fatalf("round trip: %+v %v", got, ok)
	}
	for _, bad := range []string{"", "data:1:2", "data:1:2:-3", ":1:2:3"} {
		if _, ok := ParseVolumeMeta(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func volTar(t *testing.T, hs ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, h := range hs {
		h.Format = tar.FormatPAX
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(bytes.Repeat([]byte("x"), int(h.Size)))
		}
	}
	_ = tw.Close()
	buf.Write(make([]byte, 4096)) // padding after the end, as GNU tar leaves
	return buf.Bytes()
}

func dir(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755} }

func TestScanVolumes(t *testing.T) {
	good := volTar(t,
		dir("data/"), reg("data/a", 5000), dir("data/sub/"), dir("data/empty/"),
		&tar.Header{Name: "data/abs", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		&tar.Header{Name: "data/hard", Typeflag: tar.TypeLink, Linkname: "data/a"},
		&tar.Header{Name: "data/fifo", Typeflag: tar.TypeFifo},
		dir("uploads/"), reg("uploads/b", 1),
	)
	m, err := ScanVolumes(bytes.NewReader(good), []string{"data", "uploads"}, VolumeTarLimits)
	if err != nil {
		t.Fatal(err)
	}
	if m.Entries != 9 || m.Bytes != 5001 || len(m.Volumes) != 2 {
		t.Fatalf("manifest: %+v", m)
	}
	// data: 3 folders and 5000 bytes in two blocks.
	if d, _ := m.Volume("data"); d.Entries != 7 || d.Need != 3*4096+2*4096 {
		t.Fatalf("data: %+v", d)
	}
	cases := map[string][]byte{
		"outside the volumes": volTar(t, dir("data/"), dir("etc/")),
		"no volume folder":    volTar(t, reg("data/a", 1)),
		"dot dot":             volTar(t, dir("data/"), reg("data/../x", 1)),
		"absolute":            volTar(t, dir("data/"), reg("/data/x", 1)),
		"beneath a link":      volTar(t, dir("data/"), &tar.Header{Name: "data/l", Typeflag: tar.TypeSymlink, Linkname: "/"}, reg("data/l/x", 1)),
		"device":              volTar(t, dir("data/"), &tar.Header{Name: "data/null", Typeflag: tar.TypeChar}),
		"hard link out":       volTar(t, dir("data/"), dir("uploads/"), reg("uploads/b", 1), &tar.Header{Name: "data/h", Typeflag: tar.TypeLink, Linkname: "uploads/b"}),
	}
	for name, b := range cases {
		if _, err := ScanVolumes(bytes.NewReader(b), []string{"data", "uploads"}, VolumeTarLimits); err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrUnsafePath) && !strings.Contains(err.Error(), "read the copy") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ScanVolumes(bytes.NewReader(good), []string{"data", "uploads"}, TarLimits{MaxEntries: 3}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("entries limit: %v", err)
	}
}
