package volumes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const vol = "hangar_shop_db_data"

func TestValidName(t *testing.T) {
	for _, ok := range []string{vol, "hangar_a1_web-2_media", "hangar_my-project_files_uploads-1"} {
		if !ValidName(ok) {
			t.Errorf("refused %q", ok)
		}
	}
	for _, bad := range []string{
		"", "data", "hangar_shop_db", "hangar_shop_db_data/../x", "hangar_shop_db_../../etc",
		"hangar_Shop_db_data", "hangar_shop_db_data ", "other_shop_db_data", "hangar_shop__data",
		"hangar_shop_db_data.img", "hangar_shop_db_da\x00ta", "/var/lib/hangar_shop_db_data",
	} {
		if ValidName(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestValidate(t *testing.T) {
	good := State{Version: 1, Volumes: []Entry{
		{Name: vol, Op: OpMount, Size: 2 * GiB},
		{Name: "hangar_shop_web_media", Op: OpImport, Size: MinSize},
		{Name: "hangar_shop_old_data", Op: OpRemove},
		{Name: "hangar_shop_xy_data", Op: OpExport},
	}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []State{
		{Version: 2},
		{Version: 1, Volumes: []Entry{{Name: vol, Op: OpMount, Size: MinSize - 1}}},
		{Version: 1, Volumes: []Entry{{Name: vol, Op: OpMount, Size: MaxSize + 1}}},
		{Version: 1, Volumes: []Entry{{Name: vol, Op: OpRemove, Size: GiB}}},
		{Version: 1, Volumes: []Entry{{Name: vol, Op: "format", Size: GiB}}},
		{Version: 1, Volumes: []Entry{{Name: "../etc", Op: OpRemove}}},
		{Version: 1, Volumes: []Entry{{Name: vol, Op: OpRemove}, {Name: vol, Op: OpRemove}}},
	} {
		if bad.Validate() == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	// Unknown fields are refused by the root side.
	if _, err := decodeState([]byte(`{"version":1,"written":1,"volumes":[],"path":"/etc"}`)); err == nil {
		t.Error("unknown field accepted")
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"20GB": 20 * GiB, "1gb": GiB, " 50 GB": 50 * GiB, "2TB": 2 << 40} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "0GB", "20", "20MB", "1.5GB", "-1GB", "9TB", "20 G", "GB"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("ParseSize(%q) accepted", bad)
		}
	}
}

func TestWriterResults(t *testing.T) {
	dir := t.TempDir()
	w := NewWriter(dir)
	if w.Available() {
		t.Fatal("available before the unit ever ran")
	}
	n := int64(0)
	w.now = func() time.Time { n++; return time.Unix(0, n) }
	if err := w.Write([]Entry{{Name: vol, Op: OpMount, Size: 2 * GiB}}, false); err != nil {
		t.Fatal(err)
	}
	first := w.Current()
	if len(first.Volumes) != 1 || first.Written == 0 {
		t.Fatalf("desired = %+v", first)
	}
	// The same entries again: nothing is written (the unit is not woken).
	if err := w.Write([]Entry{{Name: vol, Op: OpMount, Size: 2 * GiB}}, false); err != nil {
		t.Fatal(err)
	}
	if w.Current().Written != first.Written {
		t.Error("rewrote an unchanged state")
	}
	if _, current, _ := w.Results(); current {
		t.Error("current before any answer")
	}
	// The unit answers this write.
	if err := (&Applier{Paths: w.Paths, NotRoot: true}).report(first, Applied{Volumes: []Result{{Name: vol, Op: OpMount, OK: true}}}); err != nil {
		t.Fatal(err)
	}
	res, current, _ := w.Results()
	if !current || !res[vol].OK || !w.Available() {
		t.Errorf("results = %+v, current %v", res, current)
	}
	// A forced write (the panel starting) is a new state: the old answer
	// no longer counts.
	if err := w.Write([]Entry{{Name: vol, Op: OpMount, Size: 2 * GiB}}, true); err != nil {
		t.Fatal(err)
	}
	if _, current, _ := w.Results(); current {
		t.Error("an answer to the previous write counted")
	}
	// The writer refuses what the unit would refuse.
	if err := w.Write([]Entry{{Name: "../../etc/passwd", Op: OpRemove}}, false); err == nil {
		t.Error("invalid entry written")
	}
}

func TestParseMountinfo(t *testing.T) {
	m := parseMountinfo(`22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw
98 22 7:0 / /var/lib/hangar/volume-mounts/hangar_a_b_c rw,nosuid,nodev,relatime shared:50 - ext4 /dev/loop0 rw
99 22 7:1 / /mnt/with\040space rw - ext4 /dev/loop1 rw
`)
	if m["/var/lib/hangar/volume-mounts/hangar_a_b_c"] != "/dev/loop0" || m["/mnt/with space"] != "/dev/loop1" || m["/"] != "/dev/sda1" {
		t.Errorf("mounts = %v", m)
	}
}

func TestDesiredFileIsReadableJSON(t *testing.T) {
	w := NewWriter(t.TempDir())
	if err := w.Write(nil, true); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(w.Paths.Dir(), desiredFile))
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(raw, &st); err != nil || st.Volumes == nil || !strings.Contains(string(raw), `"volumes": []`) {
		t.Errorf("desired = %s (%v)", raw, err)
	}
}
