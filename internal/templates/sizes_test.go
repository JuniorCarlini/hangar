package templates

import (
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/volumes"
)

func withSize(f map[string][]byte, table string) map[string][]byte {
	f[FileMeta] = append(append([]byte{}, f[FileMeta]...), []byte("\n"+table+"\n")...)
	return f
}

func TestVolumeSizes(t *testing.T) {
	tp, err := Parse("xy", withSize(sharedFolder("world:/data:ro", ""), "[volumes.world]\nsize = \"20GB\""))
	if err != nil {
		t.Fatal(err)
	}
	if tp.Sizes["world"] != 20*volumes.GiB {
		t.Errorf("sizes = %v", tp.Sizes)
	}
	for table, want := range map[string]string{
		"[volumes.other]\nsize = \"20GB\"": `volumes.other: no service`,
		"[volumes.world]\nsize = \"20\"":   `volumes.world: size "20"`,
		"[volumes.world]\nsize = \"0GB\"":  `volumes.world: size "0GB"`,
		"[volumes.world]\nsize = \"20MB\"": `volumes.world: size "20MB"`,
		"[volumes.world]\nsize = \"99TB\"": `between 1GB and`,
		"[volumes.world]\nlimit = \"1GB\"": `volumes.world.limit: unknown key`,
	} {
		_, err := Parse("xy", withSize(sharedFolder("world:/data:ro", ""), table))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", table, err, want)
		}
	}
}

// The storage and database templates of the catalog come with a size.
func TestCatalogSizes(t *testing.T) {
	c := Builtin()
	for id, want := range map[string]int64{"rustfs": 50 * volumes.GiB, "postgres": 10 * volumes.GiB, "mariadb": 10 * volumes.GiB, "mongodb": 10 * volumes.GiB} {
		tp, ok := c.Get(id)
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if tp.Sizes["data"] != want {
			t.Errorf("%s: sizes = %v", id, tp.Sizes)
		}
	}
	if tp, _ := c.Get("redis-cache"); len(tp.Sizes) != 0 {
		t.Errorf("redis-cache has a size: %v", tp.Sizes)
	}
}
