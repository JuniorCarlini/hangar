package templates

import (
	"strings"
	"testing"
)

// withVolume gives the minimal template a volume (and the healthcheck a
// service with one needs), mounted as written in mount.
func withVolume(mount string) map[string][]byte {
	f := with(FileCompose, "    environment:\n", "    volumes:\n      - "+mount+"\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n    environment:\n")
	f[FileCompose] = append(f[FileCompose], []byte("volumes:\n  data:\n")...)
	return f
}

func TestReadOnlyMounts(t *testing.T) {
	for mount, ro := range map[string]bool{
		"data:/data":    false,
		"data:/data:rw": false,
		"data:/data:ro": true,
		"{type: volume, source: data, target: /data, read_only: true}":  true,
		"{type: volume, source: data, target: /data, read_only: false}": false,
	} {
		tp, err := Parse("xy", withVolume(mount))
		if err != nil {
			t.Errorf("%s: %v", mount, err)
			continue
		}
		if v := tp.Services[0].Volumes[0]; v.Name != "data" || v.Path != "/data" || v.ReadOnly != ro {
			t.Errorf("%s: %+v", mount, v)
		}
		r, err := tp.Render(sampleVals(tp))
		if err != nil || r.Services[0].Volumes[0].ReadOnly != ro {
			t.Errorf("%s rendered: %+v %v", mount, r.Services, err)
		}
	}
	for mount, want := range map[string]string{
		"data:/data:z":    "name:/path:ro",
		"data:/data:ro,z": "name:/path:ro",
		"/srv:/data:ro":   "bind mounts",
		"{type: volume, source: data, target: /data, read_only: yes please}":  "read_only",
		"{type: volume, source: data, target: /data, volume: {nocopy: true}}": "only type, source, target and read_only",
	} {
		if _, err := Parse("xy", withVolume(mount)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want an error about %q", mount, err, want)
		}
	}
}
