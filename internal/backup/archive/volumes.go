package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// A copy of a service's volumes is one tar (GNU tar, POSIX format, owners
// as numbers, permissions, ACLs, user.* extended attributes, sparse files
// kept sparse) with a folder per volume at the top, named as the volume:
// "data/", "data/.rustfs.sys/...", "uploads/...". The folder itself is in
// the tar too, so the owner and mode of the volume's root come back.

// blockSize is the unit a restored file takes on disk at least (ext4).
const blockSize = 4096

// VolumeStat is what a copy holds of one volume.
type VolumeStat struct {
	Name string `json:"name"`
	// Entries are files, folders, links and FIFOs, the folder of the
	// volume included.
	Entries int64 `json:"entries"`
	// Bytes is the size of the files' contents (a file with several hard
	// links counts once).
	Bytes int64 `json:"bytes"`
	// Need is the least disk the volume takes once restored: each file
	// rounded up to whole blocks, a block per folder.
	Need int64 `json:"need"`
}

// VolumeManifest is what ScanVolumes found.
type VolumeManifest struct {
	Volumes []VolumeStat `json:"volumes"`
	Entries int64        `json:"entries"`
	Bytes   int64        `json:"bytes"`
}

// Volume returns the stat of the volume name.
func (m VolumeManifest) Volume(name string) (VolumeStat, bool) {
	for _, v := range m.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return VolumeStat{}, false
}

// Names lists the volumes in the copy.
func (m VolumeManifest) Names() []string {
	out := make([]string, 0, len(m.Volumes))
	for _, v := range m.Volumes {
		out = append(out, v.Name)
	}
	return out
}

// Meta is the manifest as object metadata ("data:entries:bytes:need,..."),
// so a restore checks the target's disks before it changes anything.
// Volume names are [a-z0-9-]: nothing here needs escaping.
func (m VolumeManifest) Meta() string {
	parts := make([]string, 0, len(m.Volumes))
	for _, v := range m.Volumes {
		parts = append(parts, fmt.Sprintf("%s:%d:%d:%d", v.Name, v.Entries, v.Bytes, v.Need))
	}
	return strings.Join(parts, ",")
}

// ParseVolumeMeta reads Meta back. ok is false for anything else.
func ParseVolumeMeta(s string) (VolumeManifest, bool) {
	var m VolumeManifest
	if s == "" {
		return m, false
	}
	for _, part := range strings.Split(s, ",") {
		f := strings.Split(part, ":")
		if len(f) != 4 || f[0] == "" {
			return VolumeManifest{}, false
		}
		var n [3]int64
		for i := range n {
			v, err := strconv.ParseInt(f[i+1], 10, 64)
			if err != nil || v < 0 {
				return VolumeManifest{}, false
			}
			n[i] = v
		}
		m.Volumes = append(m.Volumes, VolumeStat{Name: f[0], Entries: n[0], Bytes: n[1], Need: n[2]})
		m.Entries += n[0]
		m.Bytes += n[1]
	}
	return m, true
}

// VolumeTarLimits bound a copy of volumes: the largest disk Hangar makes,
// and more entries than any app keeps.
var VolumeTarLimits = TarLimits{MaxBytes: 8 << 40, MaxEntries: 50_000_000}

// ScanVolumes reads a volumes tar and checks every entry before anything
// is restored from it: a safe name inside one of the volumes named, a
// type a volume holds (files, folders, symlinks, hard links within the
// same volume, FIFOs), within lim. Symlinks may point anywhere, as apps
// keep them (they are restored as links, never followed), but nothing
// may sit beneath one. It counts what each volume holds and, once the
// tar ends, reads r to its end so whoever feeds it never blocks.
func ScanVolumes(r io.Reader, names []string, lim TarLimits) (VolumeManifest, error) {
	var m VolumeManifest
	idx := map[string]int{}
	tr := tar.NewReader(r)
	seen := links{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("read the copy: %w", err)
		}
		name, err := CleanName(h.Name)
		if err != nil {
			return m, err
		}
		top, _, _ := strings.Cut(name, "/")
		if !slices.Contains(names, top) {
			return m, fmt.Errorf("%w: %s is not in a volume of this service", ErrUnsafePath, name)
		}
		if err := seen.check(name); err != nil {
			return m, err
		}
		i, ok := idx[top]
		if !ok {
			if name != top || h.Typeflag != tar.TypeDir {
				return m, fmt.Errorf("%w: the copy of %s does not start with its folder", ErrUnsafePath, top)
			}
			i = len(m.Volumes)
			idx[top] = i
			m.Volumes = append(m.Volumes, VolumeStat{Name: top})
		}
		v := &m.Volumes[i]
		switch h.Typeflag {
		case tar.TypeDir:
			v.Need += blockSize
		case tar.TypeReg, tar.TypeGNUSparse:
			if h.Size < 0 {
				return m, fmt.Errorf("%w: negative size for %s", ErrUnsafePath, name)
			}
			v.Bytes += h.Size
			m.Bytes += h.Size
			v.Need += (h.Size + blockSize - 1) / blockSize * blockSize
			if lim.MaxBytes > 0 && m.Bytes > lim.MaxBytes {
				return m, ErrTooLarge
			}
		case tar.TypeSymlink:
			if h.Linkname == "" || strings.ContainsRune(h.Linkname, 0) {
				return m, fmt.Errorf("%w: bad link %s", ErrUnsafePath, name)
			}
			seen[name] = true
		case tar.TypeLink:
			target, err := CleanName(h.Linkname)
			if err != nil {
				return m, err
			}
			if t, _, _ := strings.Cut(target, "/"); t != top {
				return m, fmt.Errorf("%w: %s links to another volume", ErrUnsafePath, name)
			}
		case tar.TypeFifo:
		default:
			// Devices need a capability no helper has, and no app keeps
			// them in a volume.
			return m, fmt.Errorf("%w: unsupported entry type %q for %s", ErrUnsafePath, h.Typeflag, name)
		}
		v.Entries++
		m.Entries++
		if lim.MaxEntries > 0 && m.Entries > int64(lim.MaxEntries) {
			return m, ErrTooLarge
		}
	}
	// GNU tar pads the archive to whole records after its end marker.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return m, err
	}
	return m, nil
}
