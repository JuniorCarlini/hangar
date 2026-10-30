package archive

import (
	"archive/tar"
	"bytes"
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

// VolumeScan says how ScanVolumesTo reads a copy of volumes.
type VolumeScan struct {
	// Names are the volumes the copy may hold.
	Names  []string
	Limits TarLimits
	// Declared is what the copy says it holds (its metadata), when it
	// says: a volume found to hold more entries, bytes or disk than
	// declared, or one not declared, is refused as soon as it shows.
	Declared *VolumeManifest
	// Out, when set, receives the tar as it is read, but each entry's
	// header only once the entry passed every check: whatever extracts
	// from Out never sees an entry that was refused, nor anything after
	// it.
	Out io.Writer
}

// ScanVolumes reads a volumes tar and checks every entry (ScanVolumesTo
// with no Out and nothing declared).
func ScanVolumes(r io.Reader, names []string, lim TarLimits) (VolumeManifest, error) {
	return ScanVolumesTo(r, VolumeScan{Names: names, Limits: lim})
}

// ScanVolumesTo reads a volumes tar and checks every entry before anything
// is restored from it: a safe name inside one of the volumes named, a
// type a volume holds (files, folders, symlinks, hard links within the
// same volume, FIFOs), within the limits and what the copy declares.
// Symlinks may point anywhere, as apps keep them (they are restored as
// links, never followed), but nothing may sit beneath one, and no hard
// link may name a path beneath one. It counts what each volume holds and,
// once the tar ends, reads r to its end so whoever feeds it never blocks.
func ScanVolumesTo(r io.Reader, o VolumeScan) (VolumeManifest, error) {
	var m VolumeManifest
	idx := map[string]int{}
	g := &gate{r: r, out: o.Out}
	tr := tar.NewReader(g)
	seen := links{}
	buf := make([]byte, 1<<20)
	for {
		// Whatever Next reads (the rest of the previous entry's padding,
		// the next headers) is held until the entry is checked.
		g.hold = true
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return m, fmt.Errorf("read the copy: %w", err)
		}
		if err := o.check(&m, idx, seen, h); err != nil {
			return m, err
		}
		if err := g.release(); err != nil {
			return m, fmt.Errorf("read the copy: %w", err)
		}
		// The entry's content goes through as it is read.
		if _, err := io.CopyBuffer(io.Discard, tr, buf); err != nil {
			return m, fmt.Errorf("read the copy: %w", err)
		}
	}
	// The end marker, and the padding GNU tar adds after it.
	if err := g.release(); err != nil {
		return m, err
	}
	if _, err := io.CopyBuffer(io.Discard, g, buf); err != nil {
		return m, err
	}
	return m, nil
}

// check checks one entry and counts it in m.
func (o VolumeScan) check(m *VolumeManifest, idx map[string]int, seen links, h *tar.Header) error {
	name, err := CleanName(h.Name)
	if err != nil {
		return err
	}
	top, _, _ := strings.Cut(name, "/")
	if !slices.Contains(o.Names, top) {
		return fmt.Errorf("%w: %s is not in a volume of this service", ErrUnsafePath, name)
	}
	if err := seen.check(name); err != nil {
		return err
	}
	i, ok := idx[top]
	if !ok {
		if name != top || h.Typeflag != tar.TypeDir {
			return fmt.Errorf("%w: the copy of %s does not start with its folder", ErrUnsafePath, top)
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
			return fmt.Errorf("%w: negative size for %s", ErrUnsafePath, name)
		}
		v.Bytes += h.Size
		m.Bytes += h.Size
		v.Need += (h.Size + blockSize - 1) / blockSize * blockSize
		if o.Limits.MaxBytes > 0 && m.Bytes > o.Limits.MaxBytes {
			return ErrTooLarge
		}
	case tar.TypeSymlink:
		if h.Linkname == "" || strings.ContainsRune(h.Linkname, 0) {
			return fmt.Errorf("%w: bad link %s", ErrUnsafePath, name)
		}
		seen[name] = true
	case tar.TypeLink:
		target, err := CleanName(h.Linkname)
		if err != nil {
			return err
		}
		if t, _, _ := strings.Cut(target, "/"); t != top {
			return fmt.Errorf("%w: %s links to another volume", ErrUnsafePath, name)
		}
		// A tar program resolves the target through the links already
		// extracted: one beneath a symlink would reach outside.
		if err := seen.check(target); err != nil {
			return err
		}
	case tar.TypeFifo:
	default:
		// Devices need a capability no helper has, and no app keeps
		// them in a volume.
		return fmt.Errorf("%w: unsupported entry type %q for %s", ErrUnsafePath, h.Typeflag, name)
	}
	v.Entries++
	m.Entries++
	if o.Limits.MaxEntries > 0 && m.Entries > int64(o.Limits.MaxEntries) {
		return ErrTooLarge
	}
	if o.Declared != nil {
		d, ok := o.Declared.Volume(top)
		if !ok || v.Entries > d.Entries || v.Bytes > d.Bytes || v.Need > d.Need {
			return fmt.Errorf("%w: %s holds more than the copy declares", ErrTooLarge, top)
		}
	}
	return nil
}

// gate passes what is read from r on to out, except while hold is set:
// then it keeps it until release. ScanVolumesTo holds each entry's header
// until the entry is checked.
type gate struct {
	r    io.Reader
	out  io.Writer
	hold bool
	held bytes.Buffer
}

func (g *gate) Read(p []byte) (int, error) {
	n, err := g.r.Read(p)
	if n > 0 && g.out != nil {
		if g.hold {
			g.held.Write(p[:n])
		} else if _, werr := g.out.Write(p[:n]); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// release sends what was held and lets the rest through.
func (g *gate) release() error {
	g.hold = false
	if g.out == nil || g.held.Len() == 0 {
		g.held.Reset()
		return nil
	}
	_, err := g.out.Write(g.held.Bytes())
	g.held.Reset()
	return err
}
