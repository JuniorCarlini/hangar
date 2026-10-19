// Package volumes gives a service volume a real size limit (docs/05): the
// volume's files live in a sparse ext4 disk image of that size, mounted on
// the host through a loop device, and the Docker volume binds to a folder
// inside it. When the image is full the app gets "no space left" on that
// volume only; the server's disk and the other services are untouched.
//
// The panel runs unprivileged and only writes the desired state to a file
// (desired.json), as it does for the firewall. A root oneshot unit
// (hangar-volumes) reads it, validates everything again and creates,
// mounts, grows, fills or deletes the images, reporting back in
// applied.json. The panel never names a path for root: every path is
// derived here from the volume's name, under two fixed folders of the data
// directory.
package volumes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/node"
)

const (
	desiredFile = "desired.json"
	appliedFile = "applied.json"
	maxEntries  = 512

	// GiB is the unit the panel shows and the templates use ("20GB").
	GiB int64 = 1 << 30
	// MinSize is the smallest limit: ext4's own metadata takes a few
	// megabytes, and below this a database barely starts.
	MinSize = GiB
	// MaxSize is far above any single disk Hangar runs on and below
	// ext4's limit with 4 KiB blocks (16 TiB).
	MaxSize = 8 << 40
)

// Operations on one volume's image.
const (
	// OpMount keeps the image at Size (growing it when Size is bigger;
	// never shrinking it) and mounted.
	OpMount = "mount"
	// OpImport is OpMount, then copies the plain Docker volume of the same
	// name into the image. The panel stops the services first.
	OpImport = "import"
	// OpExport copies the image into the plain Docker volume of the same
	// name (the panel recreated it empty), then deletes the image.
	OpExport = "export"
	// OpRemove unmounts and deletes the image (its data is gone).
	OpRemove = "remove"
)

// Entry is one volume in the desired state.
type Entry struct {
	// Name is the Docker volume's name, hangar_<project>_<service>_<name>.
	Name string `json:"name"`
	Op   string `json:"op"`
	// Size is the image size in bytes (OpMount and OpImport).
	Size int64 `json:"size,omitempty"`
}

// State is the desired file.
type State struct {
	Version int `json:"version"`
	// Written makes every write unique, so a result in applied.json is
	// known to answer this very write (the hash covers it).
	Written int64   `json:"written"`
	Volumes []Entry `json:"volumes"`
}

// Result is what the root unit did with one entry.
type Result struct {
	Name  string `json:"name"`
	Op    string `json:"op"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	// Size is the image's size; Used and Total are the filesystem inside
	// it as df shows them (mounted images only).
	Size    int64  `json:"size,omitempty"`
	Used    uint64 `json:"used,omitempty"`
	Total   uint64 `json:"total,omitempty"`
	Mounted bool   `json:"mounted,omitempty"`
}

// Applied is what the root unit reports back.
type Applied struct {
	Hash    string    `json:"hash"`
	At      time.Time `json:"at"`
	Error   string    `json:"error,omitempty"`
	Volumes []Result  `json:"volumes"`
}

var nameRE = func() *regexp.Regexp {
	slug := strings.Trim(node.SlugRE.String(), "^$")
	vol := strings.Trim(node.VolumeNameRE.String(), "^$")
	return regexp.MustCompile("^" + regexp.QuoteMeta(node.NetworkPrefix) + slug + "_" + slug + "_" + vol + "$")
}()

// ValidName reports whether name is a service volume's Docker name, as
// node.VolumeName builds it. It is the only thing that becomes part of a
// path for root, so nothing else gets through.
func ValidName(name string) bool { return len(name) <= 120 && nameRE.MatchString(name) }

// Validate checks everything the root unit acts on.
func (s State) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unknown version %d", s.Version)
	}
	if len(s.Volumes) > maxEntries {
		return errors.New("too many volumes")
	}
	seen := map[string]bool{}
	for _, e := range s.Volumes {
		if !ValidName(e.Name) {
			return fmt.Errorf("invalid volume name %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("volume %s listed twice", e.Name)
		}
		seen[e.Name] = true
		switch e.Op {
		case OpMount, OpImport:
			if e.Size < MinSize || e.Size > MaxSize {
				return fmt.Errorf("volume %s: size %d out of range", e.Name, e.Size)
			}
		case OpExport, OpRemove:
			if e.Size != 0 {
				return fmt.Errorf("volume %s: %s takes no size", e.Name, e.Op)
			}
		default:
			return fmt.Errorf("volume %s: unknown operation %q", e.Name, e.Op)
		}
	}
	return nil
}

func (s State) hash() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// Paths are the folders of the feature, all derived from the panel's data
// directory.
type Paths struct{ Data string }

// Dir holds desired.json (written by the panel) and applied.json.
func (p Paths) Dir() string { return filepath.Join(p.Data, "volumes") }

// Images holds one <name>.img per limited volume (root only).
func (p Paths) Images() string { return filepath.Join(p.Data, "volume-images") }

// Mounts holds one mount point per limited volume.
func (p Paths) Mounts() string { return filepath.Join(p.Data, "volume-mounts") }

// Image is the disk image of a volume.
func (p Paths) Image(name string) string { return filepath.Join(p.Images(), name+".img") }

// Mount is where a volume's image is mounted.
func (p Paths) Mount(name string) string { return filepath.Join(p.Mounts(), name) }

// Device is the folder inside the mounted image the Docker volume binds
// to. It exists only while the image is mounted: should the mount be
// missing (a reboot before the unit ran), Docker cannot bind it and the
// container does not start, instead of starting on an empty folder of the
// server's own disk.
func (p Paths) Device(name string) string { return filepath.Join(p.Mount(name), "data") }

// Writer writes the desired state and reads the results (the panel side).
type Writer struct {
	Paths Paths
	now   func() time.Time
}

// NewWriter creates the writer for the data directory.
func NewWriter(dataDir string) *Writer { return &Writer{Paths: Paths{Data: dataDir}, now: time.Now} }

// Current is the desired state written before (empty when none).
func (w *Writer) Current() State {
	st := State{Version: 1, Volumes: []Entry{}}
	if raw, err := os.ReadFile(filepath.Join(w.Paths.Dir(), desiredFile)); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

// Write replaces the desired state atomically; the path unit notices it.
// It writes even when nothing changed when force is set (at start, so the
// unit runs again after a boot that found Docker still down).
func (w *Writer) Write(entries []Entry, force bool) error {
	entries = slices.Clone(entries)
	slices.SortFunc(entries, func(a, b Entry) int { return strings.Compare(a.Name, b.Name) })
	if entries == nil {
		entries = []Entry{}
	}
	if !force && slices.Equal(w.Current().Volumes, entries) {
		return nil
	}
	st := State{Version: 1, Written: w.now().UnixNano(), Volumes: entries}
	if err := st.Validate(); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return writeAtomic(w.Paths.Dir(), desiredFile, b)
}

// Results are the root unit's answers to the current desired state, by
// volume name. current is false while the unit has not answered the last
// write yet (the results are then from an earlier one, or empty).
func (w *Writer) Results() (res map[string]Result, current bool, applied Applied) {
	res = map[string]Result{}
	b, err := os.ReadFile(filepath.Join(w.Paths.Dir(), appliedFile))
	if err != nil {
		return res, false, Applied{}
	}
	if json.Unmarshal(b, &applied) != nil {
		return res, false, Applied{}
	}
	for _, r := range applied.Volumes {
		res[r.Name] = r
	}
	return res, applied.Hash == w.Current().hash(), applied
}

// Available reports whether the root unit has ever answered: it writes
// applied.json on its first run (install-units starts it), so a panel
// without it (no root unit installed, a laptop) does not offer limits.
func (w *Writer) Available() bool {
	_, err := os.Stat(filepath.Join(w.Paths.Dir(), appliedFile))
	return err == nil
}

// WrittenAt is when the current desired state was written.
func (w *Writer) WrittenAt() time.Time {
	if st := w.Current(); st.Written > 0 {
		return time.Unix(0, st.Written)
	}
	return time.Time{}
}

// WriteApplied answers the current desired state with results, as the
// root unit does; the panel's tests play the unit with it.
func WriteApplied(p Paths, results []Result) error {
	st := (&Writer{Paths: p}).Current()
	if results == nil {
		results = []Result{}
	}
	b, _ := json.MarshalIndent(Applied{Hash: st.hash(), At: time.Now().UTC(), Volumes: results}, "", "  ")
	return writeAtomic(p.Dir(), appliedFile, b)
}

func writeAtomic(dir, name string, b []byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // root must read it; it holds no secret
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+strings.TrimSuffix(name, ".json")+"-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}

// decodeState reads a desired file strictly.
func decodeState(raw []byte) (State, error) {
	var st State
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return State{}, err
	}
	if st.Volumes == nil {
		st.Volumes = []Entry{}
	}
	return st, st.Validate()
}

var sizeRE = regexp.MustCompile(`^([0-9]{1,5})\s*(GB|TB)$`)

// ParseSize reads a template's size ("20GB", "1TB"; binary units, as the
// panel shows them) and checks it is in range.
func ParseSize(s string) (int64, error) {
	m := sizeRE.FindStringSubmatch(strings.ToUpper(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("size %q: write a whole number of GB or TB, such as \"20GB\"", s)
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	b := n * GiB
	if m[2] == "TB" {
		b = n << 40
	}
	if b < MinSize || b > MaxSize {
		return 0, fmt.Errorf("size %q: between 1GB and %dTB", s, MaxSize>>40)
	}
	return b, nil
}
