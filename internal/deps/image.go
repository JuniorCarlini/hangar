package deps

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	scalibrimage "github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	javaarchive "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/chisel"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	scalibrlog "github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
)

// Images reads the image a container runs (docker.Local implements it).
type Images interface {
	// ContainerImage returns the ID and size of the image the named
	// Hangar container runs.
	ContainerImage(ctx context.Context, container string) (id string, size int64, err error)
	// SaveImage writes the image as a `docker save` tarball.
	SaveImage(ctx context.Context, id string, w io.Writer) error
}

// Puller fetches and drops images that no container runs, so a newer build
// or a newer tag can be read before anyone deploys it (docker.Local
// implements it).
type Puller interface {
	// LocalImage reports whether ref (name@digest) is already in the image
	// store, with its ID and size.
	LocalImage(ctx context.Context, ref string) (id string, size int64, ok bool, err error)
	// PullImage pulls ref from its registry.
	PullImage(ctx context.Context, ref string) error
	// RemoveImage drops the reference (and the image when nothing else
	// uses it).
	RemoveImage(ctx context.Context, ref string) error
}

// Image scan limits. The panel runs with MemoryMax=384M (docs/04): one
// image at a time, files kept on disk, never a scan without an end.
const (
	DefaultMaxImageBytes = 3 << 30
	DefaultImageTimeout  = 10 * time.Minute
	// maxScanFileBytes skips files bigger than this (SCALIBR reads some
	// whole into memory, e.g. a nested jar).
	maxScanFileBytes = 256 << 20
	// diskMargin is left free on top of the scan's own files.
	diskMargin = 256 << 20
	// probeFloor is the free space a probe needs before it pulls an image
	// whose size it cannot know yet.
	probeFloor = 2 << 30
	// imageTarPrefix names the exported tarballs in the work dir.
	imageTarPrefix = "hangar-image-"
	// scalibrBlobPrefix is the file SCALIBR unpacks the layers into
	// (os.CreateTemp in its image package).
	scalibrBlobPrefix = "image-blob-"
)

// saveSlack is what an export may exceed the image's inspected size by
// (half of it more, plus this): the tarball wraps each layer and the config.
var saveSlack int64 = 64 << 20

// SkipError is an image the scanner chose not to read (too big, not enough
// disk): the reason is for the operator, and the exec inventory is used.
type SkipError struct{ Reason string }

func (e *SkipError) Error() string { return "image scan skipped: " + e.Reason }

// ImageScanner inventories a container's image with OSV-SCALIBR: OS
// packages and every language it knows, from installed metadata and
// lockfiles, plus the modules compiled into Go and Rust binaries. Nothing
// runs inside the container and nothing in the image is executed: the
// image is exported to a tarball in Dir and read as files.
type ImageScanner struct {
	Images Images
	// Dir holds the tarball and the unpacked layers while a scan runs. It
	// must be on a disk with room (the data dir), and SCALIBR's own
	// temporary file goes to os.TempDir(), so the panel points TMPDIR here.
	Dir string
	// MaxImageBytes skips bigger images (0 = DefaultMaxImageBytes).
	MaxImageBytes int64
	// Timeout bounds one image (0 = DefaultImageTimeout).
	Timeout time.Duration
	// Puller, when set, lets ProbeImage read images no container runs.
	Puller Puller

	mu sync.Mutex // one image at a time
	// freeBytes reports the free space of a directory (tests replace it).
	freeBytes func(dir string) (int64, error)
}

// ScanContainer inventories the image the named container runs.
func (s *ImageScanner) ScanContainer(ctx context.Context, container string) ([]Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultImageTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	id, size, err := s.Images.ContainerImage(ctx, container)
	if err != nil {
		return nil, fmt.Errorf("inspect image: %w", err)
	}
	return s.scanImage(ctx, id, size)
}

// errNoPuller: the node cannot pull images to look inside them.
var errNoPuller = errors.New("image probes need Docker")

// ProbeImage reads the packages of an image no container runs (ref is
// name@digest): pulled when it is not here, read like a running image, and
// removed again when it was not here before. Same limits as ScanContainer:
// one image at a time, a size cap, a disk check and a time limit.
func (s *ImageScanner) ProbeImage(ctx context.Context, ref string) ([]Package, error) {
	if s.Puller == nil {
		return nil, errNoPuller
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultImageTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	id, size, present, err := s.Puller.LocalImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("inspect image: %w", err)
	}
	if !present {
		if err := os.MkdirAll(s.Dir, 0o700); err != nil {
			return nil, err
		}
		free := s.freeBytes
		if free == nil {
			free = diskFree
		}
		if have, err := free(s.Dir); err == nil && have < probeFloor {
			return nil, &SkipError{Reason: fmt.Sprintf("needs %s free in %s to pull an image, has %s", humanBytes(probeFloor), s.Dir, humanBytes(have))}
		}
		if err := s.Puller.PullImage(ctx, ref); err != nil {
			return nil, fmt.Errorf("pull image: %w", err)
		}
		defer func() {
			// Not here before: leave the disk as it was (the deploy pulls it
			// again when someone asks for it).
			if err := s.Puller.RemoveImage(context.WithoutCancel(ctx), ref); err != nil {
				slog.Warn("remove probed image", "image", ref, "error", err)
			}
		}()
		if id, size, present, err = s.Puller.LocalImage(ctx, ref); err != nil || !present {
			return nil, fmt.Errorf("inspect pulled image: %w", errors.Join(err, errors.New("not found after the pull")))
		}
	}
	return s.scanImage(ctx, id, size)
}

// scanImage exports the image and reads it (the caller holds s.mu).
func (s *ImageScanner) scanImage(ctx context.Context, id string, size int64) ([]Package, error) {
	limit := s.MaxImageBytes
	if limit <= 0 {
		limit = DefaultMaxImageBytes
	}
	if size > limit {
		return nil, &SkipError{Reason: fmt.Sprintf("image is %s, above the %s limit", humanBytes(size), humanBytes(limit))}
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	s.cleanLeftovers()
	// The tarball and the unpacked layers each take about the image size.
	need := 2*size + diskMargin
	free := s.freeBytes
	if free == nil {
		free = diskFree
	}
	if have, err := free(s.Dir); err == nil && have < need {
		return nil, &SkipError{Reason: fmt.Sprintf("needs %s free in %s, has %s", humanBytes(need), s.Dir, humanBytes(have))}
	}

	tar, err := os.CreateTemp(s.Dir, imageTarPrefix+"*.tar")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(tar.Name()) }()
	// A save bigger than the image itself is not what was inspected: stop
	// before it fills the disk.
	w := &limitFile{f: tar, max: size + size/2 + saveSlack}
	err = s.Images.SaveImage(ctx, id, w)
	if cerr := tar.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("export image: %w", err)
	}
	return ScanImageTarball(ctx, tar.Name())
}

// cleanLeftovers removes what a scan killed half-way (panel restart, OOM)
// left in Dir.
func (s *ImageScanner) cleanLeftovers() {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if n := e.Name(); strings.HasPrefix(n, imageTarPrefix) || strings.HasPrefix(n, scalibrBlobPrefix) {
			_ = os.Remove(filepath.Join(s.Dir, n))
		}
	}
}

type limitFile struct {
	f   *os.File
	n   int64
	max int64
}

var errSaveTooBig = errors.New("exported image is larger than its inspected size")

func (l *limitFile) Write(p []byte) (int, error) {
	if l.n+int64(len(p)) > l.max {
		return 0, errSaveTooBig
	}
	n, err := l.f.Write(p)
	l.n += int64(n)
	return n, err
}

func diskFree(dir string) (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Bsize), nil //nolint:gosec,unconvert // block counts fit in int64; field types differ per OS
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return strconv.FormatFloat(float64(n)/(1<<30), 'f', 1, 64) + " GB"
	case n >= 1<<20:
		return strconv.FormatInt(n>>20, 10) + " MB"
	}
	return strconv.FormatInt(n>>10, 10) + " KB"
}

// ScanImageTarball reads a `docker save` tarball with OSV-SCALIBR and
// returns its packages in OSV terms. The tarball is removed as soon as its
// layers are unpacked (SCALIBR keeps one file with their content, removed
// at the end).
func ScanImageTarball(ctx context.Context, tarPath string) ([]Package, error) {
	quietSCALIBR()
	img, err := scalibrimage.FromTarball(tarPath, &scalibrimage.Config{
		MaxFileBytes: maxScanFileBytes, MaxSymlinkDepth: scalibrimage.DefaultMaxSymlinkDepth,
	})
	_ = os.Remove(tarPath)
	if err != nil {
		return nil, fmt.Errorf("read image: %w", err)
	}
	defer func() { _ = img.CleanUp() }()

	extractors, err := imageExtractors()
	if err != nil {
		return nil, err
	}
	// Only SCALIBR's filesystem extraction runs (not scalibr.Scan with its
	// detectors and enrichers, which would add network clients and ~30 MB
	// to the binary), on the merged filesystem: that is what runs, and
	// tracing each package back to its layer would read every layer again.
	inv, _, err := filesystem.Run(ctx, &filesystem.Config{
		Extractors:  extractors,
		ScanRoots:   []*scalibrfs.ScanRoot{{FS: img.FS()}},
		MaxFileSize: maxScanFileBytes,
		Stats:       stats.NoopCollector{},
	})
	if ctx.Err() != nil {
		return nil, fmt.Errorf("image scan: %w", ctx.Err())
	}
	if err != nil {
		return nil, fmt.Errorf("image scan: %w", err)
	}
	out := make([]Package, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		if pk, ok := osvPackage(p); ok {
			out = append(out, pk)
		}
	}
	return dedupe(out), nil
}

// imageCapabilities: a virtual filesystem, not this machine, offline.
// Plugins that need more (network lookups, direct paths, the running
// system, "unsafe" code execution) are never enabled.
var imageCapabilities = &plugin.Capabilities{
	OS: plugin.OSLinux, Network: plugin.NetworkOffline, DirectFS: false, RunningSystem: false,
}

func pluginConfig() *cpb.PluginConfig {
	no := false
	return &cpb.PluginConfig{
		MaxFileSizeBytes: maxScanFileBytes,
		PluginSpecific: []*cpb.PluginSpecificConfig{{Config: &cpb.PluginSpecificConfig_JavaArchive{
			JavaArchive: &cpb.JavaArchiveConfig{MaxOpenedBytes: maxScanFileBytes, HashJars: &no},
		}}},
	}
}

// imagePlugins are the package extractors run on an image: what is
// installed (OS databases, Python dist-info, node_modules, gems, jars,
// .NET deps.json), the lockfiles of languages whose installs leave no
// metadata (Composer, Bundler, Cargo, Pub, Mix), and the module lists
// compiled into Go and Rust binaries. No secret detector, no network, no
// source manifests (unpinned versions say nothing about what runs).
func imageExtractors() ([]filesystem.Extractor, error) {
	cfg := pluginConfig()
	news := []func(*cpb.PluginConfig) (filesystem.Extractor, error){
		dpkg.New, apk.New, rpm.New, chisel.New,
		wheelegg.New, packagejson.New, gemspec.New, gemfilelock.New, composerlock.New,
		javaarchive.New, depsjson.New, gobinary.New, cargoauditable.New, cargolock.New,
		pubspec.New, mixlock.New,
		// The app's own lockfiles name its package manager, so the page can
		// give the exact command (uv lock --upgrade-package, npm install…).
		uvlock.New, poetrylock.New, pipfilelock.New, packagelockjson.New, pnpmlock.New, yarnlock.New,
	}
	out := make([]filesystem.Extractor, 0, len(news))
	for _, n := range news {
		e, err := n(cfg)
		if err != nil {
			return nil, fmt.Errorf("image scan plugin: %w", err)
		}
		if plugin.ValidateRequirements(e, imageCapabilities) == nil {
			out = append(out, e)
		}
	}
	return out, nil
}

// lockfiles found inside installed dependencies describe the dependency's
// own development tree, not what runs.
var lockfileNames = map[string]bool{
	"composer.lock": true, "Gemfile.lock": true, "gems.locked": true, "Cargo.lock": true,
	"pubspec.lock": true, "mix.lock": true,
	"uv.lock": true, "poetry.lock": true, "Pipfile.lock": true,
	"package-lock.json": true, ".package-lock.json": true, "pnpm-lock.yaml": true, "yarn.lock": true,
}

var pypiSepRE = regexp.MustCompile(`[-_.]+`)

// osvPackage maps a SCALIBR package to the name and version OSV indexes it
// under. The ecosystem comes from SCALIBR (it knows each distribution's
// release suffix); the name fixes follow what osv-scanner sends: Debian and
// Alpine advisories name the source package, Maven names are
// group:artifact, Go's toolchain is "stdlib".
func osvPackage(p *extractor.Package) (Package, bool) {
	if p == nil || p.Name == "" || p.Version == "" {
		return Package{}, false
	}
	eco := p.Ecosystem()
	if eco.IsEmpty() {
		return Package{}, false
	}
	pk := Package{Ecosystem: eco.String(), Name: p.Name, Version: p.Version, Source: "/" + strings.TrimPrefix(p.Location.PathOrEmpty(), "/")}
	switch m := p.Metadata.(type) {
	case *dpkgmeta.Metadata:
		if m.SourceName != "" {
			pk.Name = m.SourceName
		}
		if m.SourceVersion != "" {
			pk.Version = m.SourceVersion
		}
	case *apkmeta.Metadata:
		if m.OriginName != "" {
			pk.Name = m.OriginName
		}
	case *rpmmeta.Metadata:
		// Red Hat family advisories carry the epoch in the version.
		if d, _, _ := strings.Cut(pk.Ecosystem, ":"); m.Epoch > 0 && (d == "Red Hat" || d == "AlmaLinux" || d == "Rocky Linux") {
			pk.Version = strconv.Itoa(m.Epoch) + ":" + pk.Version
		}
	case *archivemeta.Metadata:
		if m.GroupID != "" && m.ArtifactID != "" {
			pk.Name = m.GroupID + ":" + m.ArtifactID
		}
	}
	switch eco.Ecosystem {
	case "Go":
		if pk.Name == "go" {
			pk.Name = "stdlib"
		}
		// A module built from a checkout has no version OSV can match.
		if strings.HasPrefix(pk.Version, "(") {
			return Package{}, false
		}
	case "PyPI":
		pk.Name = pypiSepRE.ReplaceAllString(strings.ToLower(pk.Name), "-")
	case "Maven":
		if !strings.Contains(pk.Name, ":") {
			u := p.PURL()
			if u == nil || u.Type != purl.TypeMaven || u.Namespace == "" {
				return Package{}, false // OSV cannot match a jar without its group
			}
			pk.Name = u.Namespace + ":" + u.Name
		}
	case "Ubuntu":
		// OSV files LTS releases as "Ubuntu:24.04:LTS".
		if parts, _, ok := numericParts(eco.Suffix); ok && !strings.Contains(eco.Suffix, ":") &&
			len(parts) == 2 && parts[1] == 4 && parts[0]%2 == 0 {
			pk.Ecosystem += ":LTS"
		}
	}
	if lockfileNames[path.Base(pk.Source)] && (strings.Contains(pk.Source, "/node_modules/") || strings.Contains(pk.Source, "/vendor/") ||
		strings.Contains(pk.Source, "-packages/")) { // site-packages, dist-packages
		return Package{}, false
	}
	return pk, true
}

// --- SCALIBR plumbing --------------------------------------------------------

var quietOnce sync.Once

// quietSCALIBR sends SCALIBR's log (one line per unreadable file, by
// default to stderr) to slog's debug level.
func quietSCALIBR() {
	quietOnce.Do(func() { scalibrlog.SetLogger(slogLogger{}) })
}

type slogLogger struct{}

func (slogLogger) Errorf(f string, a ...any) { slog.Debug("scalibr: " + fmt.Sprintf(f, a...)) }
func (slogLogger) Error(a ...any)            { slog.Debug("scalibr: " + fmt.Sprint(a...)) }
func (slogLogger) Warnf(f string, a ...any)  { slog.Debug("scalibr: " + fmt.Sprintf(f, a...)) }
func (slogLogger) Warn(a ...any)             { slog.Debug("scalibr: " + fmt.Sprint(a...)) }
func (slogLogger) Infof(string, ...any)      {}
func (slogLogger) Info(...any)               {}
func (slogLogger) Debugf(string, ...any)     {}
func (slogLogger) Debug(...any)              {}
