package deps

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// Package is one installed package version found in a container.
type Package struct {
	Ecosystem string // OSV ecosystem: PyPI, npm, Packagist, Debian:13, Alpine:v3.22, Ubuntu:24.04:LTS
	Name      string
	Version   string
	Source    string // where it was read (/var/lib/dpkg/status, a site-packages dir, a lockfile)
}

// Execer runs a fixed command in a service's container (node.Node.Exec).
type Execer interface {
	Exec(ctx context.Context, project, service string, cmd []string, w io.Writer) error
}

// Inventory limits: a container never makes the panel read unbounded data.
const (
	execTimeout   = 45 * time.Second
	maxOutput     = 16 << 20
	maxLockfiles  = 12
	findMaxDepth  = "8"
	maxPackageLen = 214 // npm's own name limit; anything longer is junk
)

// errTooBig marks output cut at maxOutput.
var errTooBig = errors.New("output too large")

type capWriter struct {
	buf bytes.Buffer
	max int
	cut bool
}

func (c *capWriter) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); room < len(p) {
		c.buf.Write(p[:max(room, 0)])
		c.cut = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func run(ctx context.Context, ex Execer, project, service string, cmd ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, execTimeout)
	defer cancel()
	w := &capWriter{max: maxOutput}
	if err := ex.Exec(ctx, project, service, cmd, w); err != nil {
		return w.buf.Bytes(), err
	}
	if w.cut {
		return w.buf.Bytes(), errTooBig
	}
	return w.buf.Bytes(), nil
}

// Inventory reads what is installed in a running service container: the OS
// packages (dpkg or apk database) and the language packages (Python
// *.dist-info directories, npm and Composer lockfiles). It only runs fixed
// read-only commands (cat, find), the same data an SBOM tool like Syft
// reads. A container without those tools yields what could be read plus an
// error saying what could not.
func Inventory(ctx context.Context, ex Execer, project, service string) ([]Package, error) {
	var (
		pkgs []Package
		errs []error
	)
	osPkgs, err := readOSPackages(ctx, ex, project, service)
	pkgs = append(pkgs, osPkgs...)
	if err != nil {
		errs = append(errs, fmt.Errorf("os packages: %w", err))
	}
	langPkgs, err := readLanguagePackages(ctx, ex, project, service)
	pkgs = append(pkgs, langPkgs...)
	if err != nil {
		errs = append(errs, fmt.Errorf("language packages: %w", err))
	}
	return dedupe(pkgs), errors.Join(errs...)
}

func dedupe(in []Package) []Package {
	seen := map[string]bool{}
	out := make([]Package, 0, len(in))
	for _, p := range in {
		k := queryKey(p)
		if seen[k] || p.Name == "" || p.Version == "" || len(p.Name) > maxPackageLen || len(p.Version) > 100 {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func readOSPackages(ctx context.Context, ex Execer, project, service string) ([]Package, error) {
	rel, err := run(ctx, ex, project, service, "cat", "/etc/os-release")
	if err != nil {
		return nil, fmt.Errorf("read /etc/os-release: %w", err)
	}
	eco, kind := osEcosystem(rel)
	switch kind {
	case "dpkg":
		db, err := run(ctx, ex, project, service, "cat", "/var/lib/dpkg/status")
		if err != nil {
			return nil, fmt.Errorf("read dpkg status: %w", err)
		}
		return parseDpkgStatus(db, eco), nil
	case "apk":
		db, err := run(ctx, ex, project, service, "cat", "/lib/apk/db/installed")
		if err != nil {
			return nil, fmt.Errorf("read apk database: %w", err)
		}
		return parseApkInstalled(db, eco), nil
	}
	return nil, nil // another distribution (or scratch): nothing OSV knows
}

// osEcosystem maps /etc/os-release to the OSV ecosystem and the package
// database to read.
func osEcosystem(osRelease []byte) (eco, kind string) {
	vals := map[string]string{}
	for _, line := range strings.Split(string(osRelease), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			vals[k] = strings.Trim(v, `"'`)
		}
	}
	id, ver := vals["ID"], vals["VERSION_ID"]
	switch id {
	case "debian":
		if ver == "" {
			return "", "" // testing/sid: no stable OSV ecosystem
		}
		major, _, _ := strings.Cut(ver, ".")
		return "Debian:" + major, "dpkg"
	case "ubuntu":
		if ver == "" {
			return "", ""
		}
		eco := "Ubuntu:" + ver
		if parts, _, ok := numericParts(ver); ok && len(parts) == 2 && parts[1] == 4 && parts[0]%2 == 0 {
			eco += ":LTS"
		}
		return eco, "dpkg"
	case "alpine":
		parts, _, ok := numericParts(ver)
		if !ok || len(parts) < 2 {
			return "", ""
		}
		return fmt.Sprintf("Alpine:v%d.%d", parts[0], parts[1]), "apk"
	}
	return "", ""
}

// parseDpkgStatus lists installed packages by their source package, which
// is what Debian and Ubuntu advisories name.
func parseDpkgStatus(db []byte, eco string) []Package {
	var out []Package
	for _, para := range strings.Split(string(db), "\n\n") {
		f := map[string]string{}
		for _, line := range strings.Split(para, "\n") {
			if line == "" || line[0] == ' ' || line[0] == '\t' {
				continue
			}
			if k, v, ok := strings.Cut(line, ":"); ok {
				f[k] = strings.TrimSpace(v)
			}
		}
		if f["Package"] == "" || f["Version"] == "" || !strings.HasSuffix(f["Status"], " installed") {
			continue
		}
		name, version := f["Package"], f["Version"]
		if src := f["Source"]; src != "" {
			n, v, hasVer := strings.Cut(src, " ")
			name = n
			if hasVer {
				version = strings.Trim(strings.TrimSpace(v), "()")
			}
		}
		out = append(out, Package{Ecosystem: eco, Name: name, Version: version, Source: "/var/lib/dpkg/status"})
	}
	return out
}

// parseApkInstalled lists Alpine packages by origin (the source package).
func parseApkInstalled(db []byte, eco string) []Package {
	var out []Package
	var name, origin, version string
	flush := func() {
		if origin != "" {
			name = origin
		}
		if name != "" && version != "" {
			out = append(out, Package{Ecosystem: eco, Name: name, Version: version, Source: "/lib/apk/db/installed"})
		}
		name, origin, version = "", "", ""
	}
	sc := bufio.NewScanner(bytes.NewReader(db))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
		case strings.HasPrefix(line, "P:"):
			name = line[2:]
		case strings.HasPrefix(line, "V:"):
			version = line[2:]
		case strings.HasPrefix(line, "o:"):
			origin = line[2:]
		}
	}
	flush()
	return out
}

// readLanguagePackages finds Python dist-info directories and npm/Composer
// lockfiles with one find, then reads the lockfiles.
func readLanguagePackages(ctx context.Context, ex Execer, project, service string) ([]Package, error) {
	// No -path/-prune (BusyBox builds may lack them): filtered below.
	out, err := run(ctx, ex, project, service, "find", "/", "-xdev", "-maxdepth", findMaxDepth,
		"-name", "*.dist-info", "-o", "-name", "package-lock.json", "-o", "-name", "composer.lock")
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("find: %w", err)
	}
	// find exits non-zero on an unreadable directory but still lists the
	// rest: use what came back.
	var (
		pkgs  []Package
		locks []string
	)
	for _, p := range strings.Split(string(out), "\n") {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "/proc/") || strings.HasPrefix(p, "/sys/") {
			continue
		}
		switch base := path.Base(p); {
		case strings.HasSuffix(base, ".dist-info"):
			if pk, ok := parseDistInfo(p); ok {
				pkgs = append(pkgs, pk)
			}
		case base == "package-lock.json" || base == "composer.lock":
			// Lockfiles inside dependencies describe the dependency's own
			// development tree, not what runs.
			if !strings.Contains(p, "/node_modules/") && !strings.Contains(p, "/vendor/") && len(locks) < maxLockfiles {
				locks = append(locks, p)
			}
		}
	}
	var errs []error
	for _, l := range locks {
		raw, err := run(ctx, ex, project, service, "cat", l)
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s: %w", l, err))
			continue
		}
		var parsed []Package
		if path.Base(l) == "composer.lock" {
			parsed, err = parseComposerLock(raw, l)
		} else {
			parsed, err = parsePackageLock(raw, l)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", l, err))
		}
		pkgs = append(pkgs, parsed...)
	}
	return pkgs, errors.Join(errs...)
}

// parseDistInfo reads "<site-packages>/Django-5.2.3.dist-info": the wheel
// spec escapes "-" in the name, so the first "-" splits name and version.
func parseDistInfo(p string) (Package, bool) {
	base := strings.TrimSuffix(path.Base(p), ".dist-info")
	name, version, ok := strings.Cut(base, "-")
	if !ok || name == "" || version == "" {
		return Package{}, false
	}
	return Package{Ecosystem: "PyPI", Name: normalizeName("PyPI", name), Version: version, Source: path.Dir(p)}, true
}

// parsePackageLock reads npm lockfiles v1, v2 and v3.
func parsePackageLock(raw []byte, file string) ([]Package, error) {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
			Link    bool   `json:"link"`
			Dev     bool   `json:"dev"`
		} `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	var out []Package
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link || p.Dev || p.Version == "" {
				continue
			}
			out = append(out, Package{Ecosystem: "npm", Name: key[i+len("node_modules/"):], Version: p.Version, Source: file})
		}
		return out, nil
	}
	var walk func(deps map[string]json.RawMessage, depth int)
	walk = func(deps map[string]json.RawMessage, depth int) {
		if depth > 64 {
			return
		}
		for name, raw := range deps {
			var d struct {
				Version      string                     `json:"version"`
				Dev          bool                       `json:"dev"`
				Dependencies map[string]json.RawMessage `json:"dependencies"`
			}
			if json.Unmarshal(raw, &d) != nil || d.Dev {
				continue
			}
			if d.Version != "" && !strings.Contains(d.Version, ":") { // skip file:, git+…
				out = append(out, Package{Ecosystem: "npm", Name: name, Version: d.Version, Source: file})
			}
			walk(d.Dependencies, depth+1)
		}
	}
	walk(lock.Dependencies, 0)
	return out, nil
}

func parseComposerLock(raw []byte, file string) ([]Package, error) {
	var lock struct {
		Packages []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(raw, &lock); err != nil {
		return nil, err
	}
	var out []Package
	for _, p := range lock.Packages {
		v := strings.TrimPrefix(p.Version, "v")
		if p.Name == "" || v == "" || strings.HasPrefix(v, "dev-") {
			continue
		}
		out = append(out, Package{Ecosystem: "Packagist", Name: p.Name, Version: v, Source: file})
	}
	return out, nil
}
