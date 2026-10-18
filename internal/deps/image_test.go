package deps

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scalibr/extractor"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	"github.com/google/osv-scalibr/purl"
)

func TestOSVPackageMapping(t *testing.T) {
	at := func(p string) extractor.PackageLocation { return extractor.LocationFromPath(p) }
	cases := []struct {
		name string
		in   *extractor.Package
		want Package
		skip bool
	}{
		{"debian source package", &extractor.Package{
			Name: "libssl3t64", Version: "3.5.1-1+b1", PURLType: purl.TypeDebian, Location: at("var/lib/dpkg/status"),
			Metadata: &dpkgmeta.Metadata{PackageName: "libssl3t64", SourceName: "openssl", SourceVersion: "3.5.1-1", OSID: "debian", OSVersionID: "13"},
		}, Package{Ecosystem: "Debian:13", Name: "openssl", Version: "3.5.1-1", Source: "/var/lib/dpkg/status"}, false},
		{"ubuntu LTS", &extractor.Package{
			Name: "bash", Version: "5.2.21-2ubuntu4", PURLType: purl.TypeDebian,
			Metadata: &dpkgmeta.Metadata{PackageName: "bash", OSID: "ubuntu", OSVersionID: "24.04"},
		}, Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "bash", Version: "5.2.21-2ubuntu4", Source: "/"}, false},
		{"alpine origin", &extractor.Package{
			Name: "libcrypto3", Version: "3.5.1-r0", PURLType: purl.TypeApk, Location: at("lib/apk/db/installed"),
			Metadata: &apkmeta.Metadata{PackageName: "libcrypto3", OriginName: "openssl", OSID: "alpine", OSVersionID: "3.23.2"},
		}, Package{Ecosystem: "Alpine:v3.23", Name: "openssl", Version: "3.5.1-r0", Source: "/lib/apk/db/installed"}, false},
		{"maven group:artifact", &extractor.Package{
			Name: "log4j-core", Version: "2.14.1", PURLType: purl.TypeMaven, Location: at("app/lib/log4j-core-2.14.1.jar"),
			Metadata: &archivemeta.Metadata{GroupID: "org.apache.logging.log4j", ArtifactID: "log4j-core"},
		}, Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1", Source: "/app/lib/log4j-core-2.14.1.jar"}, false},
		{"maven without group", &extractor.Package{Name: "mystery", Version: "1.0", PURLType: purl.TypeMaven}, Package{}, true},
		{
			"go toolchain", &extractor.Package{Name: "go", Version: "1.24.6", PURLType: purl.TypeGolang, Location: at("usr/bin/caddy")},
			Package{Ecosystem: "Go", Name: "stdlib", Version: "1.24.6", Source: "/usr/bin/caddy"},
			false,
		},
		{
			"go module keeps its case", &extractor.Package{Name: "github.com/BurntSushi/toml", Version: "1.6.0", PURLType: purl.TypeGolang},
			Package{Ecosystem: "Go", Name: "github.com/BurntSushi/toml", Version: "1.6.0", Source: "/"},
			false,
		},
		{"go main module from a checkout", &extractor.Package{Name: "example.com/app", Version: "(devel)", PURLType: purl.TypeGolang}, Package{}, true},
		{
			"pypi normalized", &extractor.Package{Name: "Typing_Extensions", Version: "4.15.0", PURLType: purl.TypePyPi},
			Package{Ecosystem: "PyPI", Name: "typing-extensions", Version: "4.15.0", Source: "/"},
			false,
		},
		{
			"npm scoped", &extractor.Package{Name: "@babel/core", Version: "7.28.0", PURLType: purl.TypeNPM, Location: at("app/node_modules/@babel/core/package.json")},
			Package{Ecosystem: "npm", Name: "@babel/core", Version: "7.28.0", Source: "/app/node_modules/@babel/core/package.json"},
			false,
		},
		{
			"crates.io", &extractor.Package{Name: "serde", Version: "1.0.228", PURLType: purl.TypeCargo},
			Package{Ecosystem: "crates.io", Name: "serde", Version: "1.0.228", Source: "/"},
			false,
		},
		{
			"rubygems", &extractor.Package{Name: "rack", Version: "3.1.0", PURLType: purl.TypeGem},
			Package{Ecosystem: "RubyGems", Name: "rack", Version: "3.1.0", Source: "/"},
			false,
		},
		{
			"nuget", &extractor.Package{Name: "Newtonsoft.Json", Version: "13.0.1", PURLType: purl.TypeNuget},
			Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json", Version: "13.0.1", Source: "/"},
			false,
		},
		{"lockfile of a dependency", &extractor.Package{Name: "a/b", Version: "1.0.0", PURLType: purl.TypeComposer, Location: at("app/vendor/a/b/composer.lock")}, Package{}, true},
		{"no OSV ecosystem", &extractor.Package{Name: "thing", Version: "1", PURLType: ""}, Package{}, true},
	}
	for _, c := range cases {
		got, ok := osvPackage(c.in)
		if ok == c.skip {
			t.Errorf("%s: ok = %v, want %v (%+v)", c.name, ok, !c.skip, got)
			continue
		}
		if !c.skip && got != c.want {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
	}
}

func TestSamePackageNewEcosystems(t *testing.T) {
	cases := []struct {
		eco, name string
		p         Package
		want      bool
	}{
		{"Go", "github.com/BurntSushi/toml", Package{Ecosystem: "Go", Name: "github.com/BurntSushi/toml"}, true},
		{"Go", "github.com/burntsushi/toml", Package{Ecosystem: "Go", Name: "github.com/BurntSushi/toml"}, false},
		{"Go", "stdlib", Package{Ecosystem: "Go", Name: "stdlib"}, true},
		{"Maven", "org.apache.logging.log4j:log4j-core", Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"}, true},
		{"Maven", "org.apache.logging.log4j:log4j-api", Package{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core"}, false},
		{"npm", "@babel/core", Package{Ecosystem: "npm", Name: "@babel/core"}, true},
		{"npm", "core", Package{Ecosystem: "npm", Name: "@babel/core"}, false},
		{"PyPI", "typing_extensions", Package{Ecosystem: "PyPI", Name: "typing-extensions"}, true},
		{"crates.io", "tokio_util", Package{Ecosystem: "crates.io", Name: "tokio-util"}, true},
		{"NuGet", "newtonsoft.json", Package{Ecosystem: "NuGet", Name: "Newtonsoft.Json"}, true},
		{"Ubuntu:24.04:LTS", "bash", Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "bash"}, true},
		{"Ubuntu:Pro:24.04:LTS", "bash", Package{Ecosystem: "Ubuntu:24.04:LTS", Name: "bash"}, false},
	}
	for _, c := range cases {
		if got := samePackage(c.eco, c.name, c.p); got != c.want {
			t.Errorf("samePackage(%q, %q, %+v) = %v, want %v", c.eco, c.name, c.p, got, c.want)
		}
	}
}

func TestCompareVersionsNewEcosystems(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Go modules (OSV drops the "v"; SCALIBR too).
		{"v0.17.0", "0.38.0", -1},
		{"0.0.0-20240101000000-abcdef123456", "0.17.0", -1},
		{"1.2.3-rc.1", "1.2.3", -1},
		{"2.0.0+incompatible", "2.0.0", 0},
		{"2.0.0+incompatible", "2.0.1+incompatible", -1},
		{"1.24.6", "1.24.10", -1},
		// Maven.
		{"2.14.1", "2.15.0", -1},
		{"2.17.0", "2.3.1", 1},
		{"5.3.0.RELEASE", "5.3.0", 0},
		{"5.4.0.Final", "5.4.1.Final", -1},
		{"1.0-SNAPSHOT", "1.0", -1},
		{"1.0-milestone-1", "1.0-RC1", -1},
		{"1.0-beta-2", "1.0", -1},
		// RubyGems, crates.io, NuGet.
		{"3.1.0.pre", "3.1.0", -1},
		{"1.0.228", "1.0.99", 1},
		{"13.0.1", "13.0.3", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

// fixtureImage writes a `docker save` tarball of a one-layer image with an
// Alpine package database, a Python dist-info, a scoped npm package, a
// Composer lockfile (and one inside vendor/, which is not what runs) and,
// when a Go toolchain is around, a Go binary.
func fixtureImage(t *testing.T, path string, goBinary bool) {
	t.Helper()
	files := map[string]string{
		"etc/os-release": "ID=alpine\nVERSION_ID=3.23.2\n",
		"lib/apk/db/installed": "C:Q1abc=\nP:libcrypto3\nV:3.5.1-r0\nA:aarch64\no:openssl\n\n" +
			"C:Q1def=\nP:busybox\nV:1.37.0-r30\nA:aarch64\no:busybox\n\n",
		"usr/lib/python3.13/site-packages/Django-5.2.3.dist-info/METADATA": "Metadata-Version: 2.1\nName: Django\nVersion: 5.2.3\n",
		"app/node_modules/@scope/pkg/package.json":                         `{"name":"@scope/pkg","version":"1.2.3"}`,
		"app/composer.lock":            `{"packages":[{"name":"monolog/monolog","version":"3.9.0"}]}`,
		"app/vendor/x/y/composer.lock": `{"packages":[{"name":"phpunit/phpunit","version":"10.0.0"}]}`,
	}
	if goBinary {
		files["usr/local/bin/hello"] = string(buildGoBinary(t))
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	dirs := map[string]bool{}
	for p, body := range files {
		for d := filepath.Dir(p); d != "."; d = filepath.Dir(d) {
			if !dirs[d] {
				dirs[d] = true
				_ = tw.WriteHeader(&tar.Header{Name: d + "/", Typeflag: tar.TypeDir, Mode: 0o755})
			}
		}
		if err := tw.WriteHeader(&tar.Header{Name: p, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(buf.Bytes())), nil })
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	if err := tarball.WriteToFile(path, name.MustParseReference("hangar.test/fixture:1"), img); err != nil {
		t.Fatal(err)
	}
}

// buildGoBinary compiles a tiny linux program (skips without a toolchain).
func buildGoBinary(t *testing.T) []byte {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no Go toolchain")
	}
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/hello\n\ngo 1.24\n"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() { println(\"hi\") }\n"), 0o600)
	cmd := exec.CommandContext(context.Background(), goTool, "build", "-o", "hello", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOFLAGS=-mod=mod", "GOWORK=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "hello"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScanImageTarball(t *testing.T) {
	dir := t.TempDir()
	tarPath := filepath.Join(dir, "img.tar")
	fixtureImage(t, tarPath, !testing.Short())
	pkgs, err := ScanImageTarball(context.Background(), tarPath)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range pkgs {
		got[p.Ecosystem+"|"+p.Name] = p
	}
	want := map[string]string{
		"Alpine:v3.23|openssl":      "3.5.1-r0",
		"Alpine:v3.23|busybox":      "1.37.0-r30",
		"PyPI|django":               "5.2.3",
		"npm|@scope/pkg":            "1.2.3",
		"Packagist|monolog/monolog": "3.9.0",
	}
	if !testing.Short() {
		want["Go|stdlib"] = strings.TrimPrefix(goVersion(t), "go")
	}
	for k, v := range want {
		if got[k].Version != v {
			t.Errorf("%s = %q, want %q (all: %+v)", k, got[k].Version, v, pkgs)
		}
	}
	if _, ok := got["Packagist|phpunit/phpunit"]; ok {
		t.Error("a lockfile inside vendor/ was inventoried")
	}
	if p := got["PyPI|django"]; !strings.HasPrefix(p.Source, "/usr/lib/python3.13/site-packages/") {
		t.Errorf("django source = %q", p.Source)
	}
	if _, err := os.Stat(tarPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("tarball left behind: %v", err)
	}
}

func goVersion(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(context.Background(), "go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

// fakeImages serves the fixture image for one container.
type fakeImages struct {
	tar  string
	size int64
	err  error
}

func (f *fakeImages) ContainerImage(_ context.Context, container string) (string, int64, error) {
	if f.err != nil {
		return "", 0, f.err
	}
	return "sha256:fixture-" + container, f.size, nil
}

func (f *fakeImages) SaveImage(_ context.Context, _ string, w io.Writer) error {
	b, err := os.ReadFile(f.tar)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func TestImageScannerLimits(t *testing.T) {
	src := filepath.Join(t.TempDir(), "img.tar")
	fixtureImage(t, src, false)
	st, _ := os.Stat(src)
	work := t.TempDir()
	// A leftover of a killed scan is cleaned up.
	_ = os.WriteFile(filepath.Join(work, scalibrBlobPrefix+"123"), []byte("x"), 0o600)
	s := &ImageScanner{Images: &fakeImages{tar: src, size: st.Size()}, Dir: work}

	pkgs, err := s.ScanContainer(context.Background(), "lab_web")
	if err != nil || len(pkgs) < 5 {
		t.Fatalf("scan: %d packages, %v", len(pkgs), err)
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Errorf("work dir not empty after the scan: %v", left)
	}

	var skip *SkipError
	s.MaxImageBytes = st.Size() - 1
	if _, err := s.ScanContainer(context.Background(), "lab_web"); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "limit") {
		t.Errorf("big image: %v", err)
	}
	s.MaxImageBytes = 0
	s.freeBytes = func(string) (int64, error) { return 1 << 20, nil }
	if _, err := s.ScanContainer(context.Background(), "lab_web"); !errors.As(err, &skip) || !strings.Contains(skip.Reason, "free") {
		t.Errorf("full disk: %v", err)
	}
	s.freeBytes = nil
	// An export bigger than the inspected size stops before filling the disk.
	s.Images = &fakeImages{tar: src, size: 1}
	defer func(old int64) { saveSlack = old }(saveSlack)
	saveSlack = 0
	if _, err := s.ScanContainer(context.Background(), "lab_web"); !errors.Is(err, errSaveTooBig) {
		t.Errorf("oversized export: %v", err)
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Errorf("work dir not empty after a failed export: %v", left)
	}
}

// TestScanUsesImageAndFallsBack: services are read from their image, the
// edge too; a service whose image cannot be scanned is read through exec.
func TestScanUsesImageAndFallsBack(t *testing.T) {
	src := filepath.Join(t.TempDir(), "img.tar")
	fixtureImage(t, src, false)
	e := newTestEnv(t)
	e.m.o.Images = imageByContainer{
		"lab_web":      errors.New("export failed"),
		"lab_postgres": nil,
		"hangar_caddy": nil,
	}.with(src)
	_ = e.m.Scan(context.Background())
	scans, _ := e.m.Scans(context.Background())
	if s := scans["svc_web"]; s.Packages != 3 || s.Error != "" {
		t.Errorf("web (exec fallback) = %+v", s)
	}
	if s := scans["svc_db"]; s.Packages < 5 || s.Error != "" {
		t.Errorf("postgres (image) = %+v", s)
	}
	if s := scans[EdgeTarget]; s.Packages < 5 || s.Error != "" {
		t.Errorf("edge (image) = %+v", s)
	}
}

type imageByContainer map[string]error

type imageScanFunc func(ctx context.Context, container string) ([]Package, error)

func (f imageScanFunc) ScanContainer(ctx context.Context, c string) ([]Package, error) {
	return f(ctx, c)
}

func (m imageByContainer) with(tarPath string) ImageInventory {
	return imageScanFunc(func(ctx context.Context, container string) ([]Package, error) {
		if err, ok := m[container]; !ok || err != nil {
			return nil, errors.Join(err, errors.New("unknown container "+container))
		}
		b, err := os.ReadFile(tarPath)
		if err != nil {
			return nil, err
		}
		cp := filepath.Join(filepath.Dir(tarPath), container+".tar")
		if err := os.WriteFile(cp, b, 0o600); err != nil {
			return nil, err
		}
		return ScanImageTarball(ctx, cp)
	})
}
