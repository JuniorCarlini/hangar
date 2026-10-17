package projects

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestParseEnvFile(t *testing.T) {
	got, err := ParseEnvFile("# c\nexport A=1\r\nB=\"two words\"\n\nC='x=y'\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []EnvLine{{"A", "1"}, {"B", "two words"}, {"C", "x=y"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if _, err := ParseEnvFile("OK=1\nbad line\n"); err == nil {
		t.Error("strict parse accepted an invalid line")
	}
	lenient := parseEnvFileLenient("OK=1\nbad line\n9X=no\nOK=2\nNEW=\n")
	if len(lenient) != 2 || lenient[0] != (EnvLine{"OK", "2"}) || lenient[1] != (EnvLine{"NEW", ""}) {
		t.Errorf("lenient parse: %+v", lenient)
	}
}

func writeFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadEnvExample(t *testing.T) {
	dir := t.TempDir()
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("found a file in an empty directory")
	}
	// A plain .env committed by mistake is never read.
	writeFile(t, filepath.Join(dir, ".env"), "LEAKED=hunter2\n")
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("read a plain .env")
	}
	writeFile(t, filepath.Join(dir, "example.env"), "LAST=1\n")
	writeFile(t, filepath.Join(dir, ".env.sample"), strings.Join([]string{
		"# database",
		"DEBUG=1",
		"DATABASE_URL=postgres://app:s3cret@localhost:5432/app",
		"REDIS_URL=redis://localhost:6379/0",
		"SECRET_KEY=change-me",
		"STRIPE=sk_live_abcdefghijklmnop",
		"SIGNING=Zx9Qk2Lm8Pw4Rt6Yv1Bn3Hj5",
		"ALLOWED_HOSTS=localhost,127.0.0.1",
		"EMPTY=",
		"not a line",
	}, "\n"))
	file, vars, ok := readEnvExample(dir)
	if !ok || file != ".env.sample" {
		t.Fatalf("file %q ok=%v: .env.sample comes before example.env", file, ok)
	}
	got := map[string]string{}
	for _, v := range vars {
		got[v.Key] = v.Value
	}
	want := map[string]string{
		"DEBUG": "1", "DATABASE_URL": "", "REDIS_URL": "redis://localhost:6379/0", "SECRET_KEY": "",
		"STRIPE": "", "SIGNING": "", "ALLOWED_HOSTS": "localhost,127.0.0.1", "EMPTY": "",
	}
	if len(got) != len(want) {
		t.Fatalf("vars: %+v", vars)
	}
	for k, v := range want {
		if g, ok := got[k]; !ok || g != v {
			t.Errorf("%s = %q (present %v), want %q", k, g, ok, v)
		}
	}
	if vars[0].Key != "DEBUG" {
		t.Errorf("file order lost: %+v", vars)
	}
}

func TestReadEnvExampleRefusesSymlinksAndHugeFiles(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secrets")
	writeFile(t, outside, "HOST_SECRET=from-outside\n")

	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, ".env.example")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("followed a symlink")
	}

	dir = t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".env.example"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("read a directory")
	}

	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, ".env.example"), "A=1\n"+strings.Repeat("#", envExampleMax))
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("read a file over the cap")
	}

	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, ".env.example"), "A=1\x00\n")
	if _, _, ok := readEnvExample(dir); ok {
		t.Fatal("read a binary file")
	}

	dir = t.TempDir()
	var b strings.Builder
	for i := range envExampleMaxVars + 50 {
		b.WriteString("V_" + strconv.Itoa(i) + "=1\n")
	}
	writeFile(t, filepath.Join(dir, ".env.example"), b.String())
	if _, vars, ok := readEnvExample(dir); !ok || len(vars) != envExampleMaxVars {
		t.Fatalf("var cap: ok=%v n=%d", ok, len(vars))
	}
}

func TestSafeExample(t *testing.T) {
	for _, c := range []struct {
		key, value string
		safe       bool
	}{
		{"PORT", "8000", true},
		{"DEBUG", "false", true},
		{"APP_NAME", "My shop", true},
		{"BASE_URL", "https://example.com/app", true},
		{"PLACEHOLDER", "your-value-here", true},
		{"VERSION", "2024-01-01T00:00:00Z", true},
		{"DB_PASSWORD", "postgres", false},
		{"API_KEY", "x", false},
		{"DATABASE_URL", "postgres://u:p@db/app", false},
		{"GH", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", false},
		{"CERT", "-----BEGIN PRIVATE KEY-----", false},
		{"JWT", "eyJhbGciOiJIUzI1NiJ9.e30.x", false},
		{"AWS_ID", "AKIAIOSFODNN7EXAMPLE", false},
		{"RANDOM", "q8V2nL5xR7tK1mZ4wB9cJ3", false},
		{"LONG", strings.Repeat("a ", 150), false},
	} {
		if got := safeExample(c.key, c.value); got != c.safe {
			t.Errorf("safeExample(%s, %q) = %v, want %v", c.key, c.value, got, c.safe)
		}
	}
}

func TestBuildRecordsSuggestedVariables(t *testing.T) {
	g := newGitFixture(t)
	commitFiles(t, g.repoDir, "main", map[string]string{
		".env.example": "DEBUG=1\nSECRET_KEY=change-me\nREDIS_URL=redis://cache:6379\n",
		".env":         "LEAKED=hunter2\n",
	}, "exemplo de variáveis")
	id := g.create(t, GitServiceInput{ServiceInput: ServiceInput{Port: 8000}})
	ctx := context.Background()

	s, ok, err := g.m.EnvSuggestions(ctx, id)
	if err != nil || !ok || s.File != ".env.example" || len(s.Vars) != 3 {
		t.Fatalf("suggestions: %+v ok=%v err=%v", s, ok, err)
	}
	for _, v := range s.Vars {
		if v.Key == "LEAKED" || strings.Contains(v.Value, "hunter2") {
			t.Fatal("the plain .env was read")
		}
		if v.Key == "SECRET_KEY" && v.Value != "" {
			t.Error("a secret's example value was kept")
		}
	}

	// A variable the service already has is not suggested again.
	if err := g.m.SetEnv(ctx, g.who, id, "DEBUG", "0", false); err != nil {
		t.Fatal(err)
	}
	if s, _, _ = g.m.EnvSuggestions(ctx, id); len(s.Vars) != 2 {
		t.Errorf("defined key still suggested: %+v", s.Vars)
	}

	// Dismissed: hidden until the file's keys change.
	if err := g.m.DismissEnvSuggestions(ctx, g.who, id); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ = g.m.EnvSuggestions(ctx, id); ok {
		t.Fatal("dismissed suggestions still shown")
	}
	redeploy := func() {
		t.Helper()
		if _, err := g.m.Deploy(ctx, g.who, "lab", "web", "manual"); err != nil {
			t.Fatal(err)
		}
		g.m.Wait()
	}
	redeploy()
	if _, ok, _ = g.m.EnvSuggestions(ctx, id); ok {
		t.Fatal("a rebuild with the same keys brought the dismissed card back")
	}
	commitFiles(t, g.repoDir, "main", map[string]string{".env.example": "DEBUG=1\nSECRET_KEY=x\nREDIS_URL=r\nSENTRY_ENV=prod\n"}, "nova variável")
	redeploy()
	if s, ok, _ = g.m.EnvSuggestions(ctx, id); !ok || len(s.Vars) != 3 {
		t.Fatalf("a new key should show the card again: %+v ok=%v", s, ok)
	}

	// The file no longer lists anything: the suggestion goes too.
	commitFiles(t, g.repoDir, "main", map[string]string{".env.example": "# nada\n"}, "sem exemplo")
	redeploy()
	if _, ok, _ = g.m.EnvSuggestions(ctx, id); ok {
		t.Error("suggestions outlived the file")
	}
	if err := g.m.DismissEnvSuggestions(ctx, g.who, id); err == nil {
		t.Error("dismissing nothing should be not found")
	}
}
