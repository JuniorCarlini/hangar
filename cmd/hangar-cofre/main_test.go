package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

func cli(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(context.Background(), args, strings.NewReader(stdin), &out, &errb)
	return out.String() + errb.String(), err
}

func TestKitCheckProtectAndDecrypt(t *testing.T) {
	t.Setenv("LANG", "pt_BR.UTF-8")
	dir := t.TempDir()
	id, _ := age.GenerateX25519Identity()
	kit := filepath.Join(dir, "hangar-kit.txt")
	if err := os.WriteFile(kit, []byte("# kit\n"+id.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := cli(t, "", "kit", "check", kit)
	if err != nil || !strings.Contains(out, id.Recipient().String()) || !strings.Contains(out, archive.ConfirmCode(id)) {
		t.Fatalf("kit check: %v\n%s", err, out)
	}
	if _, err := cli(t, "curta\ncurta\n", "kit", "protect", kit); err == nil {
		t.Fatal("a short passphrase must be refused")
	}
	if _, err := cli(t, "uma frase bem longa\numa frase bem longa\n", "kit", "protect", kit); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HANGAR_COFRE_PASSPHRASE", "uma frase bem longa")
	out, err = cli(t, "", "kit", "check", kit+".protegido")
	if err != nil || !strings.Contains(out, id.Recipient().String()) {
		t.Fatalf("protected kit check: %v\n%s", err, out)
	}

	// decrypt a .tar.zst.age into .tar, with the protected kit.
	rs, _ := archive.ParseRecipients([]string{id.Recipient().String()})
	var buf bytes.Buffer
	w, _ := archive.Seal(&buf, rs, true)
	_, _ = w.Write([]byte("conteúdo do backup"))
	_ = w.Close()
	enc := filepath.Join(dir, "painel_"+time.Now().UTC().Format(archive.TimeFormat)+".tar.zst.age")
	_ = os.WriteFile(enc, buf.Bytes(), 0o600)
	out, err = cli(t, "", "decrypt", enc, "-identity", kit+".protegido", "-config", filepath.Join(dir, "nada.toml"))
	if err != nil {
		t.Fatalf("decrypt: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(strings.TrimSuffix(enc, ".zst.age")); string(b) != "conteúdo do backup" {
		t.Fatalf("decrypted %q", b)
	}
	other, _ := age.GenerateX25519Identity()
	_ = os.WriteFile(filepath.Join(dir, "outro.txt"), []byte(other.String()+"\n"), 0o600)
	if _, err := cli(t, "", "decrypt", enc, "-o", filepath.Join(dir, "x"), "-identity", filepath.Join(dir, "outro.txt"), "-config", filepath.Join(dir, "nada.toml")); err == nil {
		t.Fatal("a wrong kit must fail")
	}
}

func TestUsageAndInit(t *testing.T) {
	out, err := cli(t, "", "help")
	if err != nil || !strings.Contains(out, "restore-local") {
		t.Fatalf("help: %v %s", err, out)
	}
	if _, err := cli(t, "", "nao-existe"); err == nil {
		t.Fatal("unknown command must fail")
	}
	cfg := filepath.Join(t.TempDir(), "c", "cofre.toml")
	if _, err := cli(t, "", "init", "-config", cfg); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(cfg); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config file: %v", err)
	}
	if _, err := cli(t, "", "init", "-config", cfg); err == nil {
		t.Fatal("init must not overwrite")
	}
	if _, err := cli(t, "", "list", "-config", cfg); err == nil {
		t.Fatal("list without credentials must explain what is missing")
	}
	if at, err := parseAt("2026-10-15 14:32"); err != nil || at.Second() != 59 {
		t.Fatalf("parseAt: %v %v", at, err)
	}
}
