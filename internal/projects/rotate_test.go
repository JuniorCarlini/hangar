package projects

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/secrets"
)

// The master key rotation (hangard secrets rotate-key) must rebuild the
// exact associated data of each package: secrets written by the real code
// are read back by the real code with the new key, and no longer with the
// old one.
func TestMasterKeyRotationKeepsEverySecretReadable(t *testing.T) {
	g := newGitFixture(t)
	ctx := context.Background()
	id := g.create(t, GitServiceInput{ServiceInput: ServiceInput{Slug: "web", Port: 8000}, Token: "github_pat_leitura_123"})
	if err := g.m.SetEnv(ctx, g.who, id, "SECRET_KEY", "super-segredo-123", true); err != nil {
		t.Fatal(err)
	}
	hook, err := g.m.RotateWebhook(ctx, g.who, id)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := g.m.EnableDynamicDomains(ctx, g.who, "lab", "web") == nil
	check := ""
	if dynamic {
		if check, err = g.m.CheckSecret(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	g.m.Wait()

	oldBox, _ := secrets.NewBox(bytes.Repeat([]byte{7}, 32))
	newBox, _ := secrets.NewBox(bytes.Repeat([]byte{9}, 32))
	n, err := secrets.Rotate(ctx, g.st.DB, oldBox, newBox)
	if err != nil {
		t.Fatal(err)
	}
	if n < 4 {
		t.Fatalf("only %d values re-encrypted", n)
	}

	m2 := New(g.st.DB, newBox, g.b, audit.New(g.st.DB), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if v, err := m2.RevealEnv(ctx, g.who, id, "SECRET_KEY"); err != nil || v != "super-segredo-123" {
		t.Errorf("env after rotation: %q, %v", v, err)
	}
	if v, err := m2.RevealGitToken(ctx, g.who, id); err != nil || v != "github_pat_leitura_123" {
		t.Errorf("git token after rotation: %q, %v", v, err)
	}
	if w, err := m2.RevealWebhook(ctx, g.who, id); err != nil || w.Token != hook.Token || w.Secret != hook.Secret {
		t.Errorf("webhook after rotation: %+v, %v", w, err)
	}
	if dynamic {
		if v, err := m2.CheckSecret(ctx, id); err != nil || v != check {
			t.Errorf("domain check secret after rotation: %v", err)
		}
	}
	if _, err := g.m.RevealEnv(ctx, g.who, id, "SECRET_KEY"); err == nil {
		t.Error("the old key still opens the secrets")
	}
	// A wrong old key changes nothing.
	if _, err := secrets.Rotate(ctx, g.st.DB, oldBox, newBox); err == nil {
		t.Error("rotation with the wrong old key should fail")
	}
	if v, err := m2.RevealEnv(ctx, g.who, id, "SECRET_KEY"); err != nil || v != "super-segredo-123" {
		t.Errorf("a failed rotation touched the data: %q, %v", v, err)
	}
}
