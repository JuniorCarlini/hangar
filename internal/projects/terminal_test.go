package projects

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestShellCommand(t *testing.T) {
	for shell, want := range map[string]string{"": "exec bash -l", "bash": "exec bash -l", "sh": "/bin/sh -l"} {
		cmd, err := ShellCommand(shell, "ignored")
		if err != nil || !strings.Contains(strings.Join(cmd, " "), want) {
			t.Errorf("ShellCommand(%q) = %v, %v", shell, cmd, err)
		}
	}
	cmd, err := ShellCommand("custom", "  python manage.py migrate --noinput  ")
	if err != nil || !slices.Equal(cmd, []string{"/bin/sh", "-c", "python manage.py migrate --noinput"}) {
		t.Errorf("custom: %v, %v", cmd, err)
	}
	for _, bad := range []struct{ shell, cmd string }{
		{"zsh", ""},
		{"/bin/bash", ""},
		{"custom", ""},
		{"custom", "   "},
		{"custom", "ls\nrm -rf /"},
		{"custom", "echo \x1b[2J"},
		{"custom", strings.Repeat("a", 1001)},
	} {
		if _, err := ShellCommand(bad.shell, bad.cmd); err == nil {
			t.Errorf("ShellCommand(%q, %q) should be refused", bad.shell, bad.cmd)
		}
	}
}

func TestOpenShellAuditsTheCommand(t *testing.T) {
	f := newFixture(t)
	f.service(t)
	ctx := context.Background()
	sh, err := f.m.OpenShell(ctx, f.who, "lab", "web", "custom", "python manage.py createsuperuser", 80, 24)
	if err != nil {
		t.Fatal(err)
	}
	_ = sh.Close()
	if _, err := f.m.OpenShell(ctx, f.who, "lab", "web", "sh", "", 80, 24); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.OpenShell(ctx, f.who, "lab", "web", "fish", "", 80, 24); err == nil {
		t.Error("an unknown shell must be refused")
	}
	if len(f.n.shells) != 2 || f.n.shells[0][2] != "python manage.py createsuperuser" || f.n.shells[1][0] != "/bin/sh" {
		t.Fatalf("container ran %v", f.n.shells)
	}
	var withCmd, withSh int
	_ = f.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.terminal.open' AND summary_json LIKE '%createsuperuser%'`).Scan(&withCmd)
	_ = f.st.DB.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'service.terminal.open' AND summary_json LIKE '%"shell":"sh"%'`).Scan(&withSh)
	if withCmd != 1 || withSh != 1 {
		t.Errorf("audit: command %d, sh %d", withCmd, withSh)
	}
}

func TestSavedCommands(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	ctx := context.Background()
	if err := f.m.SaveCommand(ctx, f.who, svcID, " aplicar migrações ", "python manage.py migrate"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{"", "ls"}, {"x", ""}, {"x", "ls\nid"}, {strings.Repeat("n", 61), "ls"}} {
		if err := f.m.SaveCommand(ctx, f.who, svcID, bad[0], bad[1]); err == nil {
			t.Errorf("SaveCommand(%q, %q) should be refused", bad[0], bad[1])
		}
	}
	cmds, err := f.m.ListCommands(ctx, svcID)
	if err != nil || len(cmds) != 1 || cmds[0].Name != "aplicar migrações" || cmds[0].Command != "python manage.py migrate" {
		t.Fatalf("commands: %+v %v", cmds, err)
	}
	if err := f.m.DeleteCommand(ctx, f.who, "svc_other", cmds[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting through another service: %v", err)
	}
	if err := f.m.DeleteCommand(ctx, f.who, svcID, cmds[0].ID); err != nil {
		t.Fatal(err)
	}
	if cmds, _ := f.m.ListCommands(ctx, svcID); len(cmds) != 0 {
		t.Errorf("left: %+v", cmds)
	}
	for i := range maxSavedCommands {
		if err := f.m.SaveCommand(ctx, f.who, svcID, "c", "echo "+strings.Repeat("x", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.m.SaveCommand(ctx, f.who, svcID, "c", "echo"); err == nil {
		t.Error("the list has a cap")
	}
}
