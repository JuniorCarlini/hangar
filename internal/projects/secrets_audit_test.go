package projects

import (
	"context"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// SEC-013: the dynamic domains' signing secret reaches the app's
// environment, so an app that prints it must not show it in the deploy log
// nor in the live logs; neither may a variable merely named like a secret.
func TestCheckSecretMaskedInLogs(t *testing.T) {
	f := newFixture(t)
	_, svcID := f.service(t)
	ctx := context.Background()
	if err := f.m.EnableDynamicDomains(ctx, f.who, "lab", "web"); err != nil {
		t.Fatal(err)
	}
	// Named like a secret but saved unmarked.
	if err := f.m.SetEnv(ctx, f.who, svcID, "STRIPE_TOKEN", "tok-sem-marca-1234", false); err != nil {
		t.Fatal(err)
	}
	check, err := f.m.CheckSecret(ctx, svcID)
	if err != nil {
		t.Fatal(err)
	}
	s, err := f.m.q.GetServiceByID(ctx, svcID)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := f.m.envFor(ctx, s)
	if err != nil {
		t.Fatal(err)
	}
	mk, err := f.m.deployMask(ctx, s, dbq.ServiceGit{}, raw, raw)
	if err != nil {
		t.Fatal(err)
	}
	live, err := f.m.LogMasker(ctx, "lab", "web")
	if err != nil {
		t.Fatal(err)
	}
	line := "env: HANGAR_DOMAIN_CHECK_SECRET=" + check + " STRIPE_TOKEN=tok-sem-marca-1234"
	for name, got := range map[string]string{"deploy log": mk.apply(line), "live logs": live(line)} {
		if strings.Contains(got, check) || strings.Contains(got, "tok-sem-marca-1234") {
			t.Errorf("%s: a secret leaked: %s", name, got)
		}
	}
}

// labWithDB is lab/web plus lab/db holding a password, and a plain variable
// of db that only points at the password (a chain).
func labWithDB(t *testing.T, f *fixture) (webID, dbID string) {
	t.Helper()
	ctx := context.Background()
	_, webID = f.service(t)
	db, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "db", Image: "postgres:18-alpine", Port: 5432})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for k, v := range map[string]string{"POSTGRES_PASSWORD": "senha-do-banco-77", "POSTGRES_USER": "app"} {
		if err := f.m.SetEnv(ctx, f.who, db.ID, k, v, LooksSecret(k)); err != nil {
			t.Fatal(err)
		}
	}
	// An admin wrote a plain-looking variable that carries the password.
	if err := f.m.SetEnv(ctx, f.who, db.ID, "CONN", "postgres://app:${{db.POSTGRES_PASSWORD}}@db/app", false); err != nil {
		t.Fatal(err)
	}
	return webID, db.ID
}

// SEC-015: below admin nobody may point a variable at a secret value (the
// deploy would hand it to a container they steer), directly, through a
// chain, through the connector or in a pasted .env; plain values still
// connect, an admin's reference survives an operator's save, and admins
// may connect secrets.
func TestRestrictedActorCannotReferenceSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	webID, _ := labWithDB(t, f)
	op := Actor{UserID: "usr_op", Restricted: true}

	for _, v := range []string{
		"https://coleta.example/?p=${{db.POSTGRES_PASSWORD}}",
		"${{db.POSTGRES_PASSWORD}}",
		"${{db.CONN}}", // a plain variable whose value reads the password
	} {
		if err := f.m.SetEnv(ctx, op, webID, "X", v, false); err == nil {
			t.Errorf("an operator wrote %q", v)
		}
	}
	if err := f.m.SetEnv(ctx, op, webID, "DB_HOST", "${{db.HOST}}", false); err != nil {
		t.Errorf("a plain reference: %v", err)
	}
	if err := f.m.SetEnv(ctx, op, webID, "DB_USER", "${{db.POSTGRES_USER}}", false); err != nil {
		t.Errorf("a plain variable: %v", err)
	}
	if _, err := f.m.Connect(ctx, op, "lab", "web", "db", []Mapping{{Key: "POSTGRES_PASSWORD", Var: "DB_PASSWORD"}}, true); err == nil {
		t.Error("the connector let an operator connect a secret")
	}
	if _, err := f.m.SetEnvBulk(ctx, op, webID, "A=1\nLEAK=${{db.POSTGRES_PASSWORD}}\n", false); err == nil {
		t.Error("a pasted .env carried a secret reference")
	}
	if vals, _ := f.m.ListEnvValues(ctx, webID); hasKey(vals, "A") || hasKey(vals, "LEAK") {
		t.Error("a refused .env must write nothing")
	}

	// An admin connects the secret; an operator saving the file around it
	// keeps it.
	admin := Actor{UserID: "usr_admin"}
	if _, err := f.m.Connect(ctx, admin, "lab", "web", "db", []Mapping{{Key: "POSTGRES_PASSWORD", Var: "DB_PASSWORD"}}, true); err != nil {
		t.Fatalf("an admin connects a secret: %v", err)
	}
	text, _, err := f.m.EnvText(ctx, webID, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.SetEnvFile(ctx, op, webID, text+"NOVA=1\n"); err != nil {
		t.Fatalf("an operator saving the file with an admin's reference in it: %v", err)
	}
	if vals, _ := f.m.ListEnvValues(ctx, webID); !hasValue(vals, "DB_PASSWORD", "${{db.POSTGRES_PASSWORD}}") || !hasKey(vals, "NOVA") {
		t.Errorf("after the operator's save: %+v", vals)
	}
}

// SEC-014/015: a reference into a connected project the person cannot see
// is refused, secret or not.
func TestLimitedActorCannotReferenceHiddenProject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.CreateService(ctx, f.who, "loja", ServiceInput{Slug: "api", Image: "nginx:1.29-alpine", Port: 80}); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if err := f.m.LinkProjects(ctx, f.who, "lab", "loja"); err != nil {
		t.Fatal(err)
	}
	op := Actor{UserID: "usr_op", Restricted: true, SeesProject: func(s string) bool { return s == "lab" }}
	if err := f.m.SetEnv(ctx, op, webID, "API_HOST", "${{loja.api.HOST}}", false); err == nil {
		t.Error("a limited operator referenced a project they cannot see")
	}
	op.SeesProject = nil
	if err := f.m.SetEnv(ctx, op, webID, "API_HOST", "${{loja.api.HOST}}", false); err != nil {
		t.Errorf("an operator who sees every project: %v", err)
	}
}

// SEC-004: the page's copy buttons resolve references only when nothing
// secret is read on the way.
func TestResolvedPublicValuesSkipSecrets(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	labWithDB(t, f)
	p, err := f.m.GetProject(ctx, "lab")
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"HOST": "${{db.HOST}}", "URL": "${{db.CONN}}", "PASS": "${{db.POSTGRES_PASSWORD}}"}
	pub := f.m.ResolvedPublicValues(ctx, p, env)
	if pub["HOST"] == "" {
		t.Error("a plain reference has nothing secret to hide")
	}
	if _, ok := pub["URL"]; ok {
		t.Error("a chain through the password must not resolve on the page")
	}
	if _, ok := pub["PASS"]; ok {
		t.Error("a secret must not resolve on the page")
	}
	if all := f.m.ResolvedValues(ctx, p, env); !strings.Contains(all["URL"], "senha-do-banco-77") {
		t.Errorf("the reveal resolves everything: %q", all["URL"])
	}
}

func hasKey(vals []EnvVar, key string) bool {
	for _, v := range vals {
		if v.Key == key {
			return true
		}
	}
	return false
}

func hasValue(vals []EnvVar, key, value string) bool {
	for _, v := range vals {
		if v.Key == key {
			return v.Value == value
		}
	}
	return false
}

// SEC-024: below admin the .env's comments show as "# ••••" (people keep
// passwords and notes there); saving that text puts every comment back in
// its place, and a comment written anew is kept as written.
func TestHiddenCommentsRoundTrip(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	_, webID := f.service(t)
	file := "# senha antiga: hunter2-velha\nDEBUG=1\n\n# TODO trocar\nAPI_URL=https://api\n"
	if _, err := f.m.SetEnvFile(ctx, f.who, webID, file); err != nil {
		t.Fatal(err)
	}
	masked, _, err := f.m.EnvTextFor(ctx, webID, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(masked, "hunter2") || strings.Contains(masked, "TODO") || strings.Count(masked, HiddenComment) != 2 {
		t.Fatalf("comments reached a masked editor:\n%s", masked)
	}
	op := Actor{UserID: "usr_op", Restricted: true}
	if _, err := f.m.SetEnvFile(ctx, op, webID, masked+"# nota nova\nNOVA=1\n"); err != nil {
		t.Fatal(err)
	}
	full, _, _ := f.m.EnvText(ctx, webID, true)
	for _, want := range []string{"# senha antiga: hunter2-velha\nDEBUG=1\n", "# TODO trocar\nAPI_URL=https://api\n", "# nota nova\nNOVA=1\n"} {
		if !strings.Contains(full, want) {
			t.Errorf("after the masked save the file lacks %q:\n%s", want, full)
		}
	}
	if strings.Contains(full, HiddenComment) {
		t.Errorf("a placeholder was stored:\n%s", full)
	}
}
