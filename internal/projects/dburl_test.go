package projects

import (
	"context"
	"strings"
	"testing"
)

func TestDerivedURL(t *testing.T) {
	cases := []struct {
		name, image string
		vals        map[string]string
		port        string
		key, want   string
		secret, ok  bool
	}{
		{
			"postgres with everything", "postgres:17",
			map[string]string{"POSTGRES_USER": "app", "POSTGRES_PASSWORD": "s3cret", "POSTGRES_DB": "shop"},
			"5432",
			"DATABASE_URL", "postgres://app:s3cret@h:5432/shop", true, true,
		},
		{
			"postgres defaults: user and database are postgres", "docker.io/library/postgres:16-alpine",
			map[string]string{"POSTGRES_PASSWORD": "pw"},
			"",
			"DATABASE_URL", "postgres://postgres:pw@h:5432/postgres", true, true,
		},
		{
			"password with characters a URL reserves", "postgis/postgis:16-3.5",
			map[string]string{"POSTGRES_PASSWORD": "p@ss:/w?rd#1"},
			"5432",
			"DATABASE_URL", "postgres://postgres:p%40ss%3A%2Fw%3Frd%231@h:5432/postgres", true, true,
		},
		{
			"mysql app user", "mysql:8.4",
			map[string]string{"MYSQL_USER": "app", "MYSQL_PASSWORD": "pw", "MYSQL_DATABASE": "shop", "MYSQL_ROOT_PASSWORD": "root"},
			"3306",
			"DATABASE_URL", "mysql://app:pw@h:3306/shop", true, true,
		},
		{
			"mariadb with only root", "mariadb:11",
			map[string]string{"MARIADB_ROOT_PASSWORD": "r", "MARIADB_DATABASE": "shop"},
			"",
			"DATABASE_URL", "mysql://root:r@h:3306/shop", true, true,
		},
		{
			"mongo root user", "mongo:8",
			map[string]string{"MONGO_INITDB_ROOT_USERNAME": "admin", "MONGO_INITDB_ROOT_PASSWORD": "pw"},
			"27017",
			"MONGODB_URL", "mongodb://admin:pw@h:27017/?authSource=admin", true, true,
		},
		{
			"redis without a password", "redis:8", nil, "6379",
			"REDIS_URL", "redis://h:6379/0", false, true,
		},
		{
			"valkey with a password", "valkey/valkey:9",
			map[string]string{"VALKEY_PASSWORD": "pw"},
			"6379",
			"REDIS_URL", "redis://:pw@h:6379/0", true, true,
		},
		{
			"a value that is a reference is not escaped into the URL", "postgres:17",
			map[string]string{"POSTGRES_PASSWORD": "${{vault.PG}}"},
			"",
			"", "", false, false,
		},
		{
			"not a database", "nginx:1.29-alpine",
			map[string]string{"POSTGRES_PASSWORD": "x"},
			"80",
			"", "", false, false,
		},
		{
			"a name that only contains postgres", "ghcr.io/acme/postgres-exporter:1", nil, "",
			"", "", false, false,
		},
	}
	for _, c := range cases {
		key, got, secret, ok := derivedURL(c.image, c.vals, "h", c.port)
		if ok != c.ok || (ok && (key != c.key || got != c.want || secret != c.secret)) {
			t.Errorf("%s: got (%q, %q, secret=%v, ok=%v), want (%q, %q, secret=%v, ok=%v)", c.name, key, got, secret, ok, c.key, c.want, c.secret, c.ok)
		}
	}
}

// A postgres made by hand offers DATABASE_URL like the template does: on by
// default in the connector, resolved at deploy from its own variables, and
// following them when they change.
func TestHandMadeDatabaseOffersItsURL(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.service(t) // lab/web
	db, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "db", Image: "postgres:17", Port: 5432})
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	for k, v := range map[string]string{"POSTGRES_USER": "app", "POSTGRES_PASSWORD": "first-password-1", "POSTGRES_DB": "shop"} {
		if err := f.m.SetEnv(ctx, f.who, db.ID, k, v, k == "POSTGRES_PASSWORD"); err != nil {
			t.Fatal(err)
		}
	}
	plan, err := f.m.PlanConnect(ctx, "lab", "web", "db")
	if err != nil {
		t.Fatal(err)
	}
	var url *ConnectRow
	for i, r := range plan.Rows {
		if r.Key == "DATABASE_URL" {
			url = &plan.Rows[i]
		}
	}
	if url == nil || !url.Checked || !url.Secret || url.Var != "DATABASE_URL" {
		t.Fatalf("DATABASE_URL row = %+v (rows %+v)", url, plan.Rows)
	}
	if _, err := f.m.Connect(ctx, f.who, "lab", "web", "db", []Mapping{{Key: "DATABASE_URL", Var: "DATABASE_URL"}}, false); err != nil {
		t.Fatal(err)
	}
	f.m.Wait()

	p, _ := f.m.GetProject(ctx, "lab")
	got, err := f.m.resolveRefs(ctx, p, map[string]string{"U": "${{db.DATABASE_URL}}"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got["U"], "postgres://app:first-password-1@") || !strings.HasSuffix(got["U"], ":5432/shop") {
		t.Errorf("resolved URL = %q", got["U"])
	}
	if err := f.m.SetEnv(ctx, f.who, db.ID, "POSTGRES_PASSWORD", "second-password-2", true); err != nil {
		t.Fatal(err)
	}
	got, _ = f.m.resolveRefs(ctx, p, map[string]string{"U": "${{db.DATABASE_URL}}"})
	if !strings.Contains(got["U"], ":second-password-2@") {
		t.Errorf("after the password changed: %q", got["U"])
	}
	if broken, err := f.m.BrokenRefs(ctx, p); err != nil || len(broken) != 0 {
		t.Errorf("broken refs: %+v %v", broken, err)
	}
}
