package projects

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

func svcByName(t *testing.T, p ComposePlan, name string) ComposeService {
	t.Helper()
	for _, s := range p.Services {
		if s.Name == name {
			return s
		}
	}
	t.Fatalf("service %q missing from the plan", name)
	return ComposeService{}
}

func hasNote(s ComposeService, level, key string) bool {
	for _, n := range s.Notes {
		if n.Level == level && n.Msg.Key == key {
			return true
		}
	}
	return false
}

func envOf(s ComposeService) map[string]ComposeEnv {
	out := map[string]ComposeEnv{}
	for _, e := range s.Env {
		out[e.Key] = e
	}
	return out
}

const appCompose = `
version: "3.9"
services:
  db:
    image: postgres:16
    environment:
      POSTGRES_DB: shop
      POSTGRES_USER: shop
      POSTGRES_PASSWORD: segredo
    ports: ["5432:5432"]
    volumes: [pgdata:/var/lib/postgresql/data]
  cache:
    image: redis:7-alpine
  app:
    image: ghcr.io/dono/loja-api:1.4
    command: gunicorn app:wsgi --bind "0.0.0.0:8000"
    environment:
      - DATABASE_URL=postgres://shop:segredo@db:5432/shop
      - REDIS_URL=redis://cache:6379/0
      - CELERY_BROKER_URL=redis://cache:6379/1
      - DB_HOST=db
      - DB_PASSWORD=segredo
      - API_KEY=${API_KEY}
      - MODE=${MODE:-producao}
      - DEBUG
    ports: ["8080:8000"]
    volumes:
      - uploads:/app/uploads
    deploy:
      resources:
        limits: {memory: 1G, cpus: "0.5"}
    depends_on: [db, cache]
volumes:
  pgdata:
  uploads:
`

func TestComposePostgresRedisAndApp(t *testing.T) {
	p, err := ParseCompose([]byte(appCompose), false)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Creatable() || len(p.Services) != 3 {
		t.Fatalf("plan: %+v", p)
	}
	db := svcByName(t, p, "db")
	if db.Kind != ComposeTemplate || db.Template != "postgres" || db.Inputs["database"] != "shop" || db.Inputs["user"] != "shop" {
		t.Errorf("postgres must become the template with the file's database and user: %+v", db)
	}
	if len(db.Env) != 0 || len(db.Volumes) != 0 || db.Port != 0 {
		t.Error("the template brings its own variables, disk and port")
	}
	if !hasNote(db, NoteWarn, "compose.note.template_version") || !hasNote(db, NoteWarn, "compose.note.ports") {
		t.Errorf("version change and the published port must be pointed out: %+v", db.Notes)
	}
	cache := svcByName(t, p, "cache")
	if cache.Kind != ComposeTemplate || cache.Template != "redis-cache" {
		t.Errorf("a Redis without persistence is a cache: %+v", cache)
	}

	app := svcByName(t, p, "app")
	if app.Kind != ComposeImage || app.Image != "ghcr.io/dono/loja-api:1.4" || app.Port != 8000 {
		t.Errorf("app: %+v", app)
	}
	if app.MemoryMB != 1024 || app.CPUs != 0.5 {
		t.Errorf("limits: %d MB, %v CPU", app.MemoryMB, app.CPUs)
	}
	if strings.Join(app.Command, "|") != "gunicorn|app:wsgi|--bind|0.0.0.0:8000" {
		t.Errorf("command: %q", app.Command)
	}
	if len(app.Volumes) != 1 || app.Volumes[0].Name != "uploads" || app.Volumes[0].Path != "/app/uploads" {
		t.Errorf("named volume must become a disk: %+v", app.Volumes)
	}
	env := envOf(app)
	want := map[string]string{
		"DATABASE_URL":      "${{db.DATABASE_URL}}",
		"REDIS_URL":         "${{cache.REDIS_URL}}",
		"CELERY_BROKER_URL": "redis://:${{cache.PASSWORD}}@${{cache.HOST}}:${{cache.PORT}}/1",
		"DB_HOST":           "${{db.HOST}}",
		"DB_PASSWORD":       "${{db.PASSWORD}}",
		"API_KEY":           "",
		"MODE":              "producao",
		"DEBUG":             "",
	}
	for k, v := range want {
		if env[k].Value != v {
			t.Errorf("%s = %q, want %q", k, env[k].Value, v)
		}
	}
	if !env["DATABASE_URL"].Ref || env["DATABASE_URL"].Secret || !env["API_KEY"].Secret {
		t.Error("references are not secrets; API_KEY is")
	}
	for _, e := range app.Env {
		if strings.Contains(e.Value, "segredo") {
			t.Fatalf("the file's password survived in %s", e.Key)
		}
	}
	if !hasNote(app, NoteWarn, "compose.note.env_unset") || !hasNote(app, NoteWarn, "compose.note.ports") || !hasNote(app, NoteInfo, "compose.note.depends_on") {
		t.Errorf("notes: %+v", app.Notes)
	}
}

func TestComposeBindMountsAreIgnored(t *testing.T) {
	p, err := ParseCompose([]byte(`
services:
  web:
    image: nginx:1.29-alpine
    volumes:
      - ./site:/usr/share/nginx/html:ro
      - /etc/passwd:/x
      - ~/segredos:/secrets
      - type: bind
        source: /
        target: /host
      - /var/run/docker.sock:/var/run/docker.sock
      - sneaky:/data
      - cache:/cache
volumes:
  sneaky:
    driver: local
    driver_opts: {type: none, o: bind, device: /root}
  cache:
`), false)
	if err != nil {
		t.Fatal(err)
	}
	web := svcByName(t, p, "web")
	if len(web.Volumes) != 1 || web.Volumes[0].Path != "/cache" {
		t.Fatalf("only the real named volume may become a disk: %+v", web.Volumes)
	}
	if !hasNote(web, NoteSkip, "compose.note.bind") || !hasNote(web, NoteSkip, "compose.note.docker_socket") {
		t.Errorf("bind mounts and the Docker socket must be reported: %+v", web.Notes)
	}
	if web.Port != 80 {
		t.Errorf("nginx listens on 80, got %d", web.Port)
	}
}

func TestComposePortsAreNeverOpened(t *testing.T) {
	p, err := ParseCompose([]byte(`
services:
  api:
    image: traefik/whoami:v1.11
    ports:
      - "0.0.0.0:9000:8080"
      - target: 9090
        published: 9091
`), false)
	if err != nil {
		t.Fatal(err)
	}
	api := svcByName(t, p, "api")
	if api.Port != 8080 || !hasNote(api, NoteWarn, "compose.note.ports") {
		t.Errorf("the container port is the internal port and nothing is published: %+v", api)
	}
}

func TestComposePrivilegedAndHostNetworkAreRefused(t *testing.T) {
	p, err := ParseCompose([]byte(`
services:
  agent:
    image: busybox:1.37
    privileged: true
    network_mode: host
    pid: host
    cap_add: [SYS_ADMIN]
    devices: ["/dev/sda:/dev/sda"]
`), false)
	if err != nil {
		t.Fatal(err)
	}
	a := svcByName(t, p, "agent")
	refused := 0
	for _, n := range a.Notes {
		if n.Level == NoteSkip && n.Msg.Key == "compose.note.refused" {
			refused++
		}
	}
	if refused != 5 {
		t.Errorf("privileged, network_mode, pid, cap_add and devices must be refused: %+v", a.Notes)
	}
	// The service itself is still created, without any of it: ComposeService
	// has no field that could carry them.
	if a.Kind != ComposeImage {
		t.Errorf("kind %q", a.Kind)
	}
}

func TestComposeBuildNeedsRepository(t *testing.T) {
	src := []byte(`
services:
  web:
    build:
      context: ./api
      dockerfile: docker/Dockerfile.prod
      args: {X: "1"}
  bad:
    build: ../fora
`)
	p, err := ParseCompose(src, false)
	if err != nil {
		t.Fatal(err)
	}
	if web := svcByName(t, p, "web"); web.Kind != ComposeSkip || !hasNote(web, NoteSkip, "compose.note.build_needs_repo") {
		t.Errorf("a pasted build cannot be created: %+v", web)
	}
	if p.Creatable() {
		t.Error("nothing to create")
	}
	p, err = ParseCompose(src, true)
	if err != nil {
		t.Fatal(err)
	}
	web := svcByName(t, p, "web")
	if web.Kind != ComposeGit || web.Subdir != "api" || web.Dockerfile != "docker/Dockerfile.prod" || !hasNote(web, NoteWarn, "compose.note.build_ignored") {
		t.Errorf("build from the repository: %+v", web)
	}
	if bad := svcByName(t, p, "bad"); bad.Kind != ComposeSkip {
		t.Error("a context outside the repository must be refused")
	}
}

func TestComposeLimitsAndErrors(t *testing.T) {
	if _, err := ParseCompose([]byte(strings.Repeat("#", MaxComposeBytes+1)), false); err == nil {
		t.Error("oversized file accepted")
	}
	var b strings.Builder
	b.WriteString("services:\n")
	for i := range MaxComposeServices + 1 {
		b.WriteString("  s" + string(rune('a'+i)) + ":\n    image: nginx:1.29\n")
	}
	if _, err := ParseCompose([]byte(b.String()), false); err == nil {
		t.Error("too many services accepted")
	}
	for _, src := range []string{"", "services: [", "a: 1", "services: {}"} {
		if _, err := ParseCompose([]byte(src), false); err == nil {
			t.Errorf("%q accepted", src)
		}
	}
	p, err := ParseCompose([]byte("services:\n  web_app:\n    image: nginx:1.29\n  web-app:\n    image: nginx:1.29\n"), false)
	if err != nil {
		t.Fatal(err)
	}
	if p.Creatable() || p.Services[1].Problem == nil {
		t.Error("two names with the same identifier must block the import")
	}
}

func TestComposeSampleMapsCleanly(t *testing.T) {
	p, err := ParseCompose([]byte(ComposeSample), true)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Creatable() {
		t.Fatal("the model must be importable")
	}
	kinds := map[string]string{}
	for _, s := range p.Services {
		kinds[s.Name] = s.Kind + ":" + s.Template
		for _, n := range s.Notes {
			if n.Level == NoteSkip {
				t.Errorf("%s: the model must not trigger refusals: %s", s.Name, n.Msg.Key)
			}
		}
	}
	if kinds["db"] != "template:postgres" || kinds["redis"] != "template:redis-queue" || kinds["web"] != "git:" || kinds["worker"] != "git:" {
		t.Errorf("kinds: %v", kinds)
	}
	web := envOf(svcByName(t, p, "web"))
	if web["DATABASE_URL"].Value != "${{db.DATABASE_URL}}" || web["SECRET_KEY"].Value != "troque-esta-chave" {
		t.Errorf("web env: %+v", web)
	}
}

func TestSlugify(t *testing.T) {
	cases := map[string]string{
		"Loja API": "loja-api", "  Café Pão ": "cafe-pao", "web_1": "web-1", "3d": "s-3d",
		"a": "", "": "", "--": "", strings.Repeat("x", 40): strings.Repeat("x", 32),
		"api-" + strings.Repeat("y", 27) + "-z": "api-" + strings.Repeat("y", 27),
	}
	for in, want := range cases {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
	if got := UniqueName("db", map[string]bool{"db": true, "db-2": true}); got != "db-3" {
		t.Errorf("UniqueName = %q", got)
	}
	if NameFromRepo("https://github.com/dono/loja-api.git") != "loja-api" || NameFromImage("nginx:1.29") != "nginx" || NameFromImage("ghcr.io/a/b-c:1@sha256:x") != "b-c" {
		t.Error("suggested names")
	}
	if exposedPort([]byte("FROM x\nexpose 3000/tcp 9000\n")) != 3000 || exposedPort([]byte("EXPOSE $PORT\n")) != 0 {
		t.Error("EXPOSE")
	}
}

func TestCreateFromComposeLinksEverything(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	plan, err := f.m.PlanCompose(ctx, "loja", []byte(appCompose))
	if err != nil {
		t.Fatal(err)
	}
	plan.Services[2].X, plan.Services[2].Y, plan.Services[2].Placed = 48, 400, true
	svcs, err := f.m.CreateFromCompose(ctx, f.who, "loja", plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	if len(svcs) != 3 {
		t.Fatalf("created %d services", len(svcs))
	}
	app, ok := f.n.spec("loja_app")
	if !ok {
		t.Fatal("app not deployed")
	}
	db, _ := f.n.spec("loja_db")
	pw := db.Env["POSTGRES_PASSWORD"]
	if pw == "segredo" || len(pw) < 40 {
		t.Fatal("the database password must be generated, never the file's")
	}
	if app.Env["DATABASE_URL"] != "postgres://shop:"+pw+"@loja_db:5432/shop" || app.Env["DB_PASSWORD"] != pw {
		t.Errorf("references must resolve to the generated password: %v", app.Env)
	}
	if len(app.Ports) != 0 || len(app.Volumes) != 1 || app.MemoryBytes != 1024<<20 {
		t.Errorf("app spec: %+v", app)
	}
	g, err := f.m.ProjectGraph(ctx, mustProject(t, f, "loja"))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Edges) < 2 {
		t.Errorf("the canvas must show the references as lines: %+v", g.Edges)
	}
	for _, n := range g.Nodes {
		if n.Slug == "app" && (!n.Moved || n.Y != 400) {
			t.Errorf("app placed at %d,%d (moved %v)", n.X, n.Y, n.Moved)
		}
	}

	// Again: every name is taken now, and nothing is created twice.
	plan, err = f.m.PlanCompose(ctx, "loja", []byte(appCompose))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Creatable() || plan.Services[0].Problem == nil || plan.Services[0].Problem.Key != "compose.problem.taken" {
		t.Errorf("taken names must block: %+v", plan.Services[0])
	}
	if _, err := f.m.CreateFromCompose(ctx, f.who, "loja", plan, nil); err == nil {
		t.Error("created over existing services")
	}
}

func mustProject(t *testing.T, f *fixture, slug string) dbq.Project {
	t.Helper()
	p, err := f.m.GetProject(context.Background(), slug)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestComposeFromRepositoryBuildsAndReadsExpose(t *testing.T) {
	g := newGitFixture(t)
	commitFiles(t, g.repoDir, "main", map[string]string{
		"compose.yaml":   "services:\n  api:\n    build: ./app\n  db:\n    image: postgres:18\n",
		"app/Dockerfile": "FROM alpine:3.22\nEXPOSE 3000\n",
	}, "compose")
	ctx := context.Background()
	repo := &ComposeRepo{GitSourceInput: GitSourceInput{URL: g.repo}}
	plan, err := g.m.PlanComposeFromRepo(ctx, "lab", repo)
	if err != nil {
		t.Fatal(err)
	}
	api := svcByName(t, plan, "api")
	if plan.File != "compose.yaml" || api.Kind != ComposeGit || api.Port != 3000 || api.Subdir != "app" {
		t.Fatalf("plan from the repository: %+v", api)
	}
	if _, err := g.m.CreateFromCompose(ctx, g.who, "lab", plan, repo); err != nil {
		t.Fatal(err)
	}
	g.m.Wait()
	src, ok, err := g.m.GetGitSource(ctx, mustService(t, g.fixture, "lab", "api").ID)
	if err != nil || !ok || src.Subdir != "app" || src.Branch != "main" {
		t.Errorf("git source: %+v %v %v", src, ok, err)
	}

	commitFiles(t, g.repoDir, "main", map[string]string{"compose.yaml": "services:\n  x:\n    build: ./nada\n"}, "sem dockerfile")
	plan, err = g.m.PlanComposeFromRepo(ctx, "lab", repo)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Creatable() {
		t.Error("a build without its Dockerfile must block")
	}
	if _, err := g.m.PlanComposeFromRepo(ctx, "lab", &ComposeRepo{GitSourceInput: GitSourceInput{URL: g.repo, Branch: "nao-existe"}}); err == nil {
		t.Error("missing branch accepted")
	}
}

func mustService(t *testing.T, f *fixture, project, slug string) dbq.Service {
	t.Helper()
	_, s, err := f.m.GetService(context.Background(), project, slug)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestServiceNameBecomesSlug(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Name: "Loja API", Image: "nginx:1.29"})
	if err != nil || s.Slug != "loja-api" {
		t.Fatalf("slug %q: %v", s.Slug, err)
	}
	f.m.Wait()
	_, err = f.m.CreateService(ctx, f.who, "lab", ServiceInput{Name: "loja api", Image: "nginx:1.29"})
	if !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), "loja-api") {
		t.Errorf("collision must name the identifier: %v", err)
	}
	if _, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Name: "!", Image: "nginx:1.29"}); !errors.Is(err, ErrNameTooShort) {
		t.Errorf("unusable name: %v", err)
	}
}

func TestComposeAppGetsInternalEndpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "loja", ""); err != nil {
		t.Fatal(err)
	}
	plan, err := f.m.PlanCompose(ctx, "loja", []byte("services:\n  web:\n    image: nginx:1.29\n    expose: [\"3000\"]\n    deploy:\n      resources:\n        limits: {memory: 64M, cpus: \"0.5\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	svcs, err := f.m.CreateFromCompose(ctx, f.who, "loja", plan, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.m.Wait()
	eps, err := f.m.q.ListEndpoints(ctx, svcs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Public != 0 || eps[0].Port != 3000 {
		t.Errorf("a non-template app with a port should get one internal endpoint on 3000: %+v", eps)
	}
}

func TestImageServiceGetsInternalEndpoint(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.m.CreateProject(ctx, f.who, "lab", ""); err != nil {
		t.Fatal(err)
	}
	s, err := f.m.CreateService(ctx, f.who, "lab", ServiceInput{Slug: "qa-ep", Image: "nginx:1.29-alpine", Port: 80})
	if err != nil {
		t.Fatal(err)
	}
	eps, err := f.m.q.ListEndpoints(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Public != 0 || eps[0].Port != 80 {
		t.Errorf("an image service with a port should get one internal endpoint on 80: %+v", eps)
	}
}
