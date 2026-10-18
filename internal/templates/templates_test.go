package templates

import (
	"slices"
	"strings"
	"testing"
)

var shipped = []string{
	"adminer", "mariadb", "meilisearch", "mongodb", "n8n", "pgadmin", "postgres", "rabbitmq",
	"redis-cache", "redis-queue", "rustfs", "uptime-kuma", "valkey-cache", "valkey-queue",
}

func sampleVals(t *Template) map[string]string {
	v := map[string]string{"name": "svc", "project": "lab", "service": "lab_svc"}
	for _, in := range t.Inputs {
		v[in.Key] = in.Default
	}
	for _, g := range t.Generated {
		v[g.Key] = "s3cr3t-" + g.Key
	}
	return v
}

func TestEveryShippedTemplateValidatesAndRenders(t *testing.T) {
	list, errs := LoadEach(catalogFS, "catalog")
	for _, err := range errs {
		t.Error(err)
	}
	var ids []string
	for _, tp := range list {
		ids = append(ids, tp.ID)
		r, err := tp.Render(sampleVals(tp))
		if err != nil {
			t.Errorf("%s: %v", tp.ID, err)
			continue
		}
		if len(r.Services) != len(tp.Services) || r.Services[0].Slug != "svc" {
			t.Errorf("%s: rendered services %+v", tp.ID, r.Services)
		}
		for _, s := range r.Services {
			if s.Stateful && s.Health == nil {
				t.Errorf("%s/%s: stateful without healthcheck", tp.ID, s.Slug)
			}
		}
		if err := CheckSVG(tp.Logo); err != nil {
			t.Errorf("%s: logo: %v", tp.ID, err)
		}
		if tp.Remote {
			t.Errorf("%s: embedded template marked remote", tp.ID)
		}
	}
	slices.Sort(ids)
	if !slices.Equal(ids, shipped) {
		t.Errorf("catalog = %v, want %v", ids, shipped)
	}
	if Builtin().List()[0].ID != "adminer" {
		t.Error("the builtin catalog must be sorted by id")
	}
}

func TestPostgresRenders(t *testing.T) {
	tp, _ := Builtin().Get("postgres")
	if keys := []string{tp.Inputs[0].Key, tp.Inputs[1].Key}; !slices.Equal(keys, []string{"database", "user"}) {
		t.Errorf("inputs keep the file's order: %v", keys)
	}
	r, err := tp.Render(map[string]string{
		"name": "db", "project": "loja", "service": "loja_db", "database": "shop", "user": "shop", "password": "s3nh4",
	})
	if err != nil {
		t.Fatal(err)
	}
	s := r.Services[0]
	if s.Slug != "db" || s.Port != 5432 || s.Env["POSTGRES_PASSWORD"] != "s3nh4" || len(s.Volumes) != 1 || s.Health == nil || !s.Stateful {
		t.Fatalf("rendered service: %+v", s)
	}
	if s.Volumes[0].Name != "data" || s.Volumes[0].Path != "/var/lib/postgresql" || s.MemoryMB != 512 || s.CPUs != 1 {
		t.Errorf("volume and limits: %+v", s)
	}
	if !strings.Contains(strings.Join(s.Health.Test, " "), "pg_isready -U shop -d shop") {
		t.Errorf("healthcheck: %v", s.Health.Test)
	}
	var url string
	for _, e := range r.Exports {
		if e.Key == "DATABASE_URL" {
			url = e.Value
			if !e.Secret {
				t.Error("DATABASE_URL carries the password: it must be secret")
			}
		}
	}
	if url != "postgres://shop:s3nh4@loja_db:5432/shop" {
		t.Errorf("DATABASE_URL = %q", url)
	}
}

// The Redis command is the same, byte for byte, as in the TOML format the
// folders replaced: $$ in compose.yaml is the shell's $.
func TestRedisCommandIsUnchanged(t *testing.T) {
	tp, _ := Builtin().Get("redis-cache")
	r, err := tp.Render(sampleVals(tp))
	if err != nil {
		t.Fatal(err)
	}
	want := `exec docker-entrypoint.sh redis-server --requirepass "$REDIS_PASSWORD" --maxmemory 192mb --maxmemory-policy allkeys-lru --save "" --appendonly no --rename-command FLUSHALL '' --rename-command FLUSHDB '' --rename-command CONFIG '' --rename-command DEBUG ''`
	s := r.Services[0]
	if len(s.Command) != 3 || s.Command[2] != want {
		t.Errorf("command = %q", s.Command)
	}
	if s.Health.Test[1] != `redis-cli -a "$REDIS_PASSWORD" --no-auth-warning ping | grep -q PONG` {
		t.Errorf("healthcheck = %q", s.Health.Test)
	}
	if !slices.Equal(s.CapAdd, []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "SETPCAP"}) {
		t.Errorf("caps = %v", s.CapAdd)
	}
}

func TestMultiServiceTemplate(t *testing.T) {
	tp, _ := Builtin().Get("n8n")
	r, err := tp.Render(map[string]string{
		"name": "flows", "project": "loja", "service": "loja_flows", "db_password": "pw", "encryption_key": "ek",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Services) != 2 || r.Services[0].Slug != "flows" || r.Services[1].Slug != "flows-db" {
		t.Fatalf("services: %+v", r.Services)
	}
	app := r.Services[0]
	if app.Env["DB_POSTGRESDB_HOST"] != "loja_flows-db" || app.Env["DB_POSTGRESDB_PASSWORD"] != "pw" || app.Port != 5678 {
		t.Errorf("app env: %v", app.Env)
	}
	if app.CapAdd == nil || len(app.CapAdd) != 0 {
		t.Errorf("cap_add: [] must mean no capability (not the defaults): %#v", app.CapAdd)
	}
	if r.Services[1].Env["POSTGRES_PASSWORD"] != "pw" {
		t.Errorf("db env: %v", r.Services[1].Env)
	}
}

// folder is a minimal valid template; cases change one file.
func folder() map[string][]byte {
	return map[string][]byte{
		FileMeta: []byte(`id = "xy"
version = 1
category = "other"
main = "app"
name = { en = "X", "pt-BR" = "X" }
description = { en = "X", "pt-BR" = "X" }
[variables.password]
generate = "secret"
`),
		FileCompose: []byte(`services:
  app:
    image: nginx:1.29-alpine
    environment:
      PASS: ${password}
    expose: ["8080"]
    deploy:
      resources:
        limits: { memory: 64M, cpus: "0.5" }
`),
		FileLogo: []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M0 0h24v24H0z"/></svg>`),
	}
}

func with(file, old, repl string) map[string][]byte {
	f := folder()
	if !strings.Contains(string(f[file]), old) {
		panic("test case does not apply: " + old)
	}
	f[file] = []byte(strings.Replace(string(f[file]), old, repl, 1))
	return f
}

func TestStrictComposeSubset(t *testing.T) {
	if _, err := Parse("xy", folder()); err != nil {
		t.Fatalf("a minimal safe template must load: %v", err)
	}
	const env = "    environment:\n"
	cases := map[string]struct {
		files map[string][]byte
		want  string
	}{
		"published port":      {with(FileCompose, env, "    ports: [\"80:8080\"]\n"+env), "services.app.ports: published ports"},
		"privileged":          {with(FileCompose, env, "    privileged: true\n"+env), "services.app.privileged"},
		"host network":        {with(FileCompose, env, "    network_mode: host\n"+env), "services.app.network_mode"},
		"pid host":            {with(FileCompose, env, "    pid: host\n"+env), "services.app.pid"},
		"devices":             {with(FileCompose, env, "    devices: [\"/dev/sda\"]\n"+env), "services.app.devices"},
		"build":               {with(FileCompose, env, "    build: .\n"+env), "services.app.build"},
		"bind mount":          {with(FileCompose, env, "    volumes: [\"/srv:/data\"]\n"+env), "bind mounts"},
		"relative bind":       {with(FileCompose, env, "    volumes: [\"./data:/data\"]\n"+env), "bind mounts"},
		"docker socket":       {with(FileCompose, env, "    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n"+env), "Docker socket"},
		"undeclared volume":   {with(FileCompose, env, "    volumes: [\"data:/data\"]\n"+env), "declare it"},
		"long bind":           {with(FileCompose, env, "    volumes: [{type: bind, source: /, target: /host}]\n"+env), "only named volumes"},
		"volume driver":       {with(FileCompose, "services:", "volumes:\n  data: {driver_opts: {type: none, o: bind, device: /}}\nservices:"), "only plain named volumes"},
		"latest tag":          {with(FileCompose, "nginx:1.29-alpine", "nginx:latest"), "never latest"},
		"no tag":              {with(FileCompose, "nginx:1.29-alpine", "nginx"), "explicit version tag"},
		"missing limits":      {with(FileCompose, "limits: { memory: 64M, cpus: \"0.5\" }", "limits: { cpus: \"0.5\" }"), "memory and cpus are required"},
		"tiny memory":         {with(FileCompose, "64M", "8M"), "16M or more"},
		"forbidden cap":       {with(FileCompose, env, "    cap_add: [SYS_ADMIN]\n"+env), "SYS_ADMIN is not allowed"},
		"two ports":           {with(FileCompose, `["8080"]`, `["8080", "9090"]`), "exactly one port"},
		"entrypoint":          {with(FileCompose, env, "    entrypoint: [sh]\n"+env), "services.app.entrypoint"},
		"string command":      {with(FileCompose, env, "    command: nginx -g daemon\n"+env), "list form"},
		"top-level networks":  {with(FileCompose, "services:", "networks: {}\nservices:"), "networks"},
		"env from host":       {with(FileCompose, "PASS: ${password}", "PASS:"), "nothing comes from the host"},
		"bare dollar":         {with(FileCompose, "PASS: ${password}", "PASS: $password"), "bare $"},
		"unknown placeholder": {with(FileCompose, "${password}", "${nope}"), "unknown placeholder ${nope}"},
		"system mount":        {with(FileCompose, env, "    volumes: [\"data:/etc\"]\n"+env), "invalid mount path"},
		"unused volume":       {with(FileCompose, "services:", "volumes:\n  data:\nservices:"), "declared but not used"},
		"typed password":      {with(FileMeta, "generate = \"secret\"", "default = \"x\"\npattern = '^x$'\nlabel = { en = \"P\", \"pt-BR\" = \"P\" }"), "looks like a secret"},
		"unknown toml key":    {with(FileMeta, "version = 1", "version = 1\nprivileged = true"), "unknown key"},
		"id mismatch":         {with(FileMeta, `id = "xy"`, `id = "zz"`), "folder's name"},
		"main missing":        {with(FileMeta, `main = "app"`, `main = "web"`), "main: \"web\""},
		"bad category":        {with(FileMeta, `category = "other"`, `category = "games"`), "category"},
		"bad min_hangar":      {with(FileMeta, "version = 1", "version = 1\nmin_hangar = \"1.0\""), "min_hangar"},
		"no description":      {with(FileMeta, `description = { en = "X", "pt-BR" = "X" }`, ""), "description"},
	}
	for name, c := range cases {
		_, err := Parse("xy", c.files)
		if err == nil {
			t.Errorf("%s: template accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", name, err, c.want)
		}
	}

	f := folder()
	f["run.sh"] = []byte("#!/bin/sh")
	if _, err := Parse("xy", f); err == nil || !strings.Contains(err.Error(), "unexpected file") {
		t.Errorf("an extra file must be refused: %v", err)
	}
	f = folder()
	delete(f, FileLogo)
	if _, err := Parse("xy", f); err == nil || !strings.Contains(err.Error(), "logo.svg: missing") {
		t.Errorf("the logo is required: %v", err)
	}
}

func TestStatefulNeedsHealthcheck(t *testing.T) {
	f := with(FileCompose, "    environment:\n", "    volumes: [\"data:/data\"]\n    environment:\n")
	f[FileCompose] = append(f[FileCompose], []byte("volumes:\n  data:\n")...)
	_, err := Parse("xy", f)
	if err == nil || !strings.Contains(err.Error(), "healthcheck: required") {
		t.Errorf("a service with a volume needs a healthcheck: %v", err)
	}
	f[FileCompose] = []byte(strings.Replace(string(f[FileCompose]), "    expose:", "    healthcheck:\n      test: [\"CMD\", \"true\"]\n    expose:", 1))
	tp, err := Parse("xy", f)
	if err != nil {
		t.Fatal(err)
	}
	if !tp.Services[0].Stateful || tp.Services[0].Volumes[0] != (Volume{Name: "data", Path: "/data"}) {
		t.Errorf("service: %+v", tp.Services[0])
	}
}

func TestSVGRejections(t *testing.T) {
	const ok = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><linearGradient id="g"/></defs><path fill="url(#g)" d="M0 0h1"/><use href="#g"/></svg>`
	if err := CheckSVG([]byte(ok)); err != nil {
		t.Fatalf("a clean logo must pass: %v", err)
	}
	bad := map[string]string{
		"script":         `<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`,
		"foreignObject":  `<svg xmlns="http://www.w3.org/2000/svg"><foreignObject><div/></foreignObject></svg>`,
		"onload":         `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`,
		"external href":  `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><use xlink:href="https://evil.example/x.svg#a"/></svg>`,
		"javascript uri": `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><path d="M0 0"/></a></svg>`,
		"external url":   `<svg xmlns="http://www.w3.org/2000/svg"><path style="fill:url(https://evil.example/a)" d="M0 0"/></svg>`,
		"style import":   `<svg xmlns="http://www.w3.org/2000/svg"><style>@import "https://evil.example/a.css";</style></svg>`,
		"style url":      `<svg xmlns="http://www.w3.org/2000/svg"><style>path{fill:url('//evil.example/a')}</style></svg>`,
		"entity":         `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "b">]><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"not svg":        `<html><body/></html>`,
		"broken":         `<svg xmlns="http://www.w3.org/2000/svg"><path></svg>`,
		"two roots":      `<svg xmlns="http://www.w3.org/2000/svg"/><svg xmlns="http://www.w3.org/2000/svg"/>`,
		"too big":        `<svg xmlns="http://www.w3.org/2000/svg"><!--` + strings.Repeat("a", MaxLogoBytes) + `--></svg>`,
		"empty":          ``,
	}
	for name, svg := range bad {
		if err := CheckSVG([]byte(svg)); err == nil {
			t.Errorf("%s: logo accepted", name)
		}
	}
}

func TestExpand(t *testing.T) {
	vals := map[string]string{"a": "1", "b_c": "2"}
	got, err := expand(`x=${a} y=${b_c} z=$$HOME w="$$$${a}"`, vals)
	if err != nil || got != `x=1 y=2 z=$HOME w="$${a}"` {
		t.Errorf("expand = %q, %v", got, err)
	}
	for _, s := range []string{"$a", "${A}", "${{db.URL}}", "${missing}", "end$"} {
		if _, err := expand(s, vals); err == nil {
			t.Errorf("%q must be refused", s)
		}
	}
}

func TestMemorySizes(t *testing.T) {
	for in, want := range map[string]int{"512M": 512, "512m": 512, "1G": 1024, "1gb": 1024, "256MiB": 256, "1048576": 1, "2048k": 2} {
		if got, ok := memoryMB(in); !ok || got != want {
			t.Errorf("memoryMB(%q) = %d, %v; want %d", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "lots", "-1M", "1T"} {
		if _, ok := memoryMB(in); ok {
			t.Errorf("memoryMB(%q) accepted", in)
		}
	}
}

func TestSecretsAreRandomAndURLSafe(t *testing.T) {
	a, _ := NewSecret()
	b, _ := NewSecret()
	if a == b || len(a) != 43 || strings.ContainsAny(a, "+/=") {
		t.Errorf("secret %q / %q", a, b)
	}
}

func TestLogoURLChangesWithContent(t *testing.T) {
	tp, _ := Builtin().Get("postgres")
	other := *tp
	other.Logo = append(slices.Clone(tp.Logo), ' ')
	if tp.LogoURL() == other.LogoURL() || !strings.HasPrefix(tp.LogoURL(), "/templates/postgres/logo.svg?v=") {
		t.Errorf("logo URL %q / %q", tp.LogoURL(), other.LogoURL())
	}
}

func TestEndpoints(t *testing.T) {
	meta := func(extra string) map[string][]byte {
		f := folder()
		f[FileMeta] = append(f[FileMeta], []byte(extra)...)
		return f
	}
	tp, err := Parse("xy", meta(`
[[endpoints]]
name = "console"
port = 9001
label = { en = "Console", "pt-BR" = "Console" }
public = true

[[endpoints]]
port = 9000
label = { en = "API", "pt-BR" = "API" }
public = false
`))
	if err != nil {
		t.Fatalf("valid endpoints rejected: %v", err)
	}
	if len(tp.Endpoints) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(tp.Endpoints))
	}
	if e := tp.Endpoints[0]; e.Name != "console" || e.Port != 9001 || !e.Public || e.Label["pt-BR"] != "Console" {
		t.Errorf("first endpoint = %+v", e)
	}
	if tp.Endpoints[1].Public {
		t.Error("an endpoint without public = true must default to internal")
	}

	bad := map[string]string{
		"bad port":      "\n[[endpoints]]\nport = 0\nlabel = { en = \"X\", \"pt-BR\" = \"X\" }\n",
		"huge port":     "\n[[endpoints]]\nport = 70000\nlabel = { en = \"X\", \"pt-BR\" = \"X\" }\n",
		"repeated port": "\n[[endpoints]]\nport = 80\nlabel = { en = \"X\", \"pt-BR\" = \"X\" }\n[[endpoints]]\nport = 80\nlabel = { en = \"Y\", \"pt-BR\" = \"Y\" }\n",
		"missing label": "\n[[endpoints]]\nport = 80\n",
		"bad name":      "\n[[endpoints]]\nname = \"Console!\"\nport = 80\nlabel = { en = \"X\", \"pt-BR\" = \"X\" }\n",
	}
	for name, extra := range bad {
		if _, err := Parse("xy", meta(extra)); err == nil {
			t.Errorf("%s: template accepted", name)
		}
	}
}
