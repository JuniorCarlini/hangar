package templates

import (
	"strings"
	"testing"
)

const recipeTable = `
[backup]
method = "recipe"
extension = "sql"
env = ["ROOT_PW"]
serve = ["docker-entrypoint.sh", "dbd"]
ready = ["sh", "-c", "db-ping"]
dump = ["sh", "-c", "db-dump --all"]
restore = ["sh", "-c", "db-load"]
verify = ["sh", "-c", "echo HANGAR-CHECK rows=1"]
`

func withMeta(extra string) map[string][]byte {
	f := folder()
	f[FileMeta] = append(f[FileMeta], []byte(extra)...)
	return f
}

func TestRecipeParses(t *testing.T) {
	tp, err := Parse("xy", withMeta(recipeTable))
	if err != nil {
		t.Fatal(err)
	}
	r := tp.Recipe
	if tp.Backup != BackupRecipe || r == nil {
		t.Fatalf("backup = %q, recipe %+v", tp.Backup, r)
	}
	if r.Dump[2] != "db-dump --all" || r.Restore[2] != "db-load" || r.Ready[2] != "db-ping" || r.Serve[1] != "dbd" || len(r.Verify) != 3 {
		t.Fatalf("recipe = %+v", r)
	}
	if r.Env[0] != "ROOT_PW" || r.FileExt() != "sql" {
		t.Fatalf("env %v, extension %q", r.Env, r.FileExt())
	}
	if (&Recipe{}).FileExt() != "backup" {
		t.Fatal("a recipe without extension downloads as .backup")
	}
}

// The old string form and a table naming a built-in method still work.
func TestBackupStringAndMethodTable(t *testing.T) {
	for in, want := range map[string]string{
		"backup = \"volume\"\n":                        BackupVolume,
		"backup = \"pg_dump\"\n":                       BackupPGDump,
		"\n[backup]\nmethod = \"volume\"\n":            BackupVolume,
		"\n[backup]\nmethod = \"pg_dump\"\n":           BackupPGDump,
		"\n[variables.other]\ngenerate = \"secret\"\n": "",
	} {
		var f map[string][]byte
		if strings.HasPrefix(in, "backup") {
			f = with(FileMeta, `main = "app"`, in+`main = "app"`)
		} else {
			f = withMeta(in)
		}
		tp, err := Parse("xy", f)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if tp.Backup != want || tp.Recipe != nil {
			t.Errorf("%q: backup %q recipe %v, want %q", in, tp.Backup, tp.Recipe, want)
		}
	}
}

func TestRecipeRejections(t *testing.T) {
	for name, c := range map[string]struct{ old, repl, want string }{
		"no dump":        {`dump = ["sh", "-c", "db-dump --all"]`, ``, "backup.dump: required"},
		"no restore":     {`restore = ["sh", "-c", "db-load"]`, ``, "backup.restore: required"},
		"no ready":       {`ready = ["sh", "-c", "db-ping"]`, ``, "backup.ready: required"},
		"no serve":       {`serve = ["docker-entrypoint.sh", "dbd"]`, ``, "backup.serve: required"},
		"empty program":  {`restore = ["sh", "-c", "db-load"]`, `restore = ["", "x"]`, "backup.restore: the program is empty"},
		"bad env":        {`env = ["ROOT_PW"]`, `env = ["root pw"]`, "backup.env: invalid variable name"},
		"bad image":      {`method = "recipe"`, `method = "recipe"` + "\nimage = \"Bad Image\"", "backup.image: invalid image"},
		"bad extension":  {`extension = "sql"`, `extension = "../x"`, "backup.extension"},
		"unknown key":    {`method = "recipe"`, `method = "recipe"` + "\nshell = \"bash\"", "backup.shell: unknown key"},
		"unknown method": {`method = "recipe"`, `method = "rsync"`, `unknown "rsync"`},
		"long command":   {`dump = ["sh", "-c", "db-dump --all"]`, `dump = ["sh", "-c", "` + strings.Repeat("x", maxRecipeBytes) + `"]`, "backup.dump: at most"},
	} {
		meta := strings.Replace(recipeTable, c.old, c.repl, 1)
		_, err := Parse("xy", withMeta(meta))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	// A built-in method takes no recipe keys.
	if _, err := Parse("xy", withMeta("\n[backup]\nmethod = \"volume\"\ndump = [\"x\"]\n")); err == nil || !strings.Contains(err.Error(), "takes no other keys") {
		t.Errorf("volume with a dump command: %v", err)
	}
	if _, err := Parse("xy", with(FileMeta, `main = "app"`, "backup = 3\n"+`main = "app"`)); err == nil {
		t.Error("backup = 3 must be refused")
	}
}

// Every database and Redis-like template in the catalog brings its own
// recipe, and every recipe is complete.
func TestShippedRecipes(t *testing.T) {
	for _, id := range []string{"mariadb", "mongodb", "redis-cache", "redis-queue", "valkey-cache", "valkey-queue"} {
		tp, ok := Builtin().Get(id)
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if tp.Backup != BackupRecipe || tp.Recipe == nil || len(tp.Recipe.Verify) == 0 || len(tp.Recipe.Env) == 0 {
			t.Errorf("%s: backup %q recipe %+v", id, tp.Backup, tp.Recipe)
		}
	}
	if tp, _ := Builtin().Get("postgres"); tp.Backup != BackupPGDump || tp.Recipe != nil {
		t.Errorf("postgres keeps pg_dump: %q", tp.Backup)
	}
}
