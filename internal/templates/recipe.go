package templates

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// A template whose service is a database with a tool of its own to dump it
// declares a native recipe (docs/09), so a future database only needs a
// template, never a change to Hangar:
//
//	[backup]
//	method = "recipe"
//	extension = "sql"              # name of the file in a download
//	env = ["MARIADB_ROOT_PASSWORD"] # variables the empty instance needs
//	dump = ["bash", "-c", "..."]    # whole backup to stdout
//	restore = ["bash", "-c", "..."] # whole backup from stdin
//	ready = ["sh", "-c", "..."]     # exit 0: accepts the restore
//	serve = ["docker-entrypoint.sh", "mariadbd"] # an empty instance
//	verify = ["bash", "-c", "..."]  # prints HANGAR-CHECK k=v ...
//
// dump runs in the service's container (docker exec, its own environment)
// and writes the whole service to stdout: every database and the users,
// passwords and permissions, so restoring it into an empty instance gives
// a clone the apps log into as before. restore reads that from stdin in a
// running, empty instance (a new service, or the same one after its
// volumes were emptied). serve starts such an empty instance in the
// foreground inside a throwaway container of the image (no network,
// scratch storage, only the env variables named), where every backup is
// restored before it is called tested; ready says when it (or the real
// service) accepts the restore; verify prints what the instance holds as
// "HANGAR-CHECK name=number ..." (tables, rows, users...), run on the
// original and on the test copy.
//
// The commands are fixed by the template, like its image and its command:
// nothing a user types reaches them, and they run only inside the
// service's own container or a throwaway one of its image.

// Recipe is a template's native backup ([backup] method = "recipe").
type Recipe struct {
	Dump    []string `toml:"dump"`
	Restore []string `toml:"restore"`
	Ready   []string `toml:"ready"`
	Serve   []string `toml:"serve"`
	Verify  []string `toml:"verify"`
	// Env are the service's variables the throwaway instance gets (the
	// dump and the restore run in the service, which has them all).
	Env []string `toml:"env"`
	// Image runs the throwaway instance ("" = the service's own).
	Image string `toml:"image"`
	// Extension names the backup's file in a download ("" = "backup").
	Extension string `toml:"extension"`
}

// FileExt is the extension of the backup's file in a download.
func (r *Recipe) FileExt() string {
	if r.Extension == "" {
		return "backup"
	}
	return r.Extension
}

// backupTable is template.toml's [backup] table.
type backupTable struct {
	Method string `toml:"method"`
	Recipe
}

// BackupRecipe is the method of a template with a native recipe.
const BackupRecipe = "recipe"

var (
	recipeEnvRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	extensionRE = regexp.MustCompile(`^[a-z0-9]{1,12}$`)
)

// Limits of a recipe's commands: a script, not a program.
const (
	maxRecipeArgs  = 16
	maxRecipeBytes = 16 << 10
)

// parseBackup reads template.toml's backup: a string (backup = "pg_dump"
// or "volume", as before) or a [backup] table.
func parseBackup(v any) (string, *Recipe, error) {
	switch b := v.(type) {
	case nil:
		return "", nil, nil
	case string:
		return b, nil, nil
	case map[string]any:
		raw, err := toml.Marshal(b)
		if err != nil {
			return "", nil, fmt.Errorf("backup: %w", err)
		}
		var t backupTable
		dec := toml.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			var strict *toml.StrictMissingError
			if errors.As(err, &strict) {
				var keys []string
				for _, e := range strict.Errors {
					keys = append(keys, "backup."+strings.Join(e.Key(), "."))
				}
				return "", nil, fmt.Errorf("%s: unknown key", strings.Join(keys, ", "))
			}
			return "", nil, fmt.Errorf("backup: %w", err)
		}
		if t.Method != BackupRecipe {
			if t.Method == BackupPGDump || t.Method == BackupVolume {
				if t.Dump != nil || t.Restore != nil || t.Ready != nil || t.Serve != nil || t.Verify != nil || t.Env != nil || t.Image != "" || t.Extension != "" {
					return "", nil, fmt.Errorf("backup: method %q takes no other keys", t.Method)
				}
				return t.Method, nil, nil
			}
			return "", nil, fmt.Errorf("backup: method: unknown %q", t.Method)
		}
		r := t.Recipe
		return BackupRecipe, &r, nil
	}
	return "", nil, errors.New("backup: must be a string or a [backup] table")
}

// Validate checks a recipe: the commands it needs are there and bounded,
// variables are plain names, the throwaway image is a valid reference.
func (r *Recipe) Validate() error {
	for _, c := range []struct {
		name     string
		cmd      []string
		required bool
	}{
		{"dump", r.Dump, true},
		{"restore", r.Restore, true},
		{"ready", r.Ready, true},
		{"serve", r.Serve, true},
		{"verify", r.Verify, false},
	} {
		if len(c.cmd) == 0 {
			if c.required {
				return fmt.Errorf("backup.%s: required for a recipe", c.name)
			}
			continue
		}
		if len(c.cmd) > maxRecipeArgs {
			return fmt.Errorf("backup.%s: at most %d arguments", c.name, maxRecipeArgs)
		}
		if c.cmd[0] == "" {
			return fmt.Errorf("backup.%s: the program is empty", c.name)
		}
		size := 0
		for _, a := range c.cmd {
			size += len(a)
			if strings.ContainsRune(a, 0) {
				return fmt.Errorf("backup.%s: NUL in an argument", c.name)
			}
		}
		if size > maxRecipeBytes {
			return fmt.Errorf("backup.%s: at most %d bytes", c.name, maxRecipeBytes)
		}
	}
	for _, e := range r.Env {
		if !recipeEnvRE.MatchString(e) {
			return fmt.Errorf("backup.env: invalid variable name %q", e)
		}
	}
	if r.Image != "" && !node.ImageRE.MatchString(r.Image) {
		return fmt.Errorf("backup.image: invalid image %q", r.Image)
	}
	if r.Extension != "" && !extensionRE.MatchString(r.Extension) {
		return fmt.Errorf("backup.extension: %q must be lowercase letters and digits", r.Extension)
	}
	return nil
}
