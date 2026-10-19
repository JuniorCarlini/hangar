package templates

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// The files of a template folder; anything else in it is an error.
const (
	FileCompose  = "compose.yaml"
	FileMeta     = "template.toml"
	FileLogo     = "logo.svg"
	FileReadme   = "README.md"
	maxFileBytes = 64 << 10
)

var folderFiles = []string{FileCompose, FileMeta, FileLogo, FileReadme}

// manifest is template.toml.
type manifest struct {
	ID          string              `toml:"id"`
	Version     int                 `toml:"version"`
	Category    string              `toml:"category"`
	Tags        []string            `toml:"tags"`
	Docs        string              `toml:"docs"`
	Backup      string              `toml:"backup"`
	Main        string              `toml:"main"`
	MinHangar   string              `toml:"min_hangar"`
	Name        Text                `toml:"name"`
	Description Text                `toml:"description"`
	Variables   map[string]variable `toml:"variables"`
	Exports     []Export            `toml:"exports"`
	Endpoints   []endpointSpec      `toml:"endpoints"`
}

// endpointSpec is a [[endpoints]] entry: a container port the template
// exposes over HTTP, with the label shown on the "open" button and whether
// it is public by default (docs/28).
type endpointSpec struct {
	Name   string `toml:"name"`
	Port   int    `toml:"port"`
	Label  Text   `toml:"label"`
	Public bool   `toml:"public"`
}

// variable is either generated (generate = "secret") or typed (default,
// pattern, label).
type variable struct {
	Generate string `toml:"generate"`
	Default  string `toml:"default"`
	Pattern  string `toml:"pattern"`
	Label    Text   `toml:"label"`
}

// varHeaderRE finds the [variables.<name>] tables in file order: TOML
// tables decode into a map, and the form should follow the author's order.
var varHeaderRE = regexp.MustCompile(`(?m)^\s*\[\s*variables\.("?)([a-z0-9_]+)("?)\s*\]`)

// Parse builds and validates one template from its folder: id is the
// folder's name and files maps each file name to its content. Errors name
// the file and the key.
func Parse(id string, files map[string][]byte) (*Template, error) {
	for name, data := range files {
		if !slices.Contains(folderFiles, name) {
			return nil, fmt.Errorf("%s: unexpected file (a template folder holds only %s)", name, strings.Join(folderFiles, ", "))
		}
		if len(data) > maxFileBytes {
			return nil, fmt.Errorf("%s: %d bytes, at most %d", name, len(data), maxFileBytes)
		}
	}
	for _, need := range []string{FileMeta, FileCompose, FileLogo} {
		if _, ok := files[need]; !ok {
			return nil, fmt.Errorf("%s: missing", need)
		}
	}

	var m manifest
	dec := toml.NewDecoder(bytes.NewReader(files[FileMeta]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			var errs []error
			for _, e := range strict.Errors {
				errs = append(errs, fmt.Errorf("%s: %s: unknown key", FileMeta, strings.Join(e.Key(), ".")))
			}
			return nil, errors.Join(errs...)
		}
		return nil, fmt.Errorf("%s: %w", FileMeta, err)
	}
	if m.ID != id {
		return nil, fmt.Errorf("%s: id: %q must be the folder's name (%q)", FileMeta, m.ID, id)
	}
	if m.Main == "" {
		return nil, fmt.Errorf("%s: main: required (the compose service that gets the user's name)", FileMeta)
	}
	services, err := parseCompose(files[FileCompose], m.Main)
	if err != nil {
		return nil, err
	}

	t := &Template{
		ID: m.ID, Version: m.Version, Category: m.Category, Tags: m.Tags, Name: m.Name, Description: m.Description,
		Docs: m.Docs, MinHangar: m.MinHangar, Backup: m.Backup, Services: services, Exports: m.Exports,
		Logo: files[FileLogo], Readme: string(files[FileReadme]),
	}
	for _, e := range m.Endpoints {
		t.Endpoints = append(t.Endpoints, Endpoint(e))
	}
	for _, s := range services {
		t.Warnings = append(t.Warnings, s.warnings...)
	}
	for _, k := range variableOrder(files[FileMeta], m.Variables) {
		v := m.Variables[k]
		at := FileMeta + ": variables." + k
		if v.Generate != "" {
			if v.Default != "" || v.Pattern != "" || len(v.Label) > 0 {
				return nil, fmt.Errorf("%s: a generated value has no default, pattern or label", at)
			}
			t.Generated = append(t.Generated, Generate{Key: k, Kind: v.Generate})
			continue
		}
		t.Inputs = append(t.Inputs, Input{Key: k, Label: v.Label, Default: v.Default, Pattern: v.Pattern})
	}
	if err := t.Validate(); err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, FileCompose+":") || strings.HasPrefix(msg, FileLogo+":") {
			return nil, err
		}
		return nil, fmt.Errorf("%s: %w", FileMeta, err)
	}
	return t, nil
}

// variableOrder lists the variables as written in the file; any declared
// some other way (inline tables) follow, sorted.
func variableOrder(raw []byte, vars map[string]variable) []string {
	var out []string
	for _, m := range varHeaderRE.FindAllStringSubmatch(string(raw), -1) {
		if _, ok := vars[m[2]]; ok && !slices.Contains(out, m[2]) {
			out = append(out, m[2])
		}
	}
	var rest []string
	for k := range vars {
		if !slices.Contains(out, k) {
			rest = append(rest, k)
		}
	}
	slices.Sort(rest)
	return append(out, rest...)
}

// readFolder reads the files of fsys/dir (no subdirectories allowed).
func readFolder(fsys fs.FS, dir string) (map[string][]byte, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			return nil, fmt.Errorf("%s: only regular files are allowed in a template folder", e.Name())
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		if info.Size() > maxFileBytes {
			return nil, fmt.Errorf("%s: %d bytes, at most %d", e.Name(), info.Size(), maxFileBytes)
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		files[e.Name()] = b
	}
	return files, nil
}

// ParseDir reads and validates the template folder fsys/dir; its last path
// element is the id.
func ParseDir(fsys fs.FS, dir string) (*Template, error) {
	files, err := readFolder(fsys, dir)
	if err != nil {
		return nil, err
	}
	return Parse(path.Base(dir), files)
}
