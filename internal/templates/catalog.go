package templates

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
)

// The embedded catalog: the baseline every release ships (and the whole
// catalog when the server is offline).
//
//go:embed all:catalog
var catalogFS embed.FS

// Catalog is a loaded, validated set of templates.
type Catalog struct {
	list []*Template
}

// NewCatalog sorts list by id. Ids must be unique.
func NewCatalog(list []*Template) *Catalog {
	c := &Catalog{list: slices.Clone(list)}
	slices.SortFunc(c.list, func(a, b *Template) int { return strings.Compare(a.ID, b.ID) })
	return c
}

// List returns the templates sorted by id.
func (c *Catalog) List() []*Template { return c.list }

// Get finds a template by id.
func (c *Catalog) Get(id string) (*Template, bool) {
	for _, t := range c.list {
		if t.ID == id {
			return t, true
		}
	}
	return nil, false
}

// Builtin returns the embedded catalog. It is validated by the package's
// tests, so failing here is a build defect.
var Builtin = sync.OnceValue(func() *Catalog {
	c, err := LoadFS(catalogFS, "catalog")
	if err != nil {
		panic(fmt.Sprintf("embedded template catalog: %v", err))
	}
	return c
})

// LoadFS reads every template folder under fsys/root (files at the root,
// like a NOTICE, are skipped). Any invalid template fails the whole load:
// it is for catalogs that must be entirely right (the embedded one, the
// pack command).
func LoadFS(fsys fs.FS, root string) (*Catalog, error) {
	list, errs := LoadEach(fsys, root)
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return NewCatalog(list), nil
}

// isTemplateDir skips files and hidden folders (.git, .github) at the
// root of a catalog.
func isTemplateDir(e fs.DirEntry) bool { return e.IsDir() && !strings.HasPrefix(e.Name(), ".") }

// LoadEach reads every template folder under fsys/root and returns the
// valid ones and one error per invalid folder (prefixed with its name).
func LoadEach(fsys fs.FS, root string) ([]*Template, []error) {
	entries, err := fs.ReadDir(fsys, root)
	if err != nil {
		return nil, []error{err}
	}
	var list []*Template
	var errs []error
	for _, e := range entries {
		if !isTemplateDir(e) {
			continue
		}
		t, err := ParseDir(fsys, path.Join(root, e.Name()))
		if err != nil {
			errs = append(errs, prefixLines(e.Name()+"/", err))
			continue
		}
		list = append(list, t)
	}
	return list, errs
}

// Merge combines the embedded catalog with templates from the community
// catalog: per id, the higher version wins and the embedded one wins ties.
func Merge(base *Catalog, extra []*Template) *Catalog {
	byID := map[string]*Template{}
	for _, t := range base.List() {
		byID[t.ID] = t
	}
	for _, t := range extra {
		if cur, ok := byID[t.ID]; ok && cur.Version >= t.Version {
			continue
		}
		byID[t.ID] = t
	}
	list := make([]*Template, 0, len(byID))
	for _, t := range byID {
		list = append(list, t)
	}
	return NewCatalog(list)
}

// Registry holds the catalog in use; the background sync swaps it while
// requests read it. Safe for concurrent use.
type Registry struct {
	cur atomic.Pointer[Catalog]
}

// NewRegistry starts with c.
func NewRegistry(c *Catalog) *Registry {
	r := &Registry{}
	r.cur.Store(c)
	return r
}

// Catalog returns the catalog in use.
func (r *Registry) Catalog() *Catalog { return r.cur.Load() }

// Set replaces the catalog in use.
func (r *Registry) Set(c *Catalog) { r.cur.Store(c) }

// prefixLines puts prefix before every line of err (a joined error has one
// problem per line), so each names its template folder.
func prefixLines(prefix string, err error) error {
	lines := strings.Split(err.Error(), "\n")
	for i, l := range lines {
		lines[i] = prefix + l
	}
	return errors.New(strings.Join(lines, "\n"))
}
