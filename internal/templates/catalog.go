package templates

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"reflect"
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
// catalog (see MergeChecked); the refused ones are dropped silently.
func Merge(base *Catalog, extra []*Template) *Catalog {
	c, _ := MergeChecked(base, extra)
	return c
}

// MergeChecked combines the embedded catalog with templates from the
// community catalog, returning one error per community template it refused.
//
// A new id is added as is. An id the binary already ships cannot be
// replaced by the community catalog (the catalog key must not be as
// powerful as the release key): a higher version is only taken as an image
// update of the embedded template. Everything that decides what runs and
// how (services, commands, env, volumes, caps, health, inputs, exports,
// backup, endpoints, sizes) must be identical, and each image must keep its
// repository; only the tag or digest may move. The result is the embedded
// template with those images and the higher version. Anything else keeps
// the embedded one. Ties keep the embedded one too.
func MergeChecked(base *Catalog, extra []*Template) (*Catalog, []error) {
	byID := map[string]*Template{}
	builtin := map[string]*Template{}
	for _, t := range base.List() {
		byID[t.ID] = t
		builtin[t.ID] = t
	}
	var refused []error
	for _, t := range extra {
		emb, ok := builtin[t.ID]
		if !ok {
			if cur, dup := byID[t.ID]; dup && cur.Version >= t.Version {
				continue
			}
			byID[t.ID] = t
			continue
		}
		if t.Version <= emb.Version {
			continue
		}
		bumped, err := imageUpdate(emb, t)
		if err != nil {
			refused = append(refused, fmt.Errorf("%s: %w", t.ID, err))
			continue
		}
		byID[t.ID] = bumped
	}
	list := make([]*Template, 0, len(byID))
	for _, t := range byID {
		list = append(list, t)
	}
	return NewCatalog(list), refused
}

// imageUpdate returns emb with remote's images and version when remote
// differs from emb only in its images' tags or digests.
func imageUpdate(emb, remote *Template) (*Template, error) {
	if len(emb.Services) != len(remote.Services) {
		return nil, errors.New("replaces an embedded template with different services; only image tags may change")
	}
	a, b := runtimeView(emb), runtimeView(remote)
	for i := range a.Services {
		if imageRepo(a.Services[i].Image) != imageRepo(b.Services[i].Image) {
			return nil, fmt.Errorf("service %s: image %s replaces %s; only the tag may change", b.Services[i].Name, b.Services[i].Image, a.Services[i].Image)
		}
		a.Services[i].Image, b.Services[i].Image = "", ""
	}
	if !reflect.DeepEqual(a, b) {
		return nil, errors.New("changes more than image tags of an embedded template")
	}
	out := *emb
	out.Services = slices.Clone(emb.Services)
	for i := range out.Services {
		out.Services[i].Image = remote.Services[i].Image
	}
	out.Version = remote.Version
	out.Remote = true
	return &out, nil
}

// runtimeView is t without what is only shown (names, text, logo, readme,
// tags, version, warnings): everything left decides what runs and how, and
// a field added to Template later is compared by default. The presentation
// of a merged template always comes from the embedded one.
func runtimeView(t *Template) Template {
	v := *t
	v.Version, v.Category, v.Tags, v.Name, v.Description, v.Docs = 0, "", nil, nil, nil, ""
	v.MinHangar, v.Logo, v.Readme, v.Remote, v.Warnings = "", nil, "", false, nil
	v.Services = slices.Clone(t.Services)
	for i := range v.Services {
		v.Services[i].warnings = nil
	}
	return v
}

// imageRepo is an image reference without its tag and digest
// ("docker.io/library/postgres:18.1@sha256:..." -> "docker.io/library/postgres").
func imageRepo(ref string) string {
	ref, _, _ = strings.Cut(ref, "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return ref
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
