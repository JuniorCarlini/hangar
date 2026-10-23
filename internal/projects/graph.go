package projects

import (
	"context"
	"database/sql"
	"sort"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Graph is what the project canvas draws: the services, the connections
// that references create between them (${{db.DATABASE_URL}} is a line from
// the service holding it to db), and what reaches them from outside.
type Graph struct {
	Nodes  []GraphNode
	Edges  []GraphEdge
	Linked []GraphLinked
}

// GraphNode is one service of the project, or of a connected project that
// a reference points at.
type GraphNode struct {
	ID       string // service id
	Project  string
	Slug     string
	Image    string
	Template string
	Stateful bool
	Port     int64
	External bool   // belongs to a connected project
	Domains  int    // fixed domains
	Domain   string // the first fixed domain, shown on the card
	Dynamic  bool   // takes customer domains
	// Maintenance: visitors get the maintenance page instead of the app.
	Maintenance bool
	Ports       []dbq.Port
	Exports     []string // keys others may reference
	Volumes     []string // mount paths of its disks
	Pending     bool
	// X, Y is where the user left the card (Moved=false: automatic layout).
	X, Y  int
	Moved bool
}

// GraphEdge is a reference from one service to another.
type GraphEdge struct {
	From, To string // service ids
	Key      string // the variable that holds the reference
	Ref      string // the reference itself, e.g. db.DATABASE_URL
}

// GraphLinked is a connected project.
type GraphLinked struct {
	Slug     string
	Services int
}

// ProjectGraph builds the canvas of a project. Only names and references
// leave the database here, never variable values.
func (m *Manager) ProjectGraph(ctx context.Context, p dbq.Project) (Graph, error) {
	var g Graph
	svcs, err := m.q.ListServices(ctx, p.ID)
	if err != nil {
		return g, err
	}
	linked, err := m.q.LinkedProjects(ctx, p.ID)
	if err != nil {
		return g, err
	}
	bySlug := map[string]map[string]dbq.Service{p.Slug: {}}
	for _, s := range svcs {
		bySlug[p.Slug][s.Slug] = s
	}
	for _, l := range linked {
		ls, err := m.q.ListServices(ctx, l.ID)
		if err != nil {
			return g, err
		}
		bySlug[l.Slug] = map[string]dbq.Service{}
		for _, s := range ls {
			bySlug[l.Slug][s.Slug] = s
		}
		g.Linked = append(g.Linked, GraphLinked{Slug: l.Slug, Services: len(ls)})
	}

	nodes := map[string]int{}
	add := func(project string, s dbq.Service, external bool) error {
		if _, ok := nodes[s.ID]; ok {
			return nil
		}
		n := GraphNode{
			ID: s.ID, Project: project, Slug: s.Slug, Image: s.Image, Template: s.Template,
			Stateful: s.Stateful == 1, Port: s.InternalPort, External: external, Dynamic: s.DynamicDomains == 1, Maintenance: s.Maintenance == 1,
		}
		if !external && s.CanvasX.Valid && s.CanvasY.Valid {
			n.X, n.Y, n.Moved = int(s.CanvasX.Int64), int(s.CanvasY.Int64), true
		}
		if !external {
			if ds, err := m.q.ListDomains(ctx, s.ID); err == nil {
				n.Domains = len(ds)
				if len(ds) > 0 {
					n.Domain = ds[0].Hostname
				}
			}
			if pts, err := m.q.ListPorts(ctx, s.ID); err == nil {
				n.Ports = pts
			}
			n.Pending, _ = m.PendingChanges(ctx, s.ID)
			if vols, err := m.q.ListVolumes(ctx, s.ID); err == nil {
				for _, v := range vols {
					n.Volumes = append(n.Volumes, v.Path)
				}
			}
		}
		// What it offers: a card offering nothing takes no connection.
		offers, err := m.Offers(ctx, s.ID)
		if err != nil {
			return err
		}
		for _, o := range offers {
			n.Exports = append(n.Exports, o.Key)
		}
		nodes[s.ID] = len(g.Nodes)
		g.Nodes = append(g.Nodes, n)
		return nil
	}
	for _, s := range svcs {
		if err := add(p.Slug, s, false); err != nil {
			return g, err
		}
	}

	for _, s := range svcs {
		rows, err := m.q.ListEnv(ctx, s.ID)
		if err != nil {
			return g, err
		}
		for _, r := range rows {
			plain, err := m.box.Open(r.ValueEnc, envAD(s.ID, r.Key))
			if err != nil {
				continue
			}
			for _, ref := range refRE.FindAllStringSubmatch(string(plain), -1) {
				project, service := ref[1], ref[2]
				if project == "" {
					project = p.Slug
				}
				target, ok := bySlug[project][service]
				if !ok {
					continue
				}
				if err := add(project, target, project != p.Slug); err != nil {
					return g, err
				}
				refText := service + "." + ref[3]
				if project != p.Slug {
					refText = project + "." + refText
				}
				g.Edges = append(g.Edges, GraphEdge{From: s.ID, To: target.ID, Key: r.Key, Ref: refText})
			}
		}
	}
	sort.SliceStable(g.Edges, func(i, j int) bool { return g.Edges[i].From+g.Edges[i].Key < g.Edges[j].From+g.Edges[j].Key })
	return g, nil
}

// IsData tells whether a node is a database or cache (drawn on the right).
func (n GraphNode) IsData() bool {
	return n.Stateful || n.Template != ""
}

// SetCanvasPosition stores where the user dropped a card (cosmetic: not
// audited). The canvas has no edge, negative coordinates included; they are
// only clamped to a range no one reaches by dragging.
func (m *Manager) SetCanvasPosition(ctx context.Context, projectSlug, serviceSlug string, x, y int) error {
	_, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	clamp := func(v int) int64 { return int64(max(-100000, min(v, 100000))) }
	return m.q.SetCanvasPosition(ctx, dbq.SetCanvasPositionParams{
		CanvasX: sql.NullInt64{Int64: clamp(x), Valid: true}, CanvasY: sql.NullInt64{Int64: clamp(y), Valid: true}, ID: s.ID,
	})
}

// ResetCanvasLayout forgets where the cards were dropped: the canvas goes back
// to the automatic layout.
func (m *Manager) ResetCanvasLayout(ctx context.Context, projectSlug string) error {
	p, err := m.GetProject(ctx, projectSlug)
	if err != nil {
		return err
	}
	return m.q.ResetCanvasPositions(ctx, p.ID)
}
