package web

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/JuniorCarlini/hangar/internal/auth"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// Canvas geometry, in SVG units (px at 100%).
// Cards are compact, as on Railway: apps on the left, data on the right,
// close together; a database carries its volume under the card.
const (
	cvCardW  = 232
	cvCardH  = 92
	cvExtW   = 208
	cvColA   = 48
	cvColB   = 400
	cvColC   = 740
	cvTop    = 48
	cvRow    = 152
	cvMargin = 64
	cvVolume = 36 // the volume pill under a stateful card
)

var phaseProgress = map[string]int{"clone": 1, "build": 1, "pull": 1, "predeploy": 2, "start": 3, "health": 4, "switch": 5}

// buildCanvas lays the project out: apps on the left, databases and caches
// on the right, services of connected projects in a dashed group, and the
// internet above whatever has a domain. Lines come from the references in
// the variables.
func (h *handlers) buildCanvas(r *http.Request, p dbq.Project, selected string) (views.CanvasData, error) {
	ctx := r.Context()
	g, err := h.projects.ProjectGraph(ctx, p)
	if err != nil {
		return views.CanvasData{}, err
	}
	g = visibleGraph(g, PrincipalFrom(ctx))
	d := views.CanvasData{Project: p.Slug, ProjectName: p.Name}
	type box struct{ x, y, w, h int }
	pos := map[string]box{}

	var apps, data, ext []projects.GraphNode
	for _, n := range g.Nodes {
		switch {
		case n.External:
			ext = append(ext, n)
		case n.IsData():
			data = append(data, n)
		default:
			apps = append(apps, n)
		}
	}
	if len(apps) == 0 {
		apps, data = data, nil
	}
	top := cvTop
	// Cards with a saved position (dragged, or placed when a compose file
	// created them) go first; the automatic ones then take the next free
	// row of their column, so a card is never drawn on top of another.
	for _, n := range g.Nodes {
		if n.Moved {
			w := cvCardW
			if n.External {
				w = cvExtW
			}
			pos[n.ID] = box{n.X, n.Y, w, cvCardH}
		}
	}
	taken := func(c box) bool {
		for _, b := range pos {
			// A card's slot is a whole row: the card plus its volume chip.
			if c.x < b.x+b.w && b.x < c.x+c.w && c.y < b.y+cvRow && b.y < c.y+cvRow {
				return true
			}
		}
		return false
	}
	place := func(list []projects.GraphNode, x, w, y0 int) {
		row := 0
		for _, n := range list {
			if n.Moved {
				continue
			}
			c := box{x, y0 + row*cvRow, w, cvCardH}
			for taken(c) {
				row++
				c.y = y0 + row*cvRow
			}
			pos[n.ID] = c
			row++
		}
	}
	place(apps, cvColA, cvCardW, top)
	place(data, cvColB, cvCardW, top)
	extTop := top + 40
	place(ext, cvColC+20, cvExtW, extTop)

	maxX, maxY := 1000, 0
	for _, b := range pos {
		maxX = max(maxX, b.x+b.w)
		maxY = max(maxY, b.y+b.h)
	}
	if len(ext) > 0 || len(g.Linked) > 0 {
		gh := max(len(ext), 1)*cvRow + 20
		d.Groups = append(d.Groups, views.CanvasGroup{X: cvColC, Y: top, W: cvExtW + 40, H: gh, Label: linkedLabel(g.Linked)})
		maxX = max(maxX, cvColC+cvExtW+40)
		maxY = max(maxY, top+gh)
	}

	// One line per pair of services, however many variables link them (an
	// app wired to Postgres by six would draw six); its tooltip lists them.
	type link struct {
		From, To string
		Titles   []string
		Dashed   bool
	}
	var links []*link
	byPair := map[[2]string]*link{}
	for _, e := range g.Edges {
		k := [2]string{e.From, e.To}
		l := byPair[k]
		if l == nil {
			l = &link{From: e.From, To: e.To}
			byPair[k] = l
			links = append(links, l)
		}
		l.Titles = append(l.Titles, e.Key+" = ${{"+e.Ref+"}}")
		l.Dashed = l.Dashed || strings.Count(e.Ref, ".") > 1
	}

	// Edges: one slot per incoming line, so they do not overlap at the card.
	inCount, inIdx := map[string]int{}, map[string]int{}
	for _, e := range links {
		inCount[e.To]++
	}
	for _, e := range links {
		a, b := pos[e.From], pos[e.To]
		inIdx[e.To]++
		slot := 0.0
		if n := inCount[e.To]; n > 1 {
			slot = (float64(inIdx[e.To]) - float64(n+1)/2) * 18
		}
		var x1, y1, x2, y2 float64
		if b.x > a.x {
			x1, y1 = float64(a.x+a.w), float64(a.y+a.h/2)
			x2, y2 = float64(b.x), float64(b.y+b.h/2)+slot
		} else {
			// Same column (or leftwards): around the left side.
			x1, y1 = float64(a.x), float64(a.y+a.h/2)
			x2, y2 = float64(b.x), float64(b.y+b.h/2)+slot
		}
		d.Edges = append(d.Edges, views.CanvasEdge{
			D: curve(x1, y1, x2, y2, b.x <= a.x), Len: int(math.Hypot(x2-x1, y2-y1) * 1.4),
			Title: strings.Join(e.Titles, "\n"), Dashed: e.Dashed,
			From: slugOf(g, e.From), To: slugOf(g, e.To), Slot: int(slot),
		})
	}

	// Services built from Git show their repository instead of the image.
	repos := h.projects.GitDisplays(ctx, p.ID)
	// Variables whose references the next deploy cannot resolve.
	brokenKeys := map[string][]string{}
	if broken, err := h.projects.BrokenRefs(ctx, p); err == nil {
		for _, b := range broken {
			if ks := brokenKeys[b.ServiceID]; len(ks) == 0 || ks[len(ks)-1] != b.Key {
				brokenKeys[b.ServiceID] = append(ks, b.Key)
			}
		}
	}
	for i, n := range g.Nodes {
		b := pos[n.ID]
		if repo, ok := repos[n.ID]; ok && !n.External {
			n.Image = repo
		}
		cn := views.CanvasNode{
			Slug: n.Slug, Project: n.Project, Image: n.Image, Template: n.Template, External: n.External,
			X: b.x, Y: b.y, W: b.w, H: b.h, Selected: !n.External && n.Slug == selected,
			Exports: strings.Join(n.Exports, " "), Delay: min(i+1, 8), Pending: n.Pending,
			Href: servicePath(n.Project, n.Slug), Kind: kindOf(n),
		}
		if !n.External {
			cn.State, cn.Phase = h.nodeState(ctx, p.Slug, n)
			cn.Progress = phaseProgress[cn.Phase]
			if len(n.Ports) > 0 {
				cn.PortLabel, cn.PortAccess = fmt.Sprint(n.Ports[0].HostPort), n.Ports[0].Access
			}
			cn.Domain, cn.MoreHosts, cn.Dynamic = n.Domain, max(0, n.Domains-1), n.Dynamic
			cn.Maintenance = n.Maintenance
			cn.Volume = n.Stateful || len(n.Volumes) > 0
			if ks := brokenKeys[n.ID]; len(ks) > 0 {
				cn.Broken = i18n.T(ctx, "canvas.broken_refs", "n", len(ks), "keys", strings.Join(ks, ", "))
			}
			if !n.Stateful && len(n.Volumes) > 0 {
				// An app's disks show by where they are mounted.
				cn.VolumeLabel = strings.Join(n.Volumes, " · ")
			}
		}
		d.Nodes = append(d.Nodes, cn)
		if cn.Pending && cn.State != "deploying" {
			d.Pending = append(d.Pending, n.Slug)
		}
		switch cn.State {
		case "deploying":
			d.Deploying = true
		case "paused", "restarting", "created", "removing":
			// A backup pauses a service for a moment, a restart takes a
			// few seconds: the card must not stay on that state.
			d.Watch = true
		}
	}
	d.Width, d.Height = maxX+cvMargin, maxY+cvMargin+40
	return d, nil
}

// visibleGraph drops from the canvas what a user limited to some projects
// may not see (SEC-014): the services of a connected project outside their
// list, the lines to them and the project's name in the "connected" group.
// The router already answers 404 for those projects; the canvas must not
// name them either.
func visibleGraph(g projects.Graph, pr *auth.Principal) projects.Graph {
	if pr == nil || !pr.Limited() {
		return g
	}
	hidden := map[string]bool{}
	nodes := g.Nodes[:0:0]
	for _, n := range g.Nodes {
		if n.External && !pr.CanSeeProject(n.Project) {
			hidden[n.ID] = true
			continue
		}
		nodes = append(nodes, n)
	}
	edges := g.Edges[:0:0]
	for _, e := range g.Edges {
		if !hidden[e.To] && !hidden[e.From] {
			edges = append(edges, e)
		}
	}
	linked := g.Linked[:0:0]
	for _, l := range g.Linked {
		if pr.CanSeeProject(l.Slug) {
			linked = append(linked, l)
		}
	}
	g.Nodes, g.Edges, g.Linked = nodes, edges, linked
	return g
}

func linkedLabel(l []projects.GraphLinked) string {
	names := make([]string, 0, len(l))
	for _, x := range l {
		names = append(names, x.Slug)
	}
	return strings.Join(names, ", ")
}

func kindOf(n projects.GraphNode) string {
	switch {
	case n.Template == "postgres":
		return "db"
	case strings.HasPrefix(n.Template, "redis"):
		return "cache"
	case n.Stateful:
		return "db"
	}
	return "app"
}

// nodeState is the card's state and, while deploying, the current phase.
func (h *handlers) nodeState(ctx context.Context, project string, n projects.GraphNode) (string, string) {
	if deps, err := h.projects.Deployments(ctx, n.ID, 1); err == nil && len(deps) > 0 && deps[0].Status == "running" {
		return "deploying", deps[0].Phase
	}
	st, err := h.projects.Status(ctx, project, n.Slug)
	switch {
	case err != nil:
		return "unknown", ""
	case !st.Exists:
		if deps, _ := h.projects.Deployments(ctx, n.ID, 1); len(deps) > 0 && deps[0].Status == "failed" {
			return "failed", ""
		}
		return "missing", ""
	}
	return st.State, ""
}

// curve is a horizontal cubic Bézier from (x1,y1) to (x2,y2); back marks a
// line between cards of the same column, which bulges to the left.
func curve(x1, y1, x2, y2 float64, back bool) string {
	if back {
		bx := math.Min(x1, x2) - 60
		return fmt.Sprintf("M %.0f %.0f C %.0f %.0f, %.0f %.0f, %.0f %.0f", x1, y1, bx, y1, bx, y2, x2, y2)
	}
	dx := math.Max(60, math.Abs(x2-x1)/2)
	return fmt.Sprintf("M %.0f %.0f C %.0f %.0f, %.0f %.0f, %.0f %.0f", x1, y1, x1+dx, y1, x2-dx, y2, x2, y2)
}

// slugOf is the card key of a node: its slug, or project.slug when it
// belongs to a connected project.
func slugOf(g projects.Graph, id string) string {
	for _, n := range g.Nodes {
		if n.ID == id {
			if n.External {
				return n.Project + "." + n.Slug
			}
			return n.Slug
		}
	}
	return ""
}

// moveCard stores where a card was dropped on the canvas (called by
// canvas.js; answers 204).
func (h *handlers) moveCard(w http.ResponseWriter, r *http.Request) {
	x, errX := strconv.Atoi(r.PostFormValue("x"))
	y, errY := strconv.Atoi(r.PostFormValue("y"))
	if errX != nil || errY != nil {
		http.Error(w, "bad position", http.StatusBadRequest)
		return
	}
	if err := h.projects.SetCanvasPosition(r.Context(), r.PathValue("project"), r.PathValue("service"), x, y); err != nil {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tidyCanvas puts every card back in the automatic layout.
func (h *handlers) tidyCanvas(w http.ResponseWriter, r *http.Request) {
	if err := h.projects.ResetCanvasLayout(r.Context(), r.PathValue("project")); err != nil {
		http.NotFound(w, r)
		return
	}
	redirectLocal(w, r, "/p/"+r.PathValue("project"))
}
