package web

import (
	"fmt"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/gitsrc"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/templates"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// nsState is what the new-service dialog shows: the tab, what was typed
// and the error, after a form came back.
type nsState struct {
	tab      string
	err      string
	form     views.ServiceForm
	template string
	tplName  string
	inputs   map[string]string
	// limits are the template's disk limits as the form sent them, by
	// volume: the size in GB, or "" for unchecked.
	limits  map[string]string
	compose views.ComposeView
	open    bool
	github  string // the GitHub credential "Meus repositórios" starts on
}

// newServiceData builds the dialog: every tab starts with a sensible name
// that is free in the project.
func (h *handlers) newServiceData(r *http.Request, p dbq.Project, st nsState) *views.NewServiceData {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	loc := i18n.Locale(ctx)
	taken := map[string]bool{}
	var slugs []string
	if svcs, err := h.projects.ListServices(ctx, p.ID); err == nil {
		for _, s := range svcs {
			taken[s.Slug] = true
			slugs = append(slugs, s.Slug)
		}
	}
	d := &views.NewServiceData{
		CSRF: pr.CSRFToken, Project: p.Slug, ProjectName: p.Name, Open: st.open, Tab: st.tab, Error: st.err,
		Place: placeFrom(r), Taken: strings.Join(slugs, " "), Form: st.form, Compose: st.compose,
	}
	if d.Tab == "" {
		d.Tab = "template"
	}
	f := st.form
	d.Advanced = f.Port+f.MemoryMB+f.CPUs+f.Branch+f.Subdir+f.Dockerfile != "" || (st.tab == "template" && st.err != "")

	usedCats := map[string]bool{}
	limitsOK := h.projects.VolumeLimitsAvailable()
	for _, tp := range h.projects.Templates() {
		nt := views.NewTemplate{
			ID: tp.ID, Name: tp.Name.In(loc), Description: tp.Description.In(loc), Kind: templateKind(tp.ID, tp.Category),
			LogoURL: tp.LogoURL(), Category: tp.Category, CategoryLabel: i18n.T(ctx, "template.category."+tp.Category),
			Docs: tp.Docs, Version: tp.Version, Remote: tp.Remote,
			DefaultName: projects.UniqueName(projects.TemplateName(tp.ID), taken),
		}
		nt.Search = strings.ToLower(strings.Join(append([]string{tp.ID, nt.Name, nt.Description, nt.CategoryLabel}, tp.Tags...), " "))
		usedCats[tp.Category] = true
		for _, s := range tp.Services {
			ts := views.TemplateService{
				Name: s.Name, Image: s.Image, Health: s.Health != nil,
				Limits: fmt.Sprintf("%d MB · %s CPU", s.MemoryMB, strconv.FormatFloat(s.CPUs, 'f', -1, 64)),
			}
			for _, v := range s.Volumes {
				disk := v.Name + " → " + v.Path
				if size, ok := tp.Sizes[v.Name]; ok && v.Owner == "" {
					disk = i18n.T(ctx, "catalog.disk_limit", "disk", disk, "size", fmtBytes(ctx, uint64(size))) //nolint:gosec // a validated size, positive
				}
				ts.Disks = append(ts.Disks, disk)
			}
			nt.Services = append(nt.Services, ts)
		}
		for _, e := range tp.Exports {
			nt.Exports = append(nt.Exports, e.Key)
		}
		// A template born public is so only for someone who confirmed the
		// password moments ago (projects.Actor.Sudo); say what will happen.
		sudo := time.Now().Before(pr.SudoUntil)
		// The suggested disk limits come checked (a limit needs sudo too).
		if limitsOK {
			for _, s := range tp.Services {
				for _, v := range s.Volumes {
					size, ok := tp.Sizes[v.Name]
					if !ok || v.Owner != "" {
						continue
					}
					tl := views.TemplateLimit{Volume: v.Name, SizeGB: ceilGB(size), On: sudo, NeedsSudo: !sudo}
					if tp.ID == st.template && st.limits != nil && sudo {
						if gb, sent := st.limits[v.Name]; sent {
							tl.On = gb != ""
							if n, err := strconv.Atoi(gb); err == nil && n > 0 {
								tl.SizeGB = n
							}
						}
					}
					nt.Limits = append(nt.Limits, tl)
				}
			}
		}
		for _, ep := range tp.Endpoints {
			nt.Links = append(nt.Links, views.TemplateLink{Label: ep.Label.In(loc), Port: ep.Port, Public: ep.Public && sudo, NeedsSudo: ep.Public && !sudo})
		}
		for _, in := range tp.Inputs {
			v := in.Default
			if tp.ID == st.template && st.inputs[in.Key] != "" {
				v = st.inputs[in.Key]
			}
			nt.Inputs = append(nt.Inputs, views.TemplateInput{Key: in.Key, Label: in.Label.In(loc), Pattern: htmlPattern(in.Pattern), Value: v})
		}
		d.Templates = append(d.Templates, nt)
		if tp.ID == st.template {
			d.Template, d.TemplateName = tp.ID, nt.DefaultName
		}
	}
	for _, c := range templates.Categories {
		if usedCats[c] {
			d.Categories = append(d.Categories, views.CatalogCategory{Key: c, Label: i18n.T(ctx, "template.category."+c)})
		}
	}
	if st.tplName != "" {
		d.TemplateName = st.tplName
	}
	for i := range d.Templates {
		nt := &d.Templates[i]
		nt.FormName = nt.DefaultName
		if nt.ID == d.Template && d.TemplateName != "" {
			nt.FormName = d.TemplateName
		}
		nt.FormSlug = projects.Slugify(nt.FormName)
	}

	d.ImageName = projects.UniqueName(projects.NameFromImage(f.Image), taken)
	d.GitName = projects.UniqueName(projects.NameFromRepo(f.Repo), taken)
	if typed := strings.TrimSpace(f.Name + f.Slug); typed != "" {
		switch st.tab {
		case "image":
			d.ImageName = typed
		case "git":
			d.GitName = typed
		}
	}
	d.TemplateSlug, d.ImageSlug, d.GitSlug = projects.Slugify(d.TemplateName), projects.Slugify(d.ImageName), projects.Slugify(d.GitName)

	d.CredOptions = h.gitCredOptions(ctx, p.ID)
	for _, o := range d.CredOptions {
		if strings.EqualFold(o.Host, gitsrc.GitHubHost) {
			d.GitHubCreds = append(d.GitHubCreds, o)
		}
	}
	d.ManualGit = st.tab == "git" && (st.err != "" || f.Repo != "")
	for _, o := range d.GitHubCreds {
		if o.ID == st.github {
			d.GitHubSelected = o.ID
		}
	}
	d.CredSelected = f.Credential
	if f.Credential == "" && f.Repo == "" && len(d.CredOptions) > 0 {
		d.CredSelected = d.CredOptions[0].ID // a new form starts on the first credential
	}
	if d.Compose.Source == "" {
		d.Compose.Source = "paste"
	}
	if d.Compose.CredSelected == "" && d.Compose.Repo == "" && len(d.CredOptions) > 0 {
		d.Compose.CredSelected = d.CredOptions[0].ID
	}
	return d
}

// renderNew renders the canvas with the new-service dialog open.
func (h *handlers) renderNew(w http.ResponseWriter, r *http.Request, status int, st nsState) {
	p, err := h.projects.GetProject(r.Context(), r.PathValue("project"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	cd, err := h.canvasFor(r, p, "")
	if err != nil {
		code, msg := userError(r, err)
		status, cd.Error = code, msg
	}
	st.open = true
	cd.New = h.newServiceData(r, p, st)
	render(w, r, status, views.ProjectCanvas(cd, nil))
}

// --- docker-compose import ---------------------------------------------------

// composeSample serves the model compose file as plain text (the dialog
// shows it, copies it or puts it in the text box).
func (h *handlers) composeSample(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = w.Write([]byte(projects.ComposeSample))
}

// composeInput reads the Compose tab: the pasted file, or the repository to
// read it from (a "new" credential is saved here, once).
func (h *handlers) composeInput(r *http.Request) (views.ComposeView, *projects.ComposeRepo, error) {
	cv := views.ComposeView{
		Source: r.PostFormValue("source"), Text: r.PostFormValue("compose"),
		Repo: r.PostFormValue("repo"), Branch: r.PostFormValue("branch"), CredSelected: r.PostFormValue("credential"),
	}
	if cv.Source != "git" {
		cv.Source = "paste"
		return cv, nil, nil
	}
	cv.Text = ""
	id, err := h.pickedCredential(r, r.PathValue("project"))
	if err != nil {
		return cv, nil, err
	}
	cv.CredSelected = id
	return cv, &projects.ComposeRepo{
		GitSourceInput: projects.GitSourceInput{URL: cv.Repo, Branch: cv.Branch}, CredentialID: id,
	}, nil
}

func (h *handlers) planCompose(r *http.Request, cv views.ComposeView, repo *projects.ComposeRepo) (projects.ComposePlan, error) {
	if repo != nil {
		return h.projects.PlanComposeFromRepo(r.Context(), r.PathValue("project"), repo)
	}
	return h.projects.PlanCompose(r.Context(), r.PathValue("project"), []byte(cv.Text))
}

// composePreview shows what the file would create, and nothing more.
func (h *handlers) composePreview(w http.ResponseWriter, r *http.Request) {
	cv, repo, err := h.composeInput(r)
	if err == nil {
		var plan projects.ComposePlan
		if plan, err = h.planCompose(r, cv, repo); err == nil {
			cv.Preview = h.previewOf(r, plan)
		}
	}
	st := nsState{tab: "compose", compose: cv}
	status := http.StatusOK
	if err != nil {
		status, st.err = userError(r, err)
	}
	h.renderNew(w, r, status, st)
}

// composeCreate plans the file again (the preview is never trusted), lays
// the new cards out and creates everything at once.
func (h *handlers) composeCreate(w http.ResponseWriter, r *http.Request) {
	cv, repo, err := h.composeInput(r)
	var plan projects.ComposePlan
	if err == nil {
		plan, err = h.planCompose(r, cv, repo)
	}
	if err == nil {
		h.placeCompose(r, &plan)
		_, err = h.projects.CreateFromCompose(r.Context(), actor(r), r.PathValue("project"), plan, repo)
	}
	if err != nil {
		code, msg := userError(r, err)
		if len(plan.Services) > 0 {
			cv.Preview = h.previewOf(r, plan)
		}
		h.renderNew(w, r, code, nsState{tab: "compose", compose: cv, err: msg})
		return
	}
	project := r.PathValue("project")
	if !node.SlugRE.MatchString(project) {
		project = ""
	}
	redirectLocal(w, r, "/p/"+project+"?ok=compose")
}

// placeCompose puts the imported cards below everything already on the
// canvas (or where the line was dropped): apps in the left column,
// databases and caches beside them, one row each.
func (h *handlers) placeCompose(r *http.Request, plan *projects.ComposePlan) {
	p, err := h.projects.GetProject(r.Context(), r.PathValue("project"))
	if err != nil {
		return
	}
	x0, top := cvColA, cvTop
	if cd, err := h.buildCanvas(r, p, ""); err == nil {
		bottom := 0
		for _, n := range cd.Nodes {
			if n.External {
				continue
			}
			b := n.Y + n.H
			if n.Volume {
				b += cvVolume
			}
			bottom = max(bottom, b)
		}
		if bottom > 0 {
			top = (bottom + cvRow - cvCardH + 15) / 16 * 16
		}
	}
	if pl := placeFrom(r); pl.Set {
		x0, top = pl.X, pl.Y
	}
	apps, data := 0, 0
	for i := range plan.Services {
		s := &plan.Services[i]
		switch s.Kind {
		case projects.ComposeSkip:
			continue
		case projects.ComposeTemplate:
			s.X, s.Y = x0+cvColB-cvColA, top+data*cvRow
			data++
		default:
			s.X, s.Y = x0, top+apps*cvRow
			apps++
		}
		s.Placed = true
	}
}

// previewOf turns a plan into the dialog's preview, in the user's language.
func (h *handlers) previewOf(r *http.Request, plan projects.ComposePlan) *views.ComposePreview {
	loc := i18n.Locale(r.Context())
	pv := &views.ComposePreview{File: plan.File, Creatable: plan.Creatable()}
	conv := func(ns []projects.ComposeNote) []views.PreviewNote {
		out := make([]views.PreviewNote, 0, len(ns))
		for _, n := range ns {
			out = append(out, views.PreviewNote{Level: n.Level, Text: n.Msg.In(loc)})
			switch n.Level {
			case projects.NoteWarn:
				pv.Warnings++
			case projects.NoteSkip:
				pv.Skipped++
			}
		}
		return out
	}
	pv.Notes = conv(plan.Notes)
	for _, s := range plan.Services {
		ps := views.ComposePreviewService{Name: s.Name, Slug: s.Slug, Kind: s.Kind, Icon: "app", Notes: conv(s.Notes)}
		switch s.Kind {
		case projects.ComposeTemplate:
			ps.Icon = templateKind(s.Template, "database")
			if tp, ok := h.projects.Template(s.Template); ok {
				ps.What = tp.Name.In(loc)
			}
		case projects.ComposeImage:
			ps.What = s.Image
		case projects.ComposeGit:
			dir := s.Subdir
			if dir == "" {
				dir = "."
			}
			ps.What = path.Join(dir, s.Dockerfile)
		}
		if s.Kind != projects.ComposeSkip {
			pv.Count++
		}
		if s.Port > 0 {
			ps.Port = strconv.Itoa(s.Port)
		}
		if s.MemoryMB > 0 || s.CPUs > 0 {
			mem, cpus := s.MemoryMB, s.CPUs
			if mem == 0 {
				mem = projects.DefaultMemoryMB
			}
			if cpus == 0 {
				cpus = projects.DefaultCPUs
			}
			ps.Limits = i18n.Tl(loc, "service.stat.limits_value", "memory", mem, "cpus", strconv.FormatFloat(cpus, 'f', -1, 64))
		}
		var disks []string
		for _, v := range s.Volumes {
			disks = append(disks, fmt.Sprintf("%s:%s", v.Name, v.Path))
		}
		ps.Disks = strings.Join(disks, " · ")
		for _, e := range s.Env {
			ps.Env = append(ps.Env, views.PreviewEnv{Key: e.Key, Value: e.Value, Ref: e.Ref, Secret: e.Secret})
		}
		if s.Problem != nil {
			ps.Problem = s.Problem.In(loc)
		}
		pv.Services = append(pv.Services, ps)
	}
	return pv
}
