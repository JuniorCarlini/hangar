package views

// Data for the /_pista catalog. The classes are written out in full so
// Tailwind (which scans views/*.go) generates them.

// pistaSwatch is a color token and the Tailwind class that paints it.
type pistaSwatch struct {
	Token string // CSS variable, without "--p-"
	Class string // bg-* utility that maps to the token
}

var pistaSwatches = []pistaSwatch{
	{"bg", "bg-bg"},
	{"canvas", "bg-canvas"},
	{"surface", "bg-surface"},
	{"surface-2", "bg-surface-2"},
	{"border", "bg-border"},
	{"border-strong", "bg-border-strong"},
	{"fg", "bg-fg"},
	{"muted", "bg-muted"},
	{"subtle", "bg-subtle"},
	{"accent", "bg-accent"},
	{"accent-hover", "bg-accent-hover"},
	{"accent-text", "bg-accent-text"},
	{"accent-soft", "bg-accent-soft"},
	{"on-accent", "bg-on-accent"},
	{"success", "bg-success"},
	{"success-soft", "bg-success-soft"},
	{"info", "bg-info"},
	{"info-soft", "bg-info-soft"},
	{"warning", "bg-warning"},
	{"warning-soft", "bg-warning-soft"},
	{"danger", "bg-danger"},
	{"danger-soft", "bg-danger-soft"},
}

// pistaTones are the semantic tones, in the order the catalog shows them.
var pistaTones = []string{"info", "success", "warning", "danger"}

// pistaToneIcon is the alert icon of each tone.
func pistaToneIcon(tone string) string {
	switch tone {
	case "success":
		return "circle-check"
	case "warning":
		return "triangle-alert"
	case "danger":
		return "circle-x"
	}
	return "info"
}

// pistaRow is a sample row of the table section.
type pistaRow struct {
	Service, Image, Port, State, When string
}

var pistaRows = []pistaRow{
	{"web", "nginx:1.29-alpine", "80/tcp", "running", "16/10 14:02"},
	{"postgres", "postgres:18-alpine", "5432/tcp", "deploying", "16/10 13:47"},
	{"worker", "python:3.14-slim", "—", "exited", "15/10 22:10"},
}

// pistaNode is a sample canvas card.
type pistaNode struct {
	Slug, Kind, Image, State string
	Selected                 bool
}

var pistaNodes = []pistaNode{
	{Slug: "web", Kind: "app", Image: "nginx:1.29-alpine", State: "running", Selected: true},
	{Slug: "postgres", Kind: "db", Image: "postgres:18-alpine", State: "running"},
	{Slug: "redis", Kind: "cache", Image: "redis:8-alpine", State: "deploying"},
	{Slug: "worker", Kind: "app", Image: "python:3.14-slim", State: "exited"},
}

func pistaNodeClass(n pistaNode) string {
	if n.Selected {
		return "node is-selected"
	}
	return "node"
}
