// Package errpages renders the pages the edge shows visitors when a site
// cannot answer: down, updating, timed out, unknown domain, maintenance and
// HTTPS on its way. They are generic by default (no name, logo or contact:
// any site on the server may show them); the "Marca" settings can add an
// identity and replace the text of each page.
//
// The pages are rendered to files Caddy serves by itself, so they work even
// with the panel down. Caddy fills the per-request bits (request id, time)
// through its templates handler, with [[ ]] delimiters.
package errpages

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"image"
	_ "image/jpeg" // logo uploads
	"image/png"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	_ "golang.org/x/image/webp" // logo uploads

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Kinds of page, in the order the settings show them.
var Kinds = []string{"down", "deploy", "timeout", "unknown", "maint", "https"}

// File is the file name of a kind's page.
func File(kind string) string { return kind + ".html" }

// settingKey is where the brand lives in the settings table.
const settingKey = "brand"

// Limits of what the settings accept.
const (
	MaxLogo  = 200 << 10 // bytes of the image itself
	MaxTitle = 120
	MaxText  = 600
	MaxName  = 60
)

// Page is the admin's title and text for one page.
type Page struct {
	Title string `json:"title,omitempty"`
	Text  string `json:"text,omitempty"`
}

// Brand is everything the settings keep. The zero value is the generic look.
type Brand struct {
	Name      string          `json:"name,omitempty"`
	Contact   string          `json:"contact,omitempty"`
	Color     string          `json:"color,omitempty"` // #rrggbb
	Theme     string          `json:"theme,omitempty"` // "" (the visitor's), light or dark
	LogoLight string          `json:"logo_light,omitempty"`
	LogoDark  string          `json:"logo_dark,omitempty"`
	Pages     map[string]Page `json:"pages,omitempty"`
}

// Show says whether the identity line appears above the card.
func (b Brand) Show() bool { return b.Name != "" || b.LogoLight != "" || b.LogoDark != "" }

// Load reads the brand (the generic one when never saved).
func Load(ctx context.Context, q *dbq.Queries) (Brand, error) {
	var b Brand
	v, err := q.GetSetting(ctx, settingKey)
	if errors.Is(err, sql.ErrNoRows) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	return b, json.Unmarshal([]byte(v), &b)
}

// Save stores the brand after checking it.
func Save(ctx context.Context, q *dbq.Queries, b Brand) error {
	if err := b.Validate(); err != nil {
		return err
	}
	v, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return q.SetSetting(ctx, dbq.SetSettingParams{Key: settingKey, ValueJson: string(v)})
}

var colorRE = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)

// Error is a validation problem, with the i18n key the panel shows.
type Error struct{ Key string }

func (e *Error) Error() string { return e.Key }

func invalid(key string) error { return &Error{Key: key} }

// Validate checks what the settings may hold.
func (b Brand) Validate() error {
	switch {
	case len([]rune(b.Name)) > MaxName || strings.ContainsAny(b.Name, "\r\n"):
		return invalid("brand.error.name")
	case len(b.Contact) > 200 || strings.ContainsAny(b.Contact, "\r\n"):
		return invalid("brand.error.contact")
	case b.Color != "" && !colorRE.MatchString(b.Color):
		return invalid("brand.error.color")
	case b.Theme != "" && b.Theme != "light" && b.Theme != "dark":
		return invalid("brand.error.theme")
	}
	for _, l := range []string{b.LogoLight, b.LogoDark} {
		if l != "" && !validLogo(l) {
			return invalid("brand.error.logo")
		}
	}
	for k, p := range b.Pages {
		if !validKind(k) {
			return invalid("brand.error.page")
		}
		if len([]rune(p.Title)) > MaxTitle || len([]rune(p.Text)) > MaxText {
			return invalid("brand.error.too_long")
		}
	}
	return nil
}

func validKind(k string) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

// Logos are raster data URIs only: an SVG can carry script, and these pages
// are served on the sites' own domains.
var logoPrefixes = []string{"data:image/png;base64,", "data:image/jpeg;base64,", "data:image/webp;base64,"}

func validLogo(s string) bool {
	for _, p := range logoPrefixes {
		if strings.HasPrefix(s, p) {
			return len(s)-len(p) <= MaxStored*4/3+4
		}
	}
	return false
}

// Limits of an uploaded logo once opened: big enough for any logo, small
// enough that a crafted file cannot make decoding eat the server's memory.
const (
	maxLogoSide   = 2048
	maxLogoPixels = 2048 * 1024
	// MaxStored is the re-encoded PNG kept in the settings.
	MaxStored = 512 << 10
)

// LogoURI turns an uploaded image into a data URI, or refuses it. The image
// is decoded and drawn again as a fresh PNG: whatever else the file carried
// (metadata, a script in a polyglot file, trailing bytes) is dropped, and
// only PNG, JPEG or WebP pixels are accepted, whatever the browser claimed.
func LogoURI(data []byte, contentType string) (string, error) {
	_ = contentType // the bytes decide, not the browser's claim
	if len(data) > MaxLogo {
		return "", invalid("brand.error.logo_size")
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || (format != "png" && format != "jpeg" && format != "webp") {
		return "", invalid("brand.error.logo")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxLogoSide || cfg.Height > maxLogoSide || cfg.Width*cfg.Height > maxLogoPixels {
		return "", invalid("brand.error.logo_dimensions")
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", invalid("brand.error.logo")
	}
	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, img); err != nil {
		return "", invalid("brand.error.logo")
	}
	if out.Len() > MaxStored {
		return "", invalid("brand.error.logo_size")
	}
	return "data:image/png;base64," + b64(out.Bytes()), nil
}

//go:embed page.html.tmpl
var pageSrc string

var pageTmpl = template.Must(template.New("page").Parse(pageSrc))

// Default texts, in Portuguese (the visitors of the sites on this server).
type defaults struct {
	title, text, code, tone string
	rings                   bool
	retry                   int
}

var builtin = map[string]defaults{
	"down":    {"Este site está fora do ar por um momento", "O servidor recebeu o seu acesso, mas o site não respondeu. Já estamos tentando de novo: a página recarrega sozinha.", "Erro 502", "danger", true, 10},
	"deploy":  {"Estamos atualizando o site", "Uma versão nova está entrando no ar. Leva só alguns segundos e a página abre sozinha quando terminar.", "503 · volta em segundos", "info", true, 6},
	"timeout": {"O site demorou demais para responder", "Ele está no ar, mas esta página levou tempo demais para ficar pronta. Tente de novo em instantes.", "Erro 504", "warning", false, 0},
	"unknown": {"Este domínio ainda não está configurado", "O endereço chegou a este servidor, mas nenhum site está ligado a ele por enquanto.", "404 · domínio desconhecido", "neutral", false, 0},
	"maint":   {"Em manutenção", "Estamos fazendo melhorias. O site volta logo.", "503 · manutenção", "warning", false, 30},
	"https":   {"Ativando a conexão segura", "O certificado HTTPS deste endereço está sendo emitido agora. Em instantes esta página leva você para o endereço seguro.", "http · aguardando certificado", "success", false, 5},
}

const (
	icoPlug    = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22v-5"/><path d="M15 8V2"/><path d="M17 8a1 1 0 0 1 1 1v4a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V9a1 1 0 0 1 1-1z"/><path d="M9 8V2"/></svg>`
	icoRefresh = `<svg class="spin" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>`
	icoClock   = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><line class="hand slow" x1="12" y1="12" x2="15" y2="12"/><line class="hand" x1="12" y1="12" x2="12" y2="6"/></svg>`
	icoGlobe   = `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>`
	icoWrench  = `<svg class="wrench" viewBox="0 0 24 24" aria-hidden="true"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.106-3.105c.32-.322.863-.22.983.218a6 6 0 0 1-8.259 7.057l-7.91 7.91a1 1 0 0 1-2.999-3l7.91-7.91a6 6 0 0 1 7.057-8.259c.438.12.54.662.219.984z"/></svg>`
	icoLock    = `<svg viewBox="0 0 24 24" aria-hidden="true"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`
	icoRotate  = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21 12a9 9 0 1 1-9-9c2.52 0 4.93 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/></svg>`
)

var icons = map[string]string{"down": icoPlug, "deploy": icoRefresh, "timeout": icoClock, "unknown": icoGlobe, "maint": icoWrench, "https": icoLock}

func extra(kind string) template.HTML {
	switch kind {
	case "down":
		return template.HTML(`<div class="retry" aria-hidden="true"><span></span></div><p style="font-size:13px">Nova tentativa em <span id="count">10 s</span></p><div class="actions"><button class="btn main" type="button" id="again">` + icoRotate + `Tentar agora</button></div>`) //nolint:gosec // fixed markup
	case "deploy":
		return `<div class="sweep" aria-hidden="true"><span></span></div>`
	case "timeout":
		return template.HTML(`<div class="actions"><button class="btn main" type="button" onclick="location.reload()">` + icoRotate + `Tentar de novo</button></div>`) //nolint:gosec // fixed markup
	case "unknown":
		return `<div class="note"><b>É o dono deste domínio?</b> Ligue o domínio a um site no painel do servidor. Se você acabou de apontar o DNS, pode levar alguns minutos.</div>`
	}
	return ""
}

type pageData struct {
	Lang, Title, Text, Code, Tone, Theme string
	Rings                                bool
	Retry                                int
	Icon, Extra                          template.HTML
	AccentCSS                            template.CSS
	Brand                                Brand
	ContactHref                          string
	T                                    map[string]string
}

// Render produces every page as file name → HTML for Caddy (with [[ ]]
// template actions for the per-request parts).
func Render(b Brand) (map[string][]byte, error) {
	out := make(map[string][]byte, len(Kinds))
	for _, k := range Kinds {
		html, err := renderOne(b, k)
		if err != nil {
			return nil, fmt.Errorf("page %s: %w", k, err)
		}
		out[File(k)] = html
	}
	return out, nil
}

func renderOne(b Brand, kind string) ([]byte, error) {
	d := builtin[kind]
	data := pageData{
		Lang: "pt-BR", Title: d.title, Text: d.text, Code: d.code, Tone: d.tone, Theme: b.Theme,
		Rings: d.rings, Retry: d.retry, Icon: template.HTML(icons[kind]), Extra: extra(kind), //nolint:gosec // fixed markup
		Brand: b, T: map[string]string{"help": "Precisa de ajuda?"},
	}
	if p := b.Pages[kind]; p.Title != "" {
		data.Title = p.Title
	}
	if p := b.Pages[kind]; p.Text != "" {
		data.Text = p.Text
	}
	accent := b.Color
	if accent == "" {
		accent = "#5b57f0"
	}
	data.AccentCSS = template.CSS(":root{--accent:" + accent + "}") //nolint:gosec // validated #rrggbb
	data.ContactHref = contactHref(b.Contact)
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// contactHref makes an e-mail, phone or URL clickable ("" = plain text).
func contactHref(c string) string {
	c = strings.TrimSpace(c)
	if c == "" {
		return ""
	}
	if a, err := mail.ParseAddress(c); err == nil && a.Address == c {
		return "mailto:" + c
	}
	if u, err := url.Parse(c); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" {
		return c
	}
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' || r == '+' {
			return r
		}
		return -1
	}, c)
	if len(digits) >= 8 {
		return "tel:" + digits
	}
	return ""
}

// Preview renders one page as a visitor would see it, with sample values in
// place of what Caddy fills per request.
func Preview(b Brand, kind string) ([]byte, error) {
	if !validKind(kind) {
		return nil, invalid("brand.error.page")
	}
	html, err := renderOne(b, kind)
	if err != nil {
		return nil, err
	}
	s := string(html)
	s = strings.ReplaceAll(s, `[[placeholder "http.request.uuid" | trunc 8]]`, "a7f3c2e1")
	s = strings.ReplaceAll(s, `[[now | date "02/01 15:04"]]`, "16/10 14:32")
	return []byte(s), nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Default is a kind's built-in title and text (the placeholders of the
// settings form).
func Default(kind string) (title, text string) {
	d := builtin[kind]
	return d.title, d.text
}

// Store reads and writes the brand in the panel database.
type Store struct{ q *dbq.Queries }

// NewStore returns the brand store.
func NewStore(db dbq.DBTX) *Store { return &Store{q: dbq.New(db)} }

// Load reads the brand.
func (s *Store) Load(ctx context.Context) (Brand, error) { return Load(ctx, s.q) }

// Save checks and stores the brand.
func (s *Store) Save(ctx context.Context, b Brand) error { return Save(ctx, s.q, b) }
