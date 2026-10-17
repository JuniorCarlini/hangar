package web

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/errpages"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/web/views"
)

// The "Marca" settings: the identity and the text of the
// pages visitors see when a site cannot answer (internal/errpages).

func (h *handlers) brandPage(w http.ResponseWriter, r *http.Request) {
	flash := ""
	if r.URL.Query().Get("ok") == "brand" {
		flash = i18n.T(r.Context(), "brand.flash.saved")
	}
	h.renderBrand(w, r, http.StatusOK, "", flash)
}

func (h *handlers) renderBrand(w http.ResponseWriter, r *http.Request, status int, errMsg, flash string) {
	ctx := r.Context()
	pr := PrincipalFrom(ctx)
	b, err := h.brand.Load(ctx)
	if err != nil {
		status, errMsg = userError(r, err)
	}
	d := views.BrandData{
		CSRF: pr.CSRFToken, SudoActive: time.Now().Before(pr.SudoUntil), Error: errMsg, Flash: flash,
		EdgeOff: h.errorPages == nil, Name: b.Name, Contact: b.Contact, Color: b.Color, Theme: b.Theme,
		LogoLight: b.LogoLight, LogoDark: b.LogoDark, Version: time.Now().Unix(),
	}
	for _, k := range errpages.Kinds {
		title, text := errpages.Default(k)
		p := b.Pages[k]
		d.Pages = append(d.Pages, views.BrandPage{
			Kind: k, Title: p.Title, Text: p.Text, DefaultTitle: title, DefaultText: text,
			Custom: p.Title != "" || p.Text != "",
		})
	}
	render(w, r, status, views.BrandSettings(d))
}

// brandFail shows a settings error (an errpages.Error carries its own
// message key).
func (h *handlers) brandFail(w http.ResponseWriter, r *http.Request, err error) {
	var ve *errpages.Error
	if errors.As(err, &ve) {
		h.renderBrand(w, r, http.StatusUnprocessableEntity, i18n.T(r.Context(), ve.Key), "")
		return
	}
	code, msg := userError(r, err)
	h.renderBrand(w, r, code, msg, "")
}

// applyBrand stores the brand, renders the pages for Caddy and records it.
func (h *handlers) applyBrand(w http.ResponseWriter, r *http.Request, b errpages.Brand) {
	ctx := r.Context()
	if err := h.brand.Save(ctx, b); err != nil {
		h.brandFail(w, r, err)
		return
	}
	if h.errorPages != nil {
		pages, err := errpages.Render(b)
		if err == nil {
			err = h.errorPages(pages)
		}
		if err != nil {
			loggerFrom(ctx).Error("write error pages", "error", err)
			h.renderBrand(w, r, http.StatusInternalServerError, i18n.T(ctx, "brand.error.write"), "")
			return
		}
	}
	redirectLocal(w, r, "/brand?ok=brand")
}

// saveBrand saves the identity: name, contact, color, theme and the logos.
func (h *handlers) saveBrand(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Logos come as files; without them a plain form is fine too.
	switch err := r.ParseMultipartForm(maxBodyBytes); { //nolint:gosec // the body is capped by limitBody
	case errors.Is(err, http.ErrNotMultipart):
	case err != nil:
		h.brandFail(w, r, &errpages.Error{Key: "brand.error.logo_size"})
		return
	default:
		defer func() { _ = r.MultipartForm.RemoveAll() }()
	}
	b, err := h.brand.Load(ctx)
	if err != nil {
		h.brandFail(w, r, err)
		return
	}
	b.Name = strings.TrimSpace(r.FormValue("name"))
	b.Contact = strings.TrimSpace(r.FormValue("contact"))
	b.Color = strings.TrimSpace(r.FormValue("color"))
	if strings.EqualFold(b.Color, "#5b57f0") {
		b.Color = "" // the default
	}
	b.Theme = r.FormValue("theme")
	for _, l := range []struct {
		field string
		dst   *string
	}{{"logo_light", &b.LogoLight}, {"logo_dark", &b.LogoDark}} {
		if r.FormValue("remove_"+l.field) == "1" {
			*l.dst = ""
		}
		f, hdr, err := r.FormFile(l.field)
		if err != nil {
			continue // no new file
		}
		data, err := io.ReadAll(io.LimitReader(f, errpages.MaxLogo+1))
		_ = f.Close()
		if err != nil {
			h.brandFail(w, r, err)
			return
		}
		uri, err := errpages.LogoURI(data, hdr.Header.Get("Content-Type"))
		if err != nil {
			h.brandFail(w, r, err)
			return
		}
		*l.dst = uri
	}
	h.applyBrand(w, r, b)
}

// saveBrandPage saves one page's title and text ("reset" goes back to the
// built-in page).
func (h *handlers) saveBrandPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	kind := r.PathValue("kind")
	b, err := h.brand.Load(ctx)
	if err != nil {
		h.brandFail(w, r, err)
		return
	}
	if b.Pages == nil {
		b.Pages = map[string]errpages.Page{}
	}
	if r.PostFormValue("action") == "reset" {
		delete(b.Pages, kind)
	} else {
		p := errpages.Page{
			Title: strings.TrimSpace(r.PostFormValue("title")),
			Text:  strings.TrimSpace(r.PostFormValue("text")),
		}
		if p == (errpages.Page{}) {
			delete(b.Pages, kind)
		} else {
			b.Pages[kind] = p
		}
	}
	h.applyBrand(w, r, b)
}

// brandPreview shows one page as visitors see it, inside the settings'
// sandboxed frames: its own headers allow the page's inline style and
// framing by the panel, and forbid scripts.
func (h *handlers) brandPreview(w http.ResponseWriter, r *http.Request) {
	b, err := h.brand.Load(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	html, err := errpages.Preview(b, r.PathValue("kind"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Query().Get("thumb") == "1" {
		// Laid out at half size by the browser itself: sharp text, unlike a
		// scaled-down frame.
		html = thumbnail(html)
	}
	hd := w.Header()
	hd.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'; sandbox")
	hd.Set("X-Frame-Options", "SAMEORIGIN")
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	_, _ = w.Write(html) //nolint:gosec // the admin's own page, served sandboxed with scripts forbidden (CSP above)
}

// thumbnail makes a preview draw at half size.
func thumbnail(html []byte) []byte {
	const style = "<style>html{zoom:.5}</style>"
	s := string(html)
	if i := strings.Index(strings.ToLower(s), "</head>"); i >= 0 {
		return []byte(s[:i] + style + s[i:])
	}
	return []byte(style + s)
}
