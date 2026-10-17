package errpages

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"strings"
	"testing"
)

func TestGenericPagesHaveNoIdentity(t *testing.T) {
	pages, err := Render(Brand{})
	if err != nil {
		t.Fatal(err)
	}
	if len(pages) != len(Kinds) {
		t.Fatalf("got %d pages", len(pages))
	}
	for name, p := range pages {
		s := string(p)
		for _, bad := range []string{"Hangar", "class=\"brand\"", "Precisa de ajuda"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s: generic page shows %q", name, bad)
			}
		}
		if !strings.Contains(s, `[[placeholder "http.request.uuid" | trunc 8]]`) {
			t.Errorf("%s: no request id action for Caddy", name)
		}
	}
}

func TestBrandPagesRender(t *testing.T) {
	b := Brand{Name: "Loja <X>", Contact: "suporte@x.com", Color: "#112233", Pages: map[string]Page{
		"down":  {Title: "Caiu"},
		"maint": {Title: "Em obras", Text: "Voltamos já"},
	}}
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	pages, err := Render(b)
	if err != nil {
		t.Fatal(err)
	}
	down := string(pages["down.html"])
	for _, want := range []string{"Loja &lt;X&gt;", "<h1>Caiu</h1>", "mailto:suporte@x.com", "--accent:#112233"} {
		if !strings.Contains(down, want) {
			t.Errorf("down page lacks %q", want)
		}
	}
	maint := string(pages["maint.html"])
	for _, want := range []string{"Em obras", "Voltamos já"} {
		if !strings.Contains(maint, want) {
			t.Errorf("maint page lacks %q", want)
		}
	}
}

func TestValidation(t *testing.T) {
	bad := []Brand{
		{Color: "red"},
		{Theme: "blue"},
		{LogoLight: "data:image/svg+xml;base64,PHN2Zz4="},
		{Pages: map[string]Page{"nope": {}}},
		{Name: strings.Repeat("x", 61)},
	}
	for _, b := range bad {
		if b.Validate() == nil {
			t.Errorf("accepted %+v", b)
		}
	}
	if _, err := LogoURI([]byte("<svg onload=alert(1)>"), "image/png"); err == nil {
		t.Error("SVG accepted as a logo")
	}
	if _, err := LogoURI([]byte("\x89PNG\r\n\x1a\nnot really a png"), ""); err == nil {
		t.Error("a broken PNG was accepted")
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, image.NewRGBA(image.Rect(0, 0, 40, 20)))
	// A valid image with something appended (a polyglot): the bytes after the
	// image never reach the stored logo.
	payload := append(buf.Bytes(), []byte("<script>alert(1)</script>")...)
	uri, err := LogoURI(payload, "")
	if err != nil || !strings.HasPrefix(uri, "data:image/png;base64,") {
		t.Fatalf("png: %q %v", uri, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(uri, "data:image/png;base64,"))
	if bytes.Contains(raw, []byte("script")) {
		t.Error("the appended script survived the re-encoding")
	}
	buf.Reset()
	_ = png.Encode(&buf, image.NewGray(image.Rect(0, 0, 4000, 10)))
	if _, err := LogoURI(buf.Bytes(), ""); err == nil {
		t.Error("an image wider than 2048 px was accepted")
	}
}
