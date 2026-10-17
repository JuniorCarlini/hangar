package templates

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxLogoBytes caps a template's logo.svg.
const MaxLogoBytes = 64 << 10

// forbiddenElements could run code or pull content into the page.
var forbiddenElements = map[string]bool{
	"script": true, "foreignobject": true, "iframe": true, "embed": true, "object": true,
	"audio": true, "video": true, "image": true, "feimage": true,
}

// urlRE finds url(...) references in styles and presentation attributes;
// only local ones (url(#gradient)) are allowed.
var urlRE = regexp.MustCompile(`(?i)url\s*\(\s*['"]?\s*([^)'"\s]*)`)

// CheckSVG accepts a logo only if it is a small, well-formed SVG that can
// neither run code nor load anything: no scripts, no foreignObject, no
// event handlers, no external links or url()s, no DTD (entity tricks). The
// logo route also sends a CSP that forbids all of it; this is the first
// wall, and it keeps a template's author honest.
func CheckSVG(data []byte) error {
	switch {
	case len(data) == 0:
		return errors.New("missing")
	case len(data) > MaxLogoBytes:
		return fmt.Errorf("%d bytes: at most %d", len(data), MaxLogoBytes)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = true
	depth := 0
	inStyle, rootDone := false, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("not well-formed XML: %w", err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(x.Name.Local)
			if rootDone {
				return errors.New("only one root element is allowed")
			}
			if depth == 0 && name != "svg" {
				return fmt.Errorf("the root element must be <svg>, not <%s>", x.Name.Local)
			}
			if depth == 0 && x.Name.Space != "" && x.Name.Space != "http://www.w3.org/2000/svg" {
				return fmt.Errorf("unexpected namespace %q", x.Name.Space)
			}
			if forbiddenElements[name] {
				return fmt.Errorf("<%s> is not allowed", x.Name.Local)
			}
			for _, a := range x.Attr {
				if err := checkSVGAttr(a); err != nil {
					return fmt.Errorf("<%s %s>: %w", x.Name.Local, a.Name.Local, err)
				}
			}
			inStyle = name == "style"
			depth++
		case xml.EndElement:
			depth--
			inStyle = false
			if depth == 0 {
				rootDone = true
			}
		case xml.CharData:
			if inStyle {
				if err := checkCSS(string(x)); err != nil {
					return fmt.Errorf("<style>: %w", err)
				}
			}
		case xml.Directive:
			return errors.New("DTDs and entities (<!...>) are not allowed")
		case xml.ProcInst:
			if x.Target != "xml" {
				return fmt.Errorf("processing instruction <?%s?> is not allowed", x.Target)
			}
		}
	}
	if depth != 0 || !rootDone {
		return errors.New("no complete <svg> element")
	}
	return nil
}

func checkSVGAttr(a xml.Attr) error {
	name := strings.ToLower(a.Name.Local)
	val := strings.TrimSpace(a.Value)
	switch {
	case strings.HasPrefix(name, "on"):
		return errors.New("event handlers are not allowed")
	case name == "href" || name == "src":
		if !strings.HasPrefix(val, "#") {
			return errors.New("only local references (#id) are allowed")
		}
	case name == "style":
		return checkCSS(val)
	}
	return checkURLs(val)
}

func checkCSS(css string) error {
	if strings.Contains(strings.ToLower(css), "@import") {
		return errors.New("@import is not allowed")
	}
	if strings.Contains(strings.ToLower(css), "expression(") {
		return errors.New("expression() is not allowed")
	}
	return checkURLs(css)
}

func checkURLs(s string) error {
	for _, m := range urlRE.FindAllStringSubmatch(s, -1) {
		if !strings.HasPrefix(m[1], "#") {
			return fmt.Errorf("external url(%s) is not allowed", m[1])
		}
	}
	return nil
}
