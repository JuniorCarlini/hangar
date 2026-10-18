package deps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultOSV is the public OSV.dev API.
const DefaultOSV = "https://api.osv.dev"

const (
	osvBatchMax   = 1000 // queries per /v1/querybatch request (API limit)
	osvCacheTTL   = 6 * time.Hour
	osvParallel   = 6
	osvBatchBytes = 32 << 20
	osvVulnBytes  = 4 << 20
)

// OSV queries OSV.dev. Only package names and versions leave the server:
// never code, secrets or project names (docs/14). Every answer is untrusted
// data: ids are validated and text is only ever shown escaped.
type OSV struct {
	base string
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	queries map[string]cached[[]string] // eco|name|version → advisory ids
	vulns   map[string]cached[osvVuln]
}

type cached[T any] struct {
	v  T
	at time.Time
}

// NewOSV returns a client for base (DefaultOSV when empty).
func NewOSV(base string, hc *http.Client) *OSV {
	if base == "" {
		base = DefaultOSV
	}
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	return &OSV{
		base: strings.TrimRight(base, "/"), http: hc, now: time.Now,
		queries: map[string]cached[[]string]{}, vulns: map[string]cached[osvVuln]{},
	}
}

// osvVuln is the part of an OSV record the monitor uses.
type osvVuln struct {
	ID       string   `json:"id"`
	Summary  string   `json:"summary"`
	Aliases  []string `json:"aliases"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		EcosystemSpecific specific `json:"ecosystem_specific"`
		DatabaseSpecific  specific `json:"database_specific"`
	} `json:"affected"`
	DatabaseSpecific specific `json:"database_specific"`
}

// specific is a free-form OSV object; only a string "severity" in it is read,
// anything else (other shapes, other types) is ignored.
type specific struct{ Severity string }

func (s *specific) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if json.Unmarshal(b, &m) != nil {
		return nil
	}
	_ = json.Unmarshal(m["severity"], &s.Severity)
	return nil
}

var advisoryIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{1,79}$`)

// Advisory is a vulnerability affecting one package version.
type Advisory struct {
	ID       string
	Aliases  []string
	Summary  string
	Severity string
	Fixed    string // smallest fixed version above the current one; "" = no fix yet
}

// URL is the advisory's public page.
func (a Advisory) URL() string { return AdvisoryURL(a.ID) }

// AdvisoryURL is an advisory's page on osv.dev.
func AdvisoryURL(id string) string { return "https://osv.dev/vulnerability/" + url.PathEscape(id) }

func queryKey(p Package) string { return p.Ecosystem + "|" + p.Name + "|" + p.Version }

// Check returns the advisories of each package (same order as pkgs).
func (o *OSV) Check(ctx context.Context, pkgs []Package) ([][]Advisory, error) {
	ids, err := o.queryBatch(ctx, pkgs)
	if err != nil {
		return nil, err
	}
	need := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			need[id] = true
		}
	}
	recs, err := o.fetchVulns(ctx, need)
	if err != nil {
		return nil, err
	}
	out := make([][]Advisory, len(pkgs))
	for i, p := range pkgs {
		for _, id := range ids[i] {
			v, ok := recs[id]
			if !ok {
				continue
			}
			out[i] = append(out[i], Advisory{
				ID: v.ID, Aliases: cleanAliases(v.Aliases), Summary: clip(v.Summary, 300),
				Severity: severityOf(v), Fixed: fixedVersion(v, p),
			})
		}
	}
	return out, nil
}

func cleanAliases(in []string) []string {
	var out []string
	for _, a := range in {
		if advisoryIDRE.MatchString(a) && len(out) < 8 {
			out = append(out, a)
		}
	}
	return out
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	cut := s[:n]
	for len(cut) > 0 && cut[len(cut)-1]&0xC0 == 0x80 { // do not split a UTF-8 rune
		cut = cut[:len(cut)-1]
	}
	if len(cut) > 0 && cut[len(cut)-1] >= 0xC0 {
		cut = cut[:len(cut)-1]
	}
	return cut + "…"
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}

func (o *OSV) queryBatch(ctx context.Context, pkgs []Package) ([][]string, error) {
	out := make([][]string, len(pkgs))
	now := o.now()
	var todo []int
	o.mu.Lock()
	for i, p := range pkgs {
		if c, ok := o.queries[queryKey(p)]; ok && now.Sub(c.at) < osvCacheTTL {
			out[i] = c.v
			continue
		}
		todo = append(todo, i)
	}
	o.mu.Unlock()

	for start := 0; start < len(todo); start += osvBatchMax {
		chunk := todo[start:min(start+osvBatchMax, len(todo))]
		body := struct {
			Queries []osvQuery `json:"queries"`
		}{}
		for _, i := range chunk {
			var q osvQuery
			q.Package.Name, q.Package.Ecosystem, q.Version = pkgs[i].Name, pkgs[i].Ecosystem, pkgs[i].Version
			body.Queries = append(body.Queries, q)
		}
		var res struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		if err := o.post(ctx, "/v1/querybatch", body, &res); err != nil {
			return nil, err
		}
		if len(res.Results) != len(chunk) {
			return nil, fmt.Errorf("osv querybatch: %d results for %d queries", len(res.Results), len(chunk))
		}
		o.mu.Lock()
		for k, i := range chunk {
			var ids []string
			for _, v := range res.Results[k].Vulns {
				if advisoryIDRE.MatchString(v.ID) {
					ids = append(ids, v.ID)
				}
			}
			out[i] = ids
			o.queries[queryKey(pkgs[i])] = cached[[]string]{v: ids, at: now}
		}
		o.mu.Unlock()
	}
	return out, nil
}

func (o *OSV) fetchVulns(ctx context.Context, ids map[string]bool) (map[string]osvVuln, error) {
	out := map[string]osvVuln{}
	now := o.now()
	var todo []string
	o.mu.Lock()
	for id := range ids {
		if c, ok := o.vulns[id]; ok && now.Sub(c.at) < osvCacheTTL {
			out[id] = c.v
			continue
		}
		todo = append(todo, id)
	}
	o.mu.Unlock()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
		sem      = make(chan struct{}, osvParallel)
	)
	for _, id := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var v osvVuln
			err := o.get(ctx, "/v1/vulns/"+url.PathEscape(id), &v)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if v.ID != id {
				return // not what was asked for: ignore it
			}
			out[id] = v
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	o.mu.Lock()
	for _, id := range todo {
		if v, ok := out[id]; ok {
			o.vulns[id] = cached[osvVuln]{v: v, at: now}
		}
	}
	o.pruneLocked(now)
	o.mu.Unlock()
	return out, nil
}

func (o *OSV) pruneLocked(now time.Time) {
	for k, c := range o.queries {
		if now.Sub(c.at) >= osvCacheTTL {
			delete(o.queries, k)
		}
	}
	for k, c := range o.vulns {
		if now.Sub(c.at) >= osvCacheTTL {
			delete(o.vulns, k)
		}
	}
}

func (o *OSV) post(ctx context.Context, path string, body, into any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return o.do(req, osvBatchBytes, into)
}

func (o *OSV) get(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+path, nil)
	if err != nil {
		return err
	}
	return o.do(req, osvVulnBytes, into)
}

func (o *OSV) do(req *http.Request, limit int64, into any) error {
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "hangar-deps-monitor")
	res, err := o.http.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		return fmt.Errorf("osv %s: status %d", req.URL.Path, res.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, limit))
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("osv %s: %w", req.URL.Path, err)
	}
	return nil
}

// fixedVersion is the smallest version that fixes v for p and is newer than
// p's version, from the record's ranges for that package.
func fixedVersion(v osvVuln, p Package) string {
	best := ""
	for _, a := range v.Affected {
		if !samePackage(a.Package.Ecosystem, a.Package.Name, p) {
			continue
		}
		for _, r := range a.Ranges {
			if r.Type == "GIT" {
				continue
			}
			for _, e := range r.Events {
				if e.Fixed == "" || len(e.Fixed) > 100 || CompareVersions(e.Fixed, p.Version) <= 0 {
					continue
				}
				if best == "" || CompareVersions(e.Fixed, best) < 0 {
					best = e.Fixed
				}
			}
		}
	}
	return best
}

// samePackage tells whether a record's affected entry is about p. A
// distribution release (Debian:13, Alpine:v3.23) must match exactly: the
// same record lists each release with its own fix, and a fix that only
// exists in Debian 14 does nothing for a Debian 13 image.
func samePackage(eco, name string, p Package) bool {
	if strings.Contains(p.Ecosystem, ":") {
		if !strings.EqualFold(eco, p.Ecosystem) {
			return false
		}
	} else {
		base := func(e string) string { b, _, _ := strings.Cut(e, ":"); return strings.ToLower(b) }
		if base(eco) != base(p.Ecosystem) {
			return false
		}
	}
	return normalizeName(p.Ecosystem, name) == normalizeName(p.Ecosystem, p.Name)
}

var pypiSep = regexp.MustCompile(`[-_.]+`)

// normalizeName applies the ecosystem's name rules (PEP 503 for PyPI).
func normalizeName(eco, name string) string {
	switch eco {
	case "PyPI":
		return pypiSep.ReplaceAllString(strings.ToLower(name), "-")
	case "Packagist":
		return strings.ToLower(name)
	}
	return name
}
