package deps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ImageRef is a parsed image reference.
type ImageRef struct {
	Host string // registry host: docker.io, ghcr.io, quay.io…
	Repo string // library/postgres, org/app
	Tag  string // "" when pinned only by digest
}

// Name is the image without the tag, as people write it (postgres,
// ghcr.io/org/app).
func (r ImageRef) Name() string {
	if r.Host == "docker.io" {
		return strings.TrimPrefix(r.Repo, "library/")
	}
	return r.Host + "/" + r.Repo
}

// ParseImage splits "postgres:18.0", "ghcr.io/org/app:1.2@sha256:…".
func ParseImage(image string) (ImageRef, bool) {
	image = strings.TrimSpace(image)
	if i := strings.IndexByte(image, '@'); i >= 0 {
		image = image[:i]
	}
	if image == "" {
		return ImageRef{}, false
	}
	var r ImageRef
	rest := image
	if first, after, ok := strings.Cut(image, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.Host, rest = first, after
	} else {
		r.Host = "docker.io"
	}
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		r.Repo, r.Tag = rest[:i], rest[i+1:]
	} else {
		r.Repo, r.Tag = rest, "latest"
	}
	if r.Host == "docker.io" && !strings.Contains(r.Repo, "/") {
		r.Repo = "library/" + r.Repo
	}
	if r.Repo == "" || !repoRE.MatchString(r.Repo) {
		return ImageRef{}, false
	}
	return r, true
}

var (
	repoRE = regexp.MustCompile(`^[a-z0-9]+(?:[._/-][a-z0-9]+)*$`)
	tagRE  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// TagUpdate is a newer tag of the same flavor ("18.0" → "18.1"; "1.29-alpine"
// → "1.30-alpine").
type TagUpdate struct {
	Kind    string // patch, minor or major
	Current string
	Latest  string
}

// Registry lists image tags through the registry HTTP API (anonymous pull
// token, like docker pull of a public image).
type Registry struct {
	http *http.Client
	// Endpoint maps a registry host to its API base URL. Tests point it at
	// an httptest server; by default docker.io is registry-1.docker.io and
	// everything else is https://<host>.
	Endpoint func(host string) string
	now      func() time.Time

	mu      sync.Mutex
	cache   map[string]cached[[]string]
	digests map[string]cached[string]
}

// NewRegistry returns a registry client.
func NewRegistry(hc *http.Client) *Registry {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Registry{http: hc, Endpoint: defaultEndpoint, now: time.Now, cache: map[string]cached[[]string]{}, digests: map[string]cached[string]{}}
}

func defaultEndpoint(host string) string {
	if host == "docker.io" {
		return "https://registry-1.docker.io"
	}
	return "https://" + host
}

const (
	tagPages     = 30
	tagPageBytes = 4 << 20
)

// Updates returns the newer tags of image: the newest within the same major
// (patch or minor) and, separately, the newest major. Tags that are not
// versions ("latest", "alpine") have no updates.
func (g *Registry) Updates(ctx context.Context, image string) ([]TagUpdate, error) {
	ref, ok := ParseImage(image)
	if !ok {
		return nil, nil
	}
	cur, suffix, ok := numericParts(ref.Tag)
	if !ok {
		return nil, nil
	}
	tags, err := g.tags(ctx, ref)
	if err != nil {
		return nil, err
	}
	return newerTags(ref.Tag, cur, suffix, tags), nil
}

// newerTags picks, among tags with the same suffix and the same precision
// ("18" only moves to "19"; "18.1" to "18.2" or "19.0"), the newest of the
// same major and the newest overall.
func newerTags(current string, cur []int, suffix string, tags []string) []TagUpdate {
	var bestSame, bestMajor []int
	var bestSameTag, bestMajorTag string
	for _, t := range tags {
		parts, rest, ok := numericParts(t)
		if !ok || rest != suffix || len(parts) != len(cur) || strings.HasPrefix(t, "v") != strings.HasPrefix(current, "v") {
			continue
		}
		if cmpParts(parts, cur) <= 0 {
			continue
		}
		if parts[0] == cur[0] {
			if bestSame == nil || cmpParts(parts, bestSame) > 0 {
				bestSame, bestSameTag = parts, t
			}
		} else if bestMajor == nil || cmpParts(parts, bestMajor) > 0 {
			bestMajor, bestMajorTag = parts, t
		}
	}
	var out []TagUpdate
	if bestSame != nil {
		kind := "minor"
		if len(cur) >= 3 && bestSame[1] == cur[1] {
			kind = "patch"
		}
		out = append(out, TagUpdate{Kind: kind, Current: current, Latest: bestSameTag})
	}
	if bestMajor != nil {
		out = append(out, TagUpdate{Kind: "major", Current: current, Latest: bestMajorTag})
	}
	return out
}

func cmpParts(a, b []int) int {
	for i := range min(len(a), len(b)) {
		if c := cmpInt(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmpInt(len(a), len(b))
}

func (g *Registry) tags(ctx context.Context, ref ImageRef) ([]string, error) {
	key := ref.Host + "/" + ref.Repo
	now := g.now()
	g.mu.Lock()
	if c, ok := g.cache[key]; ok && now.Sub(c.at) < osvCacheTTL {
		g.mu.Unlock()
		return c.v, nil
	}
	g.mu.Unlock()

	base := strings.TrimRight(g.Endpoint(ref.Host), "/")
	next := base + "/v2/" + ref.Repo + "/tags/list?n=1000"
	var (
		all   []string
		token string
	)
	for page := 0; next != "" && page < tagPages; page++ {
		var (
			list struct {
				Tags []string `json:"tags"`
			}
			link string
			err  error
		)
		link, token, err = g.getTags(ctx, base, next, token, &list)
		if err != nil {
			return nil, err
		}
		for _, t := range list.Tags {
			if tagRE.MatchString(t) {
				all = append(all, t)
			}
		}
		next = nextPage(base, link)
	}
	g.mu.Lock()
	g.cache[key] = cached[[]string]{v: all, at: now}
	g.mu.Unlock()
	return all, nil
}

// getTags fetches one page; on a 401 it gets an anonymous token from the
// realm the registry names and tries once more.
func (g *Registry) getTags(ctx context.Context, base, u, token string, into any) (link, tok string, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", "", err
		}
		req.Header.Set("Accept", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := g.http.Do(req)
		if err != nil {
			return "", "", fmt.Errorf("registry: %w", err)
		}
		if res.StatusCode == http.StatusUnauthorized && token == "" {
			challenge := res.Header.Get("WWW-Authenticate")
			_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
			_ = res.Body.Close()
			token, err = g.anonymousToken(ctx, base, challenge)
			if err != nil {
				return "", "", err
			}
			continue
		}
		func() {
			defer func() { _ = res.Body.Close() }()
			if res.StatusCode != http.StatusOK {
				err = fmt.Errorf("registry tags: status %d", res.StatusCode)
				return
			}
			err = json.NewDecoder(io.LimitReader(res.Body, tagPageBytes)).Decode(into)
		}()
		return res.Header.Get("Link"), token, err
	}
	return "", "", errors.New("registry: not authorized")
}

var challengeRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

func (g *Registry) anonymousToken(ctx context.Context, base, challenge string) (string, error) {
	scheme, params, ok := strings.Cut(challenge, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", errors.New("registry: unsupported authentication")
	}
	vals := map[string]string{}
	for _, m := range challengeRE.FindAllStringSubmatch(params, -1) {
		vals[strings.ToLower(m[1])] = m[2]
	}
	realm, err := url.Parse(vals["realm"])
	if err != nil || realm.Host == "" {
		return "", errors.New("registry: invalid token realm")
	}
	// The realm comes from the registry's answer: only follow it over HTTPS
	// (plain HTTP only when the registry itself is plain HTTP, as in tests).
	plainOK := realm.Scheme == "http" && strings.HasPrefix(base, "http://")
	if realm.Scheme != "https" && !plainOK {
		return "", errors.New("registry: token realm is not HTTPS")
	}
	q := realm.Query()
	if s := vals["service"]; s != "" {
		q.Set("service", s)
	}
	if s := vals["scope"]; s != "" {
		q.Set("scope", s)
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	res, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("registry token: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token: status %d", res.StatusCode)
	}
	var tok struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&tok); err != nil {
		return "", fmt.Errorf("registry token: %w", err)
	}
	if tok.Token == "" {
		tok.Token = tok.AccessToken
	}
	if tok.Token == "" {
		return "", errors.New("registry token: empty")
	}
	return tok.Token, nil
}

// nextPage follows a `Link: </v2/…?last=x&n=1000>; rel="next"` header, only
// on the same registry.
func nextPage(base, link string) string {
	if link == "" || !strings.Contains(link, `rel="next"`) {
		return ""
	}
	start, end := strings.IndexByte(link, '<'), strings.IndexByte(link, '>')
	if start < 0 || end <= start {
		return ""
	}
	target := link[start+1 : end]
	if !strings.HasPrefix(target, "/v2/") {
		return ""
	}
	return base + target
}

// manifestAccept asks for the multi-platform index first (its digest is
// what `docker pull` records in the image's RepoDigests), then a single
// platform's manifest.
var manifestAccept = strings.Join([]string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}, ", ")

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// digestTTL keeps a tag's digest for the rest of a scan, not longer: a tag
// moves when its image is rebuilt.
const digestTTL = 30 * time.Minute

// Digest is the digest the registry serves for the reference's tag right
// now (a HEAD request: it does not count as a pull).
func (g *Registry) Digest(ctx context.Context, ref ImageRef) (string, error) {
	if ref.Tag == "" {
		return "", errors.New("registry: no tag")
	}
	key := ref.Host + "/" + ref.Repo + ":" + ref.Tag
	now := g.now()
	g.mu.Lock()
	if c, ok := g.digests[key]; ok && now.Sub(c.at) < digestTTL {
		g.mu.Unlock()
		return c.v, nil
	}
	g.mu.Unlock()

	base := strings.TrimRight(g.Endpoint(ref.Host), "/")
	u := base + "/v2/" + ref.Repo + "/manifests/" + url.PathEscape(ref.Tag)
	token := ""
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", manifestAccept)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := g.http.Do(req)
		if err != nil {
			return "", fmt.Errorf("registry: %w", err)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		_ = res.Body.Close()
		if res.StatusCode == http.StatusUnauthorized && token == "" {
			if token, err = g.anonymousToken(ctx, base, res.Header.Get("WWW-Authenticate")); err != nil {
				return "", err
			}
			continue
		}
		if res.StatusCode != http.StatusOK {
			return "", fmt.Errorf("registry manifest: status %d", res.StatusCode)
		}
		d := res.Header.Get("Docker-Content-Digest")
		if !digestRE.MatchString(d) {
			return "", errors.New("registry manifest: no digest")
		}
		g.mu.Lock()
		g.digests[key] = cached[string]{v: d, at: now}
		g.mu.Unlock()
		return d, nil
	}
	return "", errors.New("registry: not authorized")
}
