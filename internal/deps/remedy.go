package deps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// What fixes a vulnerability (Finding.Remedy), decided by each scan.
const (
	// RemedyDeploy: the registry has a newer build of the same tag that
	// carries the fix; a deploy pulls it.
	RemedyDeploy = "deploy"
	// RemedyTag: a newer tag of the same major carries it (RemedyTag names
	// it); the service has to switch to it.
	RemedyTag = "tag"
	// RemedyMajor: only a newer major carries it. Shown as a hint, never
	// offered as a button (it may break the app or convert a database).
	RemedyMajor = "major"
	// RemedyCode: a package of the user's own app (built from Git).
	RemedyCode = "code"
	// RemedyEdge: the Caddy edge, whose image comes with Hangar itself.
	RemedyEdge = "edge"
	// RemedyWaitImage: fixed upstream, but no image carries it yet.
	RemedyWaitImage = "wait_image"
	// RemedyNoFix: no fixed version exists.
	RemedyNoFix = "no_fix"
	// RemedyUnchecked: the images could not be checked (registry down,
	// no Docker, image too big); nothing is claimed.
	RemedyUnchecked = "unchecked"
)

// ImageProber reads the packages of an image no container runs, by
// reference (name@digest). *ImageScanner implements it.
type ImageProber interface {
	ProbeImage(ctx context.Context, ref string) ([]Package, error)
}

const (
	// probeRetry is how long a failed probe is remembered before the same
	// digest is tried again.
	probeRetry = 24 * time.Hour
	// probeKeep drops probes of digests not looked at for this long.
	probeKeep = 60 * 24 * time.Hour
)

// classify decides each vulnerability's remedy for one target. Images are
// only pulled when something could change the answer: a vulnerability with
// a fixed version, in an image the panel did not build. The order is the
// cheapest fix first: a deploy (same tag, newer build), then a newer tag of
// the same major, then a newer major (a hint only; never for databases,
// whose data a new major may convert).
func (m *Monitor) classify(ctx context.Context, t target, tags []TagUpdate, obs []observation) {
	var pending []int
	for i := range obs {
		o := &obs[i]
		if o.kind != KindVuln {
			continue
		}
		switch {
		case o.advisory.Fixed == "":
			o.remedy = RemedyNoFix
		case t.serviceID == "":
			o.remedy = RemedyEdge
		case t.git:
			o.remedy = RemedyCode
		default:
			o.remedy = RemedyUnchecked
			pending = append(pending, i)
		}
	}
	if len(pending) == 0 || m.o.Prober == nil {
		return
	}
	ref, ok := ParseImage(t.image)
	if !ok || ref.Tag == "" {
		return
	}
	log := m.o.Log.With("target", t.key(), "image", t.image)

	// A newer build of the same tag.
	remote, err := m.o.Registry.Digest(ctx, ref)
	if err != nil {
		log.Warn("dependency remedy: registry digest", "error", err)
		return
	}
	if remote != runningDigest(t.imageRef) {
		pkgs, err := m.probe(ctx, ref, remote)
		if err != nil {
			log.Warn("dependency remedy: newer build", "error", err)
			return
		}
		pending = settle(obs, pending, pkgs, RemedyDeploy, "")
	}
	// A newer tag: the same major first, a new major only as a hint.
	for _, u := range tags {
		if len(pending) == 0 {
			break
		}
		remedy := RemedyTag
		if u.Kind == KindMajor {
			if t.stateful {
				continue
			}
			remedy = RemedyMajor
		}
		cand := ref
		cand.Tag = u.Latest
		d, err := m.o.Registry.Digest(ctx, cand)
		if err != nil {
			log.Warn("dependency remedy: registry digest", "tag", u.Latest, "error", err)
			return
		}
		pkgs, err := m.probe(ctx, cand, d)
		if err != nil {
			log.Warn("dependency remedy: newer tag", "tag", u.Latest, "error", err)
			return
		}
		pending = settle(obs, pending, pkgs, remedy, u.Latest)
	}
	for _, i := range pending {
		obs[i].remedy = RemedyWaitImage
	}
}

// runningDigest is the digest in a pinned reference (name@sha256:…). A
// bare image ID is returned as is: in Docker's containerd image store the
// ID of a pulled image is its registry digest (in the classic store it is
// not, and the comparison just misses: the newer-build check then reads
// the registry's image, which costs a scan but claims nothing wrong).
func runningDigest(imageRef string) string {
	if _, d, ok := strings.Cut(imageRef, "@"); ok {
		return d
	}
	return imageRef
}

// settle marks the pending vulnerabilities pkgs fixes and returns the
// others.
func settle(obs []observation, pending []int, pkgs []Package, remedy, tag string) []int {
	var left []int
	for _, i := range pending {
		if FixedIn(pkgs, obs[i].pkg, obs[i].advisory.Fixed) {
			obs[i].remedy, obs[i].remedyTag = remedy, tag
		} else {
			left = append(left, i)
		}
	}
	return left
}

// FixedIn reports whether an image with packages pkgs no longer has p's
// vulnerability: every copy of the package is at fixed or newer, or the
// package is gone. An empty inventory proves nothing.
func FixedIn(pkgs []Package, p Package, fixed string) bool {
	if len(pkgs) == 0 || fixed == "" {
		return false
	}
	base := func(e string) string { b, _, _ := strings.Cut(e, ":"); return strings.ToLower(b) }
	name := normalizeName(p.Ecosystem, p.Name)
	for _, q := range pkgs {
		if base(q.Ecosystem) != base(p.Ecosystem) || normalizeName(q.Ecosystem, q.Name) != name {
			continue
		}
		if CompareVersions(q.Version, fixed) < 0 {
			return false
		}
	}
	return true
}

// probedPackage is how a probe's packages are kept (no source path: only
// what FixedIn compares).
type probedPackage [3]string

// probe reads an image by digest through the cache: a digest never
// changes, so it is pulled and read at most once; a failure is tried again
// after probeRetry.
func (m *Monitor) probe(ctx context.Context, ref ImageRef, digest string) ([]Package, error) {
	now := m.now()
	row, err := m.q.GetImageProbe(ctx, digest)
	switch {
	case err == nil && row.Error == "":
		var raw []probedPackage
		if err := json.Unmarshal([]byte(row.PackagesJson), &raw); err != nil {
			return nil, err
		}
		out := make([]Package, 0, len(raw))
		for _, r := range raw {
			out = append(out, Package{Ecosystem: r[0], Name: r[1], Version: r[2]})
		}
		return out, nil
	case err == nil && now.Sub(time.Unix(row.ProbedAt, 0)) < probeRetry:
		return nil, errors.New(row.Error)
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	pkgs, perr := m.o.Prober.ProbeImage(ctx, ref.Host+"/"+ref.Repo+"@"+digest)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	p := dbq.UpsertImageProbeParams{Digest: digest, PackagesJson: "[]", ProbedAt: now.Unix()}
	if perr != nil {
		p.Error = clip(perr.Error(), 500)
	} else {
		raw := make([]probedPackage, 0, len(pkgs))
		for _, k := range pkgs {
			raw = append(raw, probedPackage{k.Ecosystem, k.Name, k.Version})
		}
		b, _ := json.Marshal(raw)
		p.PackagesJson = string(b)
	}
	if err := m.q.UpsertImageProbe(ctx, p); err != nil {
		m.o.Log.Warn("store image probe", "error", err)
	}
	_ = m.q.DeleteOldImageProbes(ctx, now.Add(-probeKeep).Unix())
	return pkgs, perr
}
