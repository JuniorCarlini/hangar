package gitsrc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// GitHub webhook headers.
const (
	HeaderSignature = "X-Hub-Signature-256"
	HeaderEvent     = "X-GitHub-Event"
	HeaderDelivery  = "X-GitHub-Delivery"
)

// deliveryRE matches GitHub's delivery GUIDs (and keeps junk out of the
// database).
var deliveryRE = regexp.MustCompile(`^[A-Za-z0-9-]{8,64}$`)

// ValidDelivery reports whether a delivery id looks like one.
func ValidDelivery(id string) bool { return deliveryRE.MatchString(id) }

// VerifySignature checks GitHub's "sha256=<hex HMAC of the body>" in
// constant time.
func VerifySignature(secret, body []byte, header string) bool {
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	if !ok || len(secret) == 0 {
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}

// Sign computes the header value GitHub would send (tests and the "test
// delivery" in the UI use it).
func Sign(secret, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Push is the part of a GitHub push event the panel uses.
type Push struct {
	Ref      string // refs/heads/main
	After    string // commit SHA the branch now points to
	Deleted  bool
	PushedAt time.Time
	Repo     []string // the repository's URLs (clone, html)
}

// Branch is the pushed branch, or "" for a tag.
func (p Push) Branch() string {
	b, ok := strings.CutPrefix(p.Ref, "refs/heads/")
	if !ok {
		return ""
	}
	return b
}

// ParsePush reads a push event body. pushed_at is a Unix timestamp in push
// events; it is inside the signed body, so it dates the delivery.
func ParsePush(body []byte) (Push, error) {
	var raw struct {
		Ref        string `json:"ref"`
		After      string `json:"after"`
		Deleted    bool   `json:"deleted"`
		Repository struct {
			PushedAt json.RawMessage `json:"pushed_at"`
			CloneURL string          `json:"clone_url"`
			HTMLURL  string          `json:"html_url"`
		} `json:"repository"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Push{}, err
	}
	if raw.Ref == "" {
		return Push{}, errors.New("push without ref")
	}
	p := Push{Ref: raw.Ref, After: raw.After, Deleted: raw.Deleted}
	for _, u := range []string{raw.Repository.CloneURL, raw.Repository.HTMLURL} {
		if u != "" {
			p.Repo = append(p.Repo, u)
		}
	}
	if ts := strings.Trim(string(raw.Repository.PushedAt), `"`); ts != "" && ts != "null" {
		if n, err := strconv.ParseInt(ts, 10, 64); err == nil {
			p.PushedAt = time.Unix(n, 0)
		} else if t, err := time.Parse(time.RFC3339, ts); err == nil {
			p.PushedAt = t
		}
	}
	return p, nil
}
