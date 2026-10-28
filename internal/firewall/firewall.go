// Package firewall restricts published ports to chosen IPs (docs/05).
//
// Docker publishes ports through its own iptables rules and ignores UFW, so
// "only these IPs" must be enforced in the DOCKER-USER chain. The panel runs
// unprivileged: it only writes the desired state to a file. A root oneshot
// unit (hangar-firewall) reads it, validates it again and applies it.
package firewall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Chain is Hangar's chain, jumped to from DOCKER-USER.
const Chain = "HANGAR-PORTS"

// EdgeChain, jumped to first from INPUT, lets Caddy reach the panel's
// listeners on the edge gateway. Some provider images (Oracle's, for one)
// reject every new connection to the host but SSH, which would cut Caddy
// off from the panel and the certificate check.
const EdgeChain = "HANGAR-EDGE-IN"

const (
	desiredFile = "desired.json"
	appliedFile = "applied.json"
	maxRules    = 512
	maxAllow    = 64
)

// Rule lets only Allow reach a published host port.
type Rule struct {
	Port     int            `json:"port"`
	Protocol string         `json:"protocol"`
	Allow    []netip.Prefix `json:"allow"`
}

// EdgeAccess lets Caddy (and only Caddy) reach the panel's listeners on
// the edge gateway.
type EdgeAccess struct {
	Caddy   netip.Addr `json:"caddy"`
	Gateway netip.Addr `json:"gateway"`
	Ports   []int      `json:"ports"`
}

// State is the desired file.
type State struct {
	Version int         `json:"version"`
	Rules   []Rule      `json:"rules"`
	Edge    *EdgeAccess `json:"edge,omitempty"`
}

// Applied is what the root unit reports back.
type Applied struct {
	Hash  string    `json:"hash"`
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// Validate checks everything that becomes an iptables argument.
func (s State) Validate() error {
	if s.Version != 1 {
		return fmt.Errorf("unknown version %d", s.Version)
	}
	if len(s.Rules) > maxRules {
		return errors.New("too many rules")
	}
	if e := s.Edge; e != nil {
		if !e.Caddy.Is4() || !e.Caddy.IsPrivate() || !e.Gateway.Is4() || !e.Gateway.IsPrivate() {
			return errors.New("edge access: private IPv4 addresses only")
		}
		if len(e.Ports) == 0 || len(e.Ports) > 4 {
			return errors.New("edge access: between 1 and 4 ports")
		}
		for _, p := range e.Ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("edge access: invalid port %d", p)
			}
		}
	}
	for _, r := range s.Rules {
		if r.Port < 1 || r.Port > 65535 || (r.Protocol != "tcp" && r.Protocol != "udp") {
			return fmt.Errorf("invalid rule %d/%s", r.Port, r.Protocol)
		}
		if len(r.Allow) == 0 || len(r.Allow) > maxAllow {
			return fmt.Errorf("rule %d/%s: between 1 and %d addresses", r.Port, r.Protocol, maxAllow)
		}
		for _, p := range r.Allow {
			if !p.IsValid() {
				return fmt.Errorf("rule %d/%s: invalid address", r.Port, r.Protocol)
			}
		}
	}
	return nil
}

func (s State) hash() string {
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

// Writer writes the desired state (the panel side).
type Writer struct{ Dir string }

// current reads the desired state written before (empty when none).
func (w Writer) current() State {
	var st State
	if raw, err := os.ReadFile(filepath.Join(w.Dir, desiredFile)); err == nil {
		_ = json.Unmarshal(raw, &st)
	}
	return st
}

// Write replaces the port rules, keeping the edge access, atomically; the
// path unit notices it.
func (w Writer) Write(rules []Rule) error {
	return w.write(rules, w.current().Edge)
}

// SetEdge replaces the edge access (nil removes it), keeping the port rules.
func (w Writer) SetEdge(e *EdgeAccess) error {
	return w.write(w.current().Rules, e)
}

func (w Writer) write(rules []Rule, edge *EdgeAccess) error {
	slices.SortFunc(rules, func(a, b Rule) int {
		if a.Port != b.Port {
			return a.Port - b.Port
		}
		return strings.Compare(a.Protocol, b.Protocol)
	})
	st := State{Version: 1, Rules: rules, Edge: edge}
	if st.Rules == nil {
		st.Rules = []Rule{}
	}
	if err := st.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(w.Dir, 0o755); err != nil { //nolint:gosec // root must read it; it holds no secret
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp, err := os.CreateTemp(w.Dir, ".desired-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(w.Dir, desiredFile))
}

// Status reports whether the root unit applied the current desired state.
func (w Writer) Status() (pending bool, applied Applied) {
	raw, err := os.ReadFile(filepath.Join(w.Dir, desiredFile))
	if err != nil {
		return false, Applied{}
	}
	var st State
	if json.Unmarshal(raw, &st) != nil {
		return true, Applied{}
	}
	if b, err := os.ReadFile(filepath.Join(w.Dir, appliedFile)); err == nil {
		_ = json.Unmarshal(b, &applied)
	}
	return applied.Hash != st.hash() || applied.Error != "", applied
}

// Restore builds the iptables-restore input for one family (4 or 6). Only
// connections that went through a published port (DNAT) are matched, so
// traffic between containers is never affected; loopback is always allowed.
func Restore(st State, family int) string {
	var b strings.Builder
	b.WriteString("*filter\n:" + Chain + " - [0:0]\n:" + EdgeChain + " - [0:0]\n")
	if e := st.Edge; e != nil && family == 4 {
		ports := make([]string, len(e.Ports))
		for i, p := range e.Ports {
			ports[i] = strconv.Itoa(p)
		}
		fmt.Fprintf(&b, "-A %s -s %s/32 -d %s/32 -p tcp -m multiport --dports %s -j ACCEPT\n",
			EdgeChain, e.Caddy, e.Gateway, strings.Join(ports, ","))
	}
	loop := netip.MustParsePrefix("127.0.0.0/8")
	if family == 6 {
		loop = netip.MustParsePrefix("::1/128")
	}
	for _, r := range st.Rules {
		match := fmt.Sprintf("-p %s -m conntrack --ctstate DNAT --ctorigdstport %d --ctdir ORIGINAL", r.Protocol, r.Port)
		for _, p := range append([]netip.Prefix{loop}, r.Allow...) {
			if (family == 4) != p.Addr().Is4() {
				continue
			}
			fmt.Fprintf(&b, "-A %s %s -s %s -j RETURN\n", Chain, match, p.Masked())
		}
		fmt.Fprintf(&b, "-A %s %s -j DROP\n", Chain, match)
	}
	b.WriteString("COMMIT\n")
	return b.String()
}

// Apply reads the desired state in dir and loads it (root side). The result,
// success or error, is written to applied.json for the panel.
func Apply(ctx context.Context, dir string) error {
	raw, err := os.ReadFile(filepath.Join(dir, desiredFile)) //nolint:gosec // fixed path under the data dir
	if errors.Is(err, os.ErrNotExist) {
		raw = []byte(`{"version":1,"rules":[]}`)
	} else if err != nil {
		return err
	}
	var st State
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	err = dec.Decode(&st)
	if err == nil {
		err = st.Validate()
	}
	if err == nil {
		for _, fam := range []struct {
			n   int
			bin string
		}{{4, "iptables"}, {6, "ip6tables"}} {
			if _, lerr := exec.LookPath(fam.bin + "-restore"); lerr != nil && fam.n == 6 {
				continue // no IPv6 tooling: nothing is published over IPv6 either
			}
			if err = applyFamily(ctx, fam.bin, Restore(st, fam.n)); err != nil {
				break
			}
		}
	}
	res := Applied{Hash: st.hash(), At: time.Now().UTC()}
	if err != nil {
		res.Error = err.Error()
	}
	b, _ := json.Marshal(res)
	if werr := writeStatus(filepath.Join(dir, appliedFile), b); werr != nil && err == nil {
		err = werr
	}
	return err
}

// writeStatus writes the result for the panel. Root runs this in a directory
// the hangar user owns, so it never writes by that name directly (a planted
// symlink would point root's write anywhere): a fresh temporary file is
// renamed over it, which replaces a link instead of following it.
func writeStatus(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".applied-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(0o644); err != nil { // status, read by the panel
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runCmd runs one fixed iptables binary; a test seam.
var runCmd = func(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...) //nolint:gosec // fixed binaries, validated arguments
	cmd.Stdin = strings.NewReader(stdin)
	return cmd.CombinedOutput()
}

// applyFamily is safe to re-run at any time (the timer does): the restore
// redeclares both chains, which recreates them when something deleted them
// and refills them when something flushed them; the jumps are only added
// when missing.
func applyFamily(ctx context.Context, bin, restore string) error {
	run := func(stdin string, args ...string) (string, error) {
		out, err := runCmd(ctx, stdin, args...)
		if err != nil {
			return "", fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, bytes.TrimSpace(out))
		}
		return string(out), nil
	}
	if _, err := run(restore, bin+"-restore", "--noflush"); err != nil {
		return err
	}
	if err := jumpFirst(run, bin, "INPUT", EdgeChain); err != nil {
		return err
	}
	// Docker creates DOCKER-USER; create it if Docker has not run yet.
	_, _ = run("", bin, "-N", "DOCKER-USER")
	if _, err := run("", bin, "-C", "DOCKER-USER", "-j", Chain); err != nil {
		_, err = run("", bin, "-I", "DOCKER-USER", "1", "-j", Chain)
		return err
	}
	return nil
}

// jumpFirst makes the jump to target the first rule of chain, ahead of any
// reject rule of the provider's image, even one inserted after ours.
func jumpFirst(run func(string, ...string) (string, error), bin, chain, target string) error {
	out, err := run("", bin, "-S", chain)
	if err != nil {
		return err
	}
	jump := "-A " + chain + " -j " + target
	for line := range strings.SplitSeq(out, "\n") {
		if line = strings.TrimSpace(line); strings.HasPrefix(line, "-A ") {
			if line == jump {
				return nil
			}
			break
		}
	}
	// Drop the misplaced copies (bounded: a -D that does nothing must not
	// loop forever).
	for range 8 {
		if _, err := run("", bin, "-C", chain, "-j", target); err != nil {
			break
		}
		if _, err := run("", bin, "-D", chain, "-j", target); err != nil {
			return err
		}
	}
	_, err = run("", bin, "-I", chain, "1", "-j", target)
	return err
}

// ParseAllow parses "1.2.3.4" or "10.0.0.0/24".
func ParseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), nil
}
