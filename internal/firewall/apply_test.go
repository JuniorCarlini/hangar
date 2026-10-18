package firewall

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// fakeIPTables keeps chains as rule lists ("-j X", "-s ... -j ACCEPT") and
// answers the few commands applyFamily runs.
type fakeIPTables struct {
	chains map[string][]string
	calls  []string
}

func (f *fakeIPTables) run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, strings.Join(args, " "))
	missing := errors.New("exit status 1")
	switch {
	case strings.HasSuffix(args[0], "-restore"):
		// A declared chain is created, or emptied, even with --noflush.
		for line := range strings.SplitSeq(stdin, "\n") {
			if name, ok := strings.CutPrefix(line, ":"); ok {
				f.chains[strings.Fields(name)[0]] = []string{}
			}
		}
		for line := range strings.SplitSeq(stdin, "\n") {
			if rest, ok := strings.CutPrefix(line, "-A "); ok {
				chain, rule, _ := strings.Cut(rest, " ")
				f.chains[chain] = append(f.chains[chain], rule)
			}
		}
		return nil, nil
	}
	chain := args[2]
	rules, ok := f.chains[chain]
	rule := strings.Join(args[3:], " ")
	switch args[1] {
	case "-N":
		if ok {
			return []byte("Chain already exists."), missing
		}
		f.chains[chain] = []string{}
	case "-S":
		out := "-P " + chain + " ACCEPT\n"
		for _, r := range rules {
			out += "-A " + chain + " " + r + "\n"
		}
		return []byte(out), nil
	case "-C":
		if !slices.Contains(rules, rule) {
			return nil, missing
		}
	case "-D":
		i := slices.Index(rules, rule)
		if i < 0 {
			return nil, missing
		}
		f.chains[chain] = slices.Delete(rules, i, i+1)
	case "-I":
		f.chains[chain] = slices.Insert(rules, 0, strings.Join(args[4:], " "))
	}
	return nil, nil
}

func withFake(t *testing.T, chains map[string][]string) *fakeIPTables {
	t.Helper()
	f := &fakeIPTables{chains: chains}
	orig := runCmd
	runCmd = f.run
	t.Cleanup(func() { runCmd = orig })
	return f
}

func edgeState() State {
	return State{Version: 1, Rules: []Rule{}, Edge: &EdgeAccess{
		Caddy: netip.MustParseAddr("172.30.0.2"), Gateway: netip.MustParseAddr("172.30.0.1"), Ports: []int{7701, 7702},
	}}
}

const reject = "-j REJECT --reject-with icmp-host-prohibited"

// After a "netfilter-persistent reload" (or cloud-init) the INPUT chain is
// the image's again and Hangar's chains are gone or empty: a re-run must
// bring Caddy's access back, first in INPUT.
func TestApplyRecoversFromAReload(t *testing.T) {
	for name, chains := range map[string]map[string][]string{
		"chains deleted": {"INPUT": {"-p tcp --dport 22 -j ACCEPT", reject}},
		"chains flushed": {"INPUT": {"-p tcp --dport 22 -j ACCEPT", reject}, EdgeChain: {}, Chain: {}, "DOCKER-USER": {}},
		"jump behind reject": {
			"INPUT": {reject, "-j " + EdgeChain}, EdgeChain: {}, Chain: {}, "DOCKER-USER": {"-j " + Chain},
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := withFake(t, chains)
			if err := applyFamily(t.Context(), "iptables", Restore(edgeState(), 4)); err != nil {
				t.Fatal(err)
			}
			in := f.chains["INPUT"]
			if in[0] != "-j "+EdgeChain || strings.Count(strings.Join(in, "\n"), EdgeChain) != 1 {
				t.Errorf("INPUT = %q", in)
			}
			if e := f.chains[EdgeChain]; len(e) != 1 || !strings.Contains(e[0], "--dports 7701,7702 -j ACCEPT") {
				t.Errorf("%s = %q", EdgeChain, e)
			}
			if d := f.chains["DOCKER-USER"]; len(d) != 1 || d[0] != "-j "+Chain {
				t.Errorf("DOCKER-USER = %q", d)
			}
		})
	}
}

// The timer re-runs the apply every few minutes: on a healthy host it must
// not touch the jumps.
func TestApplyIsIdempotent(t *testing.T) {
	f := withFake(t, map[string][]string{"INPUT": {reject}})
	restore := Restore(edgeState(), 4)
	if err := applyFamily(t.Context(), "iptables", restore); err != nil {
		t.Fatal(err)
	}
	f.calls = nil
	if err := applyFamily(t.Context(), "iptables", restore); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.calls {
		if strings.Contains(c, " -I ") || strings.Contains(c, " -D ") {
			t.Errorf("second run changed a jump: %s", c)
		}
	}
	if in := f.chains["INPUT"]; len(in) != 2 || in[0] != "-j "+EdgeChain {
		t.Errorf("INPUT = %q", in)
	}
}
