package firewall

import (
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestRestoreOnlyMatchesPublishedTraffic(t *testing.T) {
	st := State{Version: 1, Rules: []Rule{{Port: 5433, Protocol: "tcp", Allow: []netip.Prefix{
		netip.MustParsePrefix("200.1.2.3/32"), netip.MustParsePrefix("2001:db8::/64"),
	}}}}
	v4 := Restore(st, 4)
	for _, want := range []string{
		":HANGAR-PORTS - [0:0]",
		"-A HANGAR-PORTS -p tcp -m conntrack --ctstate DNAT --ctorigdstport 5433 --ctdir ORIGINAL -s 127.0.0.0/8 -j RETURN",
		"-A HANGAR-PORTS -p tcp -m conntrack --ctstate DNAT --ctorigdstport 5433 --ctdir ORIGINAL -s 200.1.2.3/32 -j RETURN",
		"-A HANGAR-PORTS -p tcp -m conntrack --ctstate DNAT --ctorigdstport 5433 --ctdir ORIGINAL -j DROP",
		"COMMIT",
	} {
		if !strings.Contains(v4, want) {
			t.Errorf("missing %q in\n%s", want, v4)
		}
	}
	if strings.Contains(v4, "2001:db8") {
		t.Error("IPv6 address in the IPv4 rules")
	}
	if v6 := Restore(st, 6); !strings.Contains(v6, "-s 2001:db8::/64 -j RETURN") || strings.Contains(v6, "200.1.2.3") {
		t.Errorf("v6 rules:\n%s", v6)
	}
	// DROP comes after every RETURN of the port.
	if strings.Index(v4, "-j DROP") < strings.Index(v4, "200.1.2.3") {
		t.Error("DROP before the allowed addresses")
	}
}

func TestValidateRejectsBadRules(t *testing.T) {
	ip := []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}
	for _, r := range []Rule{
		{Port: 0, Protocol: "tcp", Allow: ip},
		{Port: 70000, Protocol: "tcp", Allow: ip},
		{Port: 5432, Protocol: "icmp", Allow: ip},
		{Port: 5432, Protocol: "tcp"},
	} {
		if (State{Version: 1, Rules: []Rule{r}}).Validate() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

func TestWriterStatus(t *testing.T) {
	w := Writer{Dir: filepath.Join(t.TempDir(), "fw")}
	if err := w.Write([]Rule{{Port: 5433, Protocol: "tcp", Allow: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}}}); err != nil {
		t.Fatal(err)
	}
	if pending, _ := w.Status(); !pending {
		t.Error("nothing applied yet: must be pending")
	}
}

func TestParseAllow(t *testing.T) {
	for in, want := range map[string]string{"200.1.2.3": "200.1.2.3/32", "10.0.0.9/24": "10.0.0.0/24", "2001:db8::1": "2001:db8::1/128"} {
		p, err := ParseAllow(in)
		if err != nil || p.String() != want {
			t.Errorf("ParseAllow(%q) = %v, %v", in, p, err)
		}
	}
	if _, err := ParseAllow("evil; rm"); err == nil {
		t.Error("garbage accepted")
	}
}
