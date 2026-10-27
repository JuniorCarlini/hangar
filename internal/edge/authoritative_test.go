package edge

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeNameserver answers like an authoritative server (AA set, no
// recursion): the TXT records in txt, "no such name" for other names under
// propzy.com.br., and a referral for anything else.
func fakeNameserver(t *testing.T, txt map[string]string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			h, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			name := q.Name.String()
			v, ok := txt[name]
			found := ok && q.Type == dnsmessage.TypeTXT
			rh := dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired}
			switch {
			case found:
				rh.Authoritative = true
			case strings.HasSuffix(name, ".propzy.com.br."):
				rh.Authoritative = true
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			if found {
				_ = b.StartAnswers()
				_ = b.TXTResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.TXTResource{TXT: []string{v}})
			}
			msg, err := b.Finish()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(msg, addr)
		}
	}()
	return pc.LocalAddr().String()
}

// The question goes to the zone's nameserver, which answers with the record,
// a final "no such name", or a referral that is reported as an error.
func TestAskServer(t *testing.T) {
	srv := fakeNameserver(t, map[string]string{"_hangar.loja4.propzy.com.br.": "hg-78c44be4c740"})
	ctx := context.Background()
	recs, err := askServer(ctx, srv, "_hangar.loja4.propzy.com.br")
	if err != nil || !slices.Equal(recs, []string{"hg-78c44be4c740"}) {
		t.Fatalf("record: %v %v", recs, err)
	}
	if _, err := askServer(ctx, srv, "_hangar.loja5.propzy.com.br"); !isNotFound(err) {
		t.Fatalf("missing record: %v", err)
	}
	if _, err := askServer(ctx, srv, "_hangar.outra.com.br"); err == nil || isNotFound(err) {
		t.Fatalf("referral: %v", err)
	}
}

// A record created after a failed attempt is seen at once: the zone's
// nameserver wins over the cached "no such name"; a failure on that path
// falls back to the system resolver.
func TestFreshTXTSkipsTheCachedMiss(t *testing.T) {
	ctx := context.Background()
	stale := func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	var asked []string
	f := &freshTXT{
		system: stale,
		servers: func(_ context.Context, zone string) ([]string, error) {
			if zone != "propzy.com.br" {
				t.Errorf("zone %q", zone)
			}
			return []string{"ns1", "ns2"}, nil
		},
		ask: func(_ context.Context, server, _ string) ([]string, error) {
			asked = append(asked, server)
			if server == "ns1" {
				return nil, errors.New("timeout")
			}
			return []string{"hg-78c44be4c740"}, nil
		},
	}
	if recs, err := f.Lookup(ctx, "_hangar.loja4.propzy.com.br"); err != nil || len(recs) != 1 {
		t.Fatalf("fresh: %v %v", recs, err)
	}
	if !slices.Equal(asked, []string{"ns1", "ns2"}) {
		t.Errorf("asked %v", asked)
	}

	f.servers = func(context.Context, string) ([]string, error) { return nil, errors.New("no NS") }
	if _, err := f.Lookup(ctx, "_hangar.loja4.propzy.com.br"); !isNotFound(err) {
		t.Errorf("fallback: %v", err)
	}
}
