package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/moby/moby/client"

	"github.com/JuniorCarlini/hangar/internal/node"
)

// fakeDocker answers the few Docker API calls the edge wiring makes and
// records them in order.
type fakeDocker struct {
	mu    sync.Mutex
	calls []string
	// bodies holds the JSON body of each create/connect call, by call.
	bodies map[string]map[string]any
	// caddyNets are the networks Caddy is on.
	caddyNets []string
	// onEdge are the service containers listed on the edge network.
	onEdge []map[string]any
}

var apiVersion = regexp.MustCompile(`^/v[0-9.]+`)

func (f *fakeDocker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := apiVersion.ReplaceAllString(r.URL.Path, "")
	call := r.Method + " " + path
	var body map[string]any
	if raw, _ := io.ReadAll(r.Body); len(raw) > 0 {
		_ = json.Unmarshal(raw, &body)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	if f.bodies == nil {
		f.bodies = map[string]map[string]any{}
	}
	f.bodies[call] = body
	reply := func(v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	switch {
	case call == "POST /containers/create":
		w.WriteHeader(http.StatusCreated)
		reply(map[string]any{"Id": "new"})
	case call == "GET /containers/"+node.EdgeContainer+"/json":
		nets := map[string]any{}
		for _, n := range f.caddyNets {
			nets[n] = map[string]any{}
		}
		reply(map[string]any{
			"Id": "caddy", "Name": "/" + node.EdgeContainer,
			"Config":          map[string]any{"Labels": map[string]string{node.LabelManaged: "true", "hangar.role": "edge"}},
			"NetworkSettings": map[string]any{"Networks": nets},
		})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "/networks/"):
		name := strings.TrimSuffix(strings.TrimPrefix(path, "/networks/"), "/")
		reply(map[string]any{"Name": name, "Id": name, "Labels": map[string]string{
			node.LabelManaged: "true", node.LabelProject: strings.TrimPrefix(name, node.NetworkPrefix),
		}})
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/connect"):
		if body["Container"] == "caddy" {
			f.caddyNets = append(f.caddyNets, strings.TrimSuffix(strings.TrimPrefix(path, "/networks/"), "/connect"))
		}
		w.WriteHeader(http.StatusOK)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/disconnect"),
		r.Method == http.MethodDelete && strings.HasPrefix(path, "/networks/"):
		w.WriteHeader(http.StatusOK)
	case call == "GET /containers/json":
		reply(f.onEdge)
	default:
		http.Error(w, "unexpected "+call, http.StatusNotImplemented)
	}
}

func (f *fakeDocker) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func fakeLocal(t *testing.T, f *fakeDocker) *Local {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	c, err := client.New(client.WithHost("tcp://"+strings.TrimPrefix(srv.URL, "http://")), client.WithAPIVersion("1.52"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &Local{c: c}
}

// A service with a domain never joins the edge network: there every project
// with a domain could reach the others' ports. Caddy joins its project
// network instead.
func TestEdgeServiceStaysOffTheEdgeNetwork(t *testing.T) {
	f := &fakeDocker{caddyNets: []string{node.EdgeNetwork}}
	l := fakeLocal(t, f)
	ctx := context.Background()
	spec := node.ServiceSpec{ProjectID: "prj_a", Project: "a", ServiceID: "svc_web", Service: "web", Deployment: "dep_1", Image: "nginx", Edge: true}
	if _, err := l.createContainer(ctx, spec, node.ContainerName("a", "web"), "nginx"); err != nil {
		t.Fatal(err)
	}
	created := f.bodies["POST /containers/create"]
	eps, _ := created["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)
	if _, ok := eps[node.EdgeNetwork]; ok {
		t.Fatalf("service got an endpoint on %s: %v", node.EdgeNetwork, eps)
	}
	if _, ok := eps[node.NetworkName("a")]; !ok {
		t.Fatalf("service is not on its project network: %v", eps)
	}

	if err := l.ConnectEdge(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	conn := f.bodies["POST /networks/"+node.NetworkName("a")+"/connect"]
	if conn == nil || conn["Container"] != "caddy" {
		t.Fatalf("caddy was not joined to the project network: %v", f.log())
	}
	if ep, _ := conn["EndpointConfig"].(map[string]any); ep == nil || ep["GwPriority"] != float64(-1) {
		t.Errorf("caddy's project endpoint may take the default gateway: %v", conn)
	}
	// Already there: no second connect.
	before := len(f.log())
	if err := l.ConnectEdge(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.log()[before:] {
		if strings.HasSuffix(c, "/connect") {
			t.Fatal("caddy joined the same network twice")
		}
	}
}

// Upgrading moves services an older version put on the edge network off it,
// joining Caddy to their project network first so no site goes down.
func TestEnsureEdgeMovesServicesOffTheEdgeNetwork(t *testing.T) {
	f := &fakeDocker{
		caddyNets: []string{node.EdgeNetwork},
		onEdge: []map[string]any{
			{"Id": "caddy", "Names": []string{"/" + node.EdgeContainer}, "Labels": map[string]string{node.LabelManaged: "true", "hangar.role": "edge"}},
			{"Id": "svc", "Names": []string{"/b_api"}, "Labels": map[string]string{node.LabelManaged: "true", node.LabelProject: "b"}},
		},
	}
	l := fakeLocal(t, f)
	if err := l.moveServicesOffEdge(context.Background()); err != nil {
		t.Fatal(err)
	}
	join, leave := -1, -1
	for i, c := range f.log() {
		switch c {
		case "POST /networks/" + node.NetworkName("b") + "/connect":
			join = i
		case "POST /networks/" + node.EdgeNetwork + "/disconnect":
			if f.bodies[c]["Container"] == "caddy" {
				t.Fatal("caddy was taken off the edge network")
			}
			leave = i
		}
	}
	if join < 0 || leave < 0 || join > leave {
		t.Fatalf("want caddy to join %s before the service leaves %s: %v", node.NetworkName("b"), node.EdgeNetwork, f.log())
	}
}

// Removing a project network takes Caddy off it first: Docker refuses while
// Caddy runs on it, and a stopped Caddy left listing it would not start.
func TestRemoveProjectNetworkTakesCaddyOff(t *testing.T) {
	f := &fakeDocker{caddyNets: []string{node.EdgeNetwork, node.NetworkName("c")}}
	l := fakeLocal(t, f)
	if err := l.RemoveProjectNetwork(context.Background(), "c"); err != nil {
		t.Fatal(err)
	}
	leave, remove := -1, -1
	for i, c := range f.log() {
		switch c {
		case "POST /networks/" + node.NetworkName("c") + "/disconnect":
			leave = i
		case "DELETE /networks/" + node.NetworkName("c"):
			remove = i
		}
	}
	if leave < 0 || remove < 0 || leave > remove {
		t.Fatalf("want caddy off the network before it is removed: %v", f.log())
	}
}
