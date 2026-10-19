package docker

import (
	"context"
	"errors"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
)

func TestCheckOwner(t *testing.T) {
	ctx := context.Background()
	known := func(_ context.Context, projectID, serviceID string) bool {
		return projectID == "prj_mine" && (serviceID == "" || serviceID == "svc_mine")
	}
	l := &Local{}
	l.SetInstance("hgi_a", known)
	labels := func(kv ...string) map[string]string {
		m := map[string]string{node.LabelManaged: "true"}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	other := func(err error) bool {
		var ie *i18n.Error
		return errors.As(err, &ie) && ie.Key == "docker.error.other_instance"
	}
	cases := []struct {
		name   string
		labels map[string]string
		check  func(error) bool
	}{
		{"not Hangar's", map[string]string{}, func(err error) bool { return errors.Is(err, ErrNotManaged) }},
		{"this panel's", labels(node.LabelInstance, "hgi_a", node.LabelProjectID, "prj_x"), func(err error) bool { return err == nil }},
		{"another panel's", labels(node.LabelInstance, "hgi_b", node.LabelProjectID, "prj_mine", node.LabelServiceID, "svc_mine"), other},
		{"legacy, known ids", labels(node.LabelProjectID, "prj_mine", node.LabelServiceID, "svc_mine"), func(err error) bool { return err == nil }},
		{"legacy network, known project", labels(node.LabelProjectID, "prj_mine"), func(err error) bool { return err == nil }},
		{"legacy, unknown service", labels(node.LabelProjectID, "prj_mine", node.LabelServiceID, "svc_theirs"), other},
		{"legacy, unknown project", labels(node.LabelProjectID, "prj_theirs", node.LabelServiceID, "svc_theirs"), other},
		{"legacy infrastructure", labels("hangar.role", "edge"), func(err error) bool { return err == nil }},
	}
	for _, c := range cases {
		if err := l.checkOwner(ctx, "p_web", c.labels); !c.check(err) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}

	// Without an instance (tests, read-only tools) every Hangar object counts.
	if err := (&Local{}).checkOwner(ctx, "p_web", labels(node.LabelInstance, "hgi_b")); err != nil {
		t.Errorf("no instance set: %v", err)
	}
	// What is created carries the id.
	if got := l.managedLabels("prj_x", "x")[node.LabelInstance]; got != "hgi_a" {
		t.Errorf("created labels carry %q", got)
	}
}
