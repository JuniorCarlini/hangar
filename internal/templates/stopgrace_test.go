package templates

import (
	"strings"
	"testing"
)

func TestStopGracePeriod(t *testing.T) {
	const env = "    environment:\n"
	tp, err := Parse("xy", with(FileCompose, env, "    stop_grace_period: 1m30s\n"+env))
	if err != nil {
		t.Fatal(err)
	}
	if tp.Services[0].StopGraceS != 90 || len(tp.Warnings) != 0 {
		t.Errorf("stop grace: %d, warnings %v", tp.Services[0].StopGraceS, tp.Warnings)
	}
	r, err := tp.Render(sampleVals(tp))
	if err != nil || r.Services[0].StopGraceS != 90 {
		t.Errorf("rendered stop grace: %+v %v", r.Services, err)
	}

	// Above the cap: kept at the cap, with a warning for the author.
	tp, err = Parse("xy", with(FileCompose, env, "    stop_grace_period: 10m\n"+env))
	if err != nil {
		t.Fatal(err)
	}
	if tp.Services[0].StopGraceS != 120 || len(tp.Warnings) != 1 || !strings.Contains(tp.Warnings[0], "stop_grace_period") {
		t.Errorf("clamped: %d, warnings %v", tp.Services[0].StopGraceS, tp.Warnings)
	}
	for _, bad := range []string{"soon", "-5s", "0s"} {
		if _, err := Parse("xy", with(FileCompose, env, "    stop_grace_period: "+bad+"\n"+env)); err == nil || !strings.Contains(err.Error(), "stop_grace_period") {
			t.Errorf("%s accepted: %v", bad, err)
		}
	}
	if secs, _, ok := StopGrace("1500ms"); !ok || secs != 2 {
		t.Errorf("sub-second parts round up: %d %v", secs, ok)
	}
}
