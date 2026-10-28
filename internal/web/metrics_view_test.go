package web

import (
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/JuniorCarlini/hangar/internal/metrics"
)

func TestLeftAlign(t *testing.T) {
	cases := []struct{ in, want []int }{
		{[]int{-1, -1, 5, 7}, []int{5, 7, -1, -1}},
		{[]int{5, -1, 7}, []int{5, -1, 7}},         // a gap in the middle stays
		{[]int{-1, 3, -1, 4}, []int{3, -1, 4, -1}}, // only the leading gaps move
		{[]int{-1, -1}, []int{-1, -1}},
		{nil, nil},
	}
	for _, c := range cases {
		if got := leftAlign(c.in); !slices.Equal(got, c.want) {
			t.Errorf("leftAlign(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSparkTipsLineUpWithBars(t *testing.T) {
	at := func(m int) time.Time { return time.Unix(1_700_000_000+int64(m)*60, 0) }
	// Two bars before the panel had data, then three readings.
	pts := []metrics.Point{{}, {}, {At: at(2), CPU: 10}, {At: at(3), CPU: 40}, {At: at(4), CPU: 20}}
	bars := hist(pts, func(p metrics.Point) float64 { return p.CPU }, 100)
	tips := sparkTips(pts, time.Minute, func(p metrics.Point) string { return strconv.Itoa(int(p.CPU)) },
		func(p metrics.Point) float64 { return p.CPU })
	if !slices.Equal(bars, []int{10, 40, 20, -1, -1}) {
		t.Fatalf("bars = %v", bars)
	}
	if !slices.Equal(tips.Text, []string{"10", "40", "20", "", ""}) {
		t.Errorf("text = %q, want it in the bars' order", tips.Text)
	}
	if tips.At[1] != at(3).Unix() || tips.At[3] != 0 {
		t.Errorf("at = %v", tips.At)
	}
	if tips.Peak != 1 || tips.Step != 60 {
		t.Errorf("peak = %d, step = %d; want 1, 60", tips.Peak, tips.Step)
	}
	if empty := sparkTips(make([]metrics.Point, 3), time.Minute, nil, nil); empty.Peak != -1 {
		t.Errorf("no data: peak = %d, want -1", empty.Peak)
	}
}
