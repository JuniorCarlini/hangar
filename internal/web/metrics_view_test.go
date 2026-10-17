package web

import (
	"slices"
	"testing"
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
