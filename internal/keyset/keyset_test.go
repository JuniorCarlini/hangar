package keyset

import (
	"slices"
	"strconv"
	"testing"
)

// rows is a table ordered newest first by (At, ID); several share an At.
func table(n int) []Key {
	var out []Key
	for i := range n {
		out = append(out, Key{At: int64(i / 3), ID: "id" + strconv.Itoa(100+i)})
	}
	slices.SortFunc(out, func(a, b Key) int { return -compare(a, b) })
	return out
}

func compare(a, b Key) int {
	switch {
	case a.At != b.At:
		if a.At < b.At {
			return -1
		}
		return 1
	case a.ID < b.ID:
		return -1
	case a.ID > b.ID:
		return 1
	}
	return 0
}

func fetchers(t *[]Key) (older, newer func(Key, int64) ([]Key, error)) {
	older = func(k Key, lim int64) ([]Key, error) {
		var out []Key
		for _, r := range *t { // newest first
			if compare(r, k) < 0 && int64(len(out)) < lim {
				out = append(out, r)
			}
		}
		return out, nil
	}
	newer = func(k Key, lim int64) ([]Key, error) {
		var out []Key
		for i := len(*t) - 1; i >= 0; i-- { // oldest first
			if r := (*t)[i]; compare(r, k) > 0 && int64(len(out)) < lim {
				out = append(out, r)
			}
		}
		return out, nil
	}
	return older, newer
}

func id(k Key) Key { return k }

func TestWalkOlderThenBackCoversEveryRowOnce(t *testing.T) {
	tab := table(23)
	older, newer := fetchers(&tab)
	var pages [][]Key
	req := Parse("")
	for {
		p, err := Fetch(req, 5, older, newer, id)
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, p.Rows)
		if len(pages) == 1 && p.Newer != "" {
			t.Fatal("the first page has no newer page")
		}
		if p.Older == "" {
			break
		}
		req = Parse(p.Older)
	}
	var seen []Key
	for _, p := range pages {
		seen = append(seen, p...)
	}
	if !slices.Equal(seen, tab) {
		t.Fatalf("pages do not cover the table in order:\n%v\n%v", seen, tab)
	}
	if len(pages) != 5 || len(pages[4]) != 3 {
		t.Fatalf("got %d pages (last %d rows), want 5 pages ending with 3", len(pages), len(pages[len(pages)-1]))
	}

	// From the third page, "newer" gives back the second, then the first.
	third, _ := Fetch(Parse(mustOlder(t, older, newer, 2)), 5, older, newer, id)
	second, _ := Fetch(Parse(third.Newer), 5, older, newer, id)
	if !slices.Equal(second.Rows, pages[1]) {
		t.Fatalf("newer page = %v, want %v", second.Rows, pages[1])
	}
	first, _ := Fetch(Parse(second.Newer), 5, older, newer, id)
	if !slices.Equal(first.Rows, pages[0]) || first.Newer != "" {
		t.Fatalf("back at the top = %v (newer %q), want the first page", first.Rows, first.Newer)
	}
}

// mustOlder follows "older" n times from the first page.
func mustOlder(t *testing.T, older, newer func(Key, int64) ([]Key, error), n int) string {
	t.Helper()
	p, _ := Fetch(Parse(""), 5, older, newer, id)
	for range n - 1 {
		p, _ = Fetch(Parse(p.Older), 5, older, newer, id)
	}
	return p.Older
}

func TestPagesStayStableWhenRowsArrive(t *testing.T) {
	tab := table(12)
	older, newer := fetchers(&tab)
	first, _ := Fetch(Parse(""), 5, older, newer, id)
	// New rows on top while the reader is on page one.
	tab = append([]Key{{At: 99, ID: "new2"}, {At: 98, ID: "new1"}}, tab...)
	second, _ := Fetch(Parse(first.Older), 5, older, newer, id)
	if second.Rows[0] != tab[7] { // continues right after the last row seen
		t.Fatalf("second page starts at %v, want %v", second.Rows[0], tab[7])
	}
	for _, r := range second.Rows {
		if slices.Contains(first.Rows, r) {
			t.Fatalf("row %v repeated across pages", r)
		}
	}
}

func TestExactPageBoundary(t *testing.T) {
	tab := table(10)
	older, newer := fetchers(&tab)
	p, _ := Fetch(Parse(""), 5, older, newer, id)
	p, _ = Fetch(Parse(p.Older), 5, older, newer, id)
	if len(p.Rows) != 5 || p.Older != "" {
		t.Fatalf("last full page: %d rows, older %q; want 5 and no older page", len(p.Rows), p.Older)
	}
	empty := table(0)
	o, n := fetchers(&empty)
	if p, _ := Fetch(Parse(""), 5, o, n, id); len(p.Rows) != 0 || p.Older != "" || p.Newer != "" {
		t.Fatalf("empty list: %+v", p)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "x", "o.", "o.abc.1", "z.1.a", "n"} {
		if r := Parse(s); !r.First() || r.Key != Top {
			t.Errorf("Parse(%q) = %+v, want the first page", s, r)
		}
	}
	if r := Parse("n.42.dep_1.x"); r.First() || !r.Newer || r.Key != (Key{At: 42, ID: "dep_1.x"}) {
		t.Errorf("Parse kept %+v", r)
	}
}

func TestPastTheEndOffersTheWayBack(t *testing.T) {
	tab := table(3)
	older, newer := fetchers(&tab)
	p, _ := Fetch(Request{Key: Key{At: -5}, set: true}, 5, older, newer, id)
	if len(p.Rows) != 0 || p.Newer == "" {
		t.Fatalf("%+v: want no rows and a link back", p)
	}
}
