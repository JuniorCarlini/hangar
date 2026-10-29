// Package keyset is server-side keyset (cursor) pagination for lists that
// grow over time (docs/20): each page is "the n rows older (or newer) than
// this one" in a stable order by time and id, so a page costs one indexed
// range read however deep it is, and rows added meanwhile never shift or
// repeat what the reader already saw (as OFFSET pagination would).
package keyset

import (
	"math"
	"strconv"
	"strings"
)

// Key is a row's place in the order: newest first by At, then by ID
// (descending) for rows with the same At. Lists ordered by an integer id
// alone use At for it and leave ID empty.
type Key struct {
	At int64
	ID string
}

// Top is the key above every row: "older than Top" is the first page.
var Top = Key{At: math.MaxInt64}

// Request is the page asked for in the URL.
type Request struct {
	Key   Key
	Newer bool // the page above Key (towards the newest) instead of below
	set   bool
}

// First reports whether the request is for the first (newest) page.
func (r Request) First() bool { return !r.set }

// Parse reads a cursor written by Page.Older or Page.Newer. Anything else
// (empty, malformed, tampered) is the first page.
func Parse(s string) Request {
	dir, rest, ok := strings.Cut(s, ".")
	if !ok || (dir != "o" && dir != "n") {
		return Request{Key: Top}
	}
	at, id, _ := strings.Cut(rest, ".")
	n, err := strconv.ParseInt(at, 10, 64)
	if err != nil || len(id) > 512 {
		return Request{Key: Top}
	}
	return Request{Key: Key{At: n, ID: id}, Newer: dir == "n", set: true}
}

func (k Key) encode(dir string) string {
	return dir + "." + strconv.FormatInt(k.At, 10) + "." + k.ID
}

// Page is one page of rows, newest first, and the cursors of its
// neighbours ("" when there is none).
type Page[T any] struct {
	Rows  []T
	Older string
	Newer string
}

// Fetch reads one page of size rows. older returns up to lim rows strictly
// below a key, newest first; newer returns up to lim rows strictly above
// it, oldest first. A "newer" page that reaches the top is the first page
// again, so going back always ends where the reader started.
func Fetch[T any](req Request, size int,
	older, newer func(k Key, lim int64) ([]T, error), key func(T) Key,
) (Page[T], error) {
	if req.Newer {
		rows, err := newer(req.Key, int64(size)+1)
		if err != nil {
			return Page[T]{}, err
		}
		if len(rows) > size {
			rows = rows[:size]
			reverse(rows)
			return Page[T]{Rows: rows, Older: key(rows[len(rows)-1]).encode("o"), Newer: key(rows[0]).encode("n")}, nil
		}
		req = Request{Key: Top}
	}
	rows, err := older(req.Key, int64(size)+1)
	if err != nil {
		return Page[T]{}, err
	}
	var p Page[T]
	if len(rows) > size {
		rows = rows[:size]
		p.Older = key(rows[len(rows)-1]).encode("o")
	}
	if !req.First() && len(rows) > 0 {
		p.Newer = key(rows[0]).encode("n")
	} else if !req.First() {
		// Past the end (rows pruned meanwhile): offer the way back.
		p.Newer = req.Key.encode("n")
	}
	p.Rows = rows
	return p, nil
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
