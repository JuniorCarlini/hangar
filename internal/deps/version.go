package deps

import (
	"math"
	"strconv"
	"strings"
)

// CompareVersions orders two version strings well enough for the ecosystems
// the monitor reads (semver, PEP 440 releases, Debian and Alpine versions):
// an optional epoch ("1:"), then runs of digits compared as numbers and runs
// of other characters compared as text. A pre-release marker ("rc", "a",
// "beta", "~", "_alpha") sorts before the release it precedes. It returns -1,
// 0 or 1.
func CompareVersions(a, b string) int {
	ea, ra := splitEpoch(a)
	eb, rb := splitEpoch(b)
	if ea != eb {
		return cmpInt(ea, eb)
	}
	pa, pb := chunks(ra), chunks(rb)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y chunk
		if i < len(pa) {
			x = pa[i]
		} else {
			x = chunk{end: true}
		}
		if i < len(pb) {
			y = pb[i]
		} else {
			y = chunk{end: true}
		}
		if c := x.cmp(y); c != 0 {
			return c
		}
	}
	return 0
}

func splitEpoch(v string) (int, string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			return n, v[i+1:]
		}
	}
	return 0, v
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// chunk is a run of digits (num) or of letters (text); other separators
// are dropped. end stands for "nothing left".
type chunk struct {
	num   int
	text  string
	isNum bool
	end   bool
}

func chunks(v string) []chunk {
	// "+" is not cut off as semver build metadata: Debian versions carry
	// the security fix there (3.5.1-1+deb13u1).
	v = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "v")
	var out []chunk
	for i := 0; i < len(v); {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(v[i:j])
			if err != nil {
				n = math.MaxInt // absurdly long digit run: sort it last
			}
			out = append(out, chunk{num: n, isNum: true})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, chunk{text: v[i:j]})
			i = j
		case c == '~':
			// Debian: "~" sorts before anything, even the end.
			out = append(out, chunk{text: "~"})
			i++
		default:
			i++
		}
	}
	return out
}

// preRelease markers sort before the release.
var preRelease = map[string]bool{"~": true, "a": true, "alpha": true, "b": true, "beta": true, "rc": true, "c": true, "pre": true, "preview": true, "dev": true}

func (x chunk) cmp(y chunk) int {
	switch {
	case x.end && y.end:
		return 0
	case x.end:
		// "1.0" vs "1.0rc1": the release is newer; "1.0" vs "1.0.1": older.
		if !y.isNum && preRelease[y.text] {
			return 1
		}
		return -1
	case y.end:
		return -y.cmp(x)
	case x.isNum && y.isNum:
		return cmpInt(x.num, y.num)
	case x.isNum:
		// A number after a shared prefix ranks above any word
		// (1.0.1 > 1.0+deb, 1.0.0 > 1.0.0-rc).
		return 1
	case y.isNum:
		return -y.cmp(x)
	}
	if x.text == y.text {
		return 0
	}
	if preRelease[x.text] != preRelease[y.text] {
		if preRelease[x.text] {
			return -1
		}
		return 1
	}
	return strings.Compare(x.text, y.text)
}

// numericParts returns the leading dotted numbers of a tag ("18.1" → [18 1],
// "3.13-slim" → [3 13]) and the rest ("-slim"). ok is false when the tag
// does not start with a number ("latest", "alpine").
func numericParts(tag string) (parts []int, rest string, ok bool) {
	s := strings.TrimPrefix(tag, "v")
	i := 0
	for {
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j == i || j-i > 9 {
			break
		}
		n, _ := strconv.Atoi(s[i:j])
		parts = append(parts, n)
		i = j
		if i < len(s) && s[i] == '.' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' {
			i++
			continue
		}
		break
	}
	if len(parts) == 0 {
		return nil, "", false
	}
	return parts, s[i:], true
}
