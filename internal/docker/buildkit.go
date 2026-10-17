package docker

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// BuildKit reports progress as moby.buildkit.trace messages: a protobuf
// StatusResponse (moby/buildkit api/services/control) in base64. Only a few
// fields matter here, so they are decoded by hand instead of pulling in
// BuildKit and gRPC:
//
//	StatusResponse { repeated Vertex vertexes = 1; repeated VertexStatus statuses = 2;
//	                 repeated VertexLog logs = 3; repeated VertexWarning warnings = 4; }
//	Vertex         { string digest = 1; string name = 3; bool cached = 4;
//	                 Timestamp started = 5; Timestamp completed = 6; string error = 7; }
//	VertexLog      { string vertex = 1; int64 stream = 3; bytes msg = 4; }
//	VertexWarning  { string vertex = 1; bytes short = 3; }

const traceLineMax = 4 << 10

// traceLog turns StatusResponses into plain log lines, like
// "docker build --progress=plain": "#3 [2/4] RUN npm ci", then the command's
// output prefixed with its step number. Output is buffered per step until a
// newline, so a secret split across two messages is still one line when the
// caller masks it.
type traceLog struct {
	out     func(string)
	num     map[string]int
	started map[string]bool
	cached  map[string]bool
	failed  map[string]bool
	partial map[string]*strings.Builder
	order   []string
}

func newTraceLog(out func(string)) *traceLog {
	return &traceLog{
		out: out, num: map[string]int{}, started: map[string]bool{}, cached: map[string]bool{},
		failed: map[string]bool{}, partial: map[string]*strings.Builder{},
	}
}

func (t *traceLog) id(digest string) int {
	n, ok := t.num[digest]
	if !ok {
		n = len(t.num) + 1
		t.num[digest] = n
	}
	return n
}

func (t *traceLog) emit(digest, line string) {
	if len(line) > traceLineMax {
		line = line[:traceLineMax] + " …"
	}
	t.out(fmt.Sprintf("#%d %s", t.id(digest), line))
}

// status decodes one StatusResponse; malformed input is ignored (it is only
// the log).
func (t *traceLog) status(b []byte) {
	_ = eachField(b, func(num int, wt byte, v []byte, _ uint64) error {
		if wt != 2 {
			return nil
		}
		switch num {
		case 1:
			t.vertex(v)
		case 3:
			t.vertexLog(v)
		case 4:
			t.warning(v)
		}
		return nil
	})
}

func (t *traceLog) vertex(b []byte) {
	var digest, name, verr string
	var cached, started bool
	_ = eachField(b, func(num int, wt byte, v []byte, x uint64) error {
		switch {
		case num == 1 && wt == 2:
			digest = string(v)
		case num == 3 && wt == 2:
			name = string(v)
		case num == 4 && wt == 0:
			cached = x != 0
		case num == 5 && wt == 2:
			started = true
		case num == 7 && wt == 2:
			verr = string(v)
		}
		return nil
	})
	if digest == "" {
		return
	}
	if (started || cached) && !t.started[digest] {
		t.started[digest] = true
		t.emit(digest, name)
	}
	if cached && !t.cached[digest] {
		t.cached[digest] = true
		t.emit(digest, "CACHED")
	}
	if verr != "" && !t.failed[digest] {
		t.failed[digest] = true
		t.flushVertex(digest)
		t.emit(digest, "ERROR: "+verr)
	}
}

func (t *traceLog) vertexLog(b []byte) {
	var digest string
	var msg []byte
	_ = eachField(b, func(num int, wt byte, v []byte, _ uint64) error {
		switch {
		case num == 1 && wt == 2:
			digest = string(v)
		case num == 4 && wt == 2:
			msg = v
		}
		return nil
	})
	if digest == "" || len(msg) == 0 {
		return
	}
	p := t.partial[digest]
	if p == nil {
		p = &strings.Builder{}
		t.partial[digest] = p
		t.order = append(t.order, digest)
	}
	p.Write(msg)
	text := strings.ReplaceAll(p.String(), "\r\n", "\n")
	for {
		i := strings.IndexAny(text, "\n\r")
		if i < 0 {
			break
		}
		if line := text[:i]; strings.TrimSpace(line) != "" {
			t.emit(digest, line)
		}
		text = text[i+1:]
	}
	p.Reset()
	if len(text) > traceLineMax*4 { // a single huge line: show it cut
		t.emit(digest, text)
		text = ""
	}
	p.WriteString(text)
}

func (t *traceLog) warning(b []byte) {
	var digest, short string
	_ = eachField(b, func(num int, wt byte, v []byte, _ uint64) error {
		switch {
		case num == 1 && wt == 2:
			digest = string(v)
		case num == 3 && wt == 2:
			short = string(v)
		}
		return nil
	})
	if short != "" {
		t.emit(digest, "WARN: "+short)
	}
}

func (t *traceLog) flushVertex(digest string) {
	if p := t.partial[digest]; p != nil && strings.TrimSpace(p.String()) != "" {
		t.emit(digest, p.String())
		p.Reset()
	}
}

// flush writes what is left of unfinished lines.
func (t *traceLog) flush() {
	for _, d := range t.order {
		t.flushVertex(d)
	}
}

var errProto = errors.New("malformed protobuf")

// eachField walks a protobuf message: fn gets the field number, the wire
// type, and the bytes (length-delimited) or the value (varint).
func eachField(b []byte, fn func(num int, wt byte, v []byte, x uint64) error) error {
	for len(b) > 0 {
		key, n := binary.Uvarint(b)
		if n <= 0 {
			return errProto
		}
		b = b[n:]
		num, wt := int(key>>3), byte(key&7)
		switch wt {
		case 0:
			x, n := binary.Uvarint(b)
			if n <= 0 {
				return errProto
			}
			b = b[n:]
			if err := fn(num, wt, nil, x); err != nil {
				return err
			}
		case 1:
			if len(b) < 8 {
				return errProto
			}
			b = b[8:]
		case 2:
			l, n := binary.Uvarint(b)
			if n <= 0 || l > uint64(len(b)-n) { //nolint:gosec // len-n is never negative here
				return errProto
			}
			end := n + int(l) //nolint:gosec // l <= len(b) was checked above
			v := b[n:end]
			b = b[end:]
			if err := fn(num, wt, v, 0); err != nil {
				return err
			}
		case 5:
			if len(b) < 4 {
				return errProto
			}
			b = b[4:]
		default:
			return errProto
		}
	}
	return nil
}
