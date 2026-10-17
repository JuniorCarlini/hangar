package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Listed is an object as a bucket listing returns it.
type Listed struct {
	Key          string // without the target's prefix
	Size         int64
	LastModified time.Time
}

// Plan is what a point-in-time restore needs: one base backup and the WAL
// files after it.
type Plan struct {
	Base    Listed
	BaseObj Object
	WAL     []Listed // segments and .history files, in order
	Target  time.Time
	// ToEnd replays every WAL file available instead of stopping at Target:
	// nothing was archived after Target yet, so the newest data is all
	// there is (and PostgreSQL refuses a target past the last record).
	ToEnd bool
}

// ErrNoBase means there is no base backup taken before the requested time.
var ErrNoBase = errors.New("archive: no base backup before that moment")

// PlanRecovery chooses the newest base backup finished before at and the
// WAL files needed to replay from it. objs are the keys under the
// service's WAL prefix.
func PlanRecovery(objs []Listed, at time.Time) (Plan, error) {
	var bases []Listed
	var basesObj []Object
	var wal []Listed
	var walObj []Object
	for _, l := range objs {
		o, ok := ParseKey(l.Key)
		if !ok {
			continue
		}
		switch o.Kind {
		case KindBase:
			// The upload time is when the copy was complete: a base finished
			// after at cannot be used to go back to at.
			if !l.LastModified.After(at) {
				bases = append(bases, l)
				basesObj = append(basesObj, o)
			}
		case KindWAL:
			wal = append(wal, l)
			walObj = append(walObj, o)
		}
	}
	if len(bases) == 0 {
		return Plan{}, ErrNoBase
	}
	best := 0
	for i := range bases {
		if bases[i].LastModified.After(bases[best].LastModified) {
			best = i
		}
	}
	p := Plan{Base: bases[best], BaseObj: basesObj[best], Target: at, ToEnd: true}
	start := p.BaseObj.StartSegment[8:]
	for i, l := range wal {
		name := walObj[i].Name
		switch {
		case strings.HasSuffix(name, ".history"):
			p.WAL = append(p.WAL, l)
		case len(name) == 24 && name[8:] >= start:
			p.WAL = append(p.WAL, l)
			if l.LastModified.After(at) {
				// Something was archived after the target, so the target
				// lies inside the available WAL: stop there.
				p.ToEnd = false
			}
		}
	}
	sort.Slice(p.WAL, func(i, j int) bool { return walName(p.WAL[i].Key) < walName(p.WAL[j].Key) })
	return p, nil
}

func walName(key string) string {
	o, _ := ParseKey(key)
	return o.Name
}

// RestoreWALDir is where a restore stages WAL files, relative to PGDATA
// (restore_command runs inside the data directory).
const RestoreWALDir = "hangar-restore-wal"

// RecoverySettings are appended to postgresql.auto.conf of a restored data
// directory, together with an empty recovery.signal.
func RecoverySettings(p Plan) string {
	var b strings.Builder
	b.WriteString("\n# Added by Hangar for a point-in-time restore.\n")
	b.WriteString("restore_command = 'cp " + RestoreWALDir + "/%f \"%p\"'\n")
	if !p.ToEnd {
		b.WriteString("recovery_target_time = '" + p.Target.UTC().Format("2006-01-02 15:04:05") + "+00'\n")
	}
	b.WriteString("recovery_target_action = 'promote'\n")
	return b.String()
}

var startWALRE = regexp.MustCompile(`START WAL LOCATION: [0-9A-F]+/[0-9A-F]+ \(file ([0-9A-F]{24})\)`)

// StartSegment reads the first WAL segment a base backup needs from its
// backup_label.
func StartSegment(label []byte) (string, error) {
	m := startWALRE.FindSubmatch(label)
	if m == nil {
		return "", errors.New("archive: backup_label without a start WAL location")
	}
	return string(m[1]), nil
}

// BaseInfo is what checking a base backup stream found.
type BaseInfo struct {
	StartSegment string
	Files        int
}

// CheckBase copies a base backup tar from r to w, checking every entry and
// that it is a real PostgreSQL data directory (PG_VERSION, backup_label).
func CheckBase(r io.Reader, w io.Writer) (BaseInfo, error) {
	var info BaseInfo
	tw := tar.NewWriter(w)
	hasVersion := false
	err := CopyTar(tw, tar.NewReader(r), DefaultTarLimits, func(name string, body io.Reader) ([]byte, bool, error) {
		info.Files++
		switch name {
		case "PG_VERSION":
			hasVersion = true
		case "backup_label":
			label, err := io.ReadAll(io.LimitReader(body, 64<<10))
			if err != nil {
				return nil, false, err
			}
			seg, err := StartSegment(label)
			if err != nil {
				return nil, false, err
			}
			info.StartSegment = seg
			return label, true, nil
		}
		return nil, false, nil
	})
	if err != nil {
		return info, err
	}
	if err := tw.Close(); err != nil {
		return info, err
	}
	if !hasVersion || info.StartSegment == "" {
		return info, fmt.Errorf("archive: base backup is incomplete (PG_VERSION or backup_label missing)")
	}
	return info, nil
}
