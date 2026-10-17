package archive

import (
	"regexp"
	"strings"
	"time"
)

// Object kinds, as recorded in backup_runs.kind.
const (
	KindDump  = "pg_dump"
	KindBase  = "pg_base"
	KindWAL   = "wal"
	KindPanel = "panel"
)

// Retention classes. Each has its own folder so the bucket's lifecycle
// rules (not the server, whose credential cannot delete) expire them.
const (
	ClassDaily   = "daily"
	ClassWeekly  = "weekly"
	ClassMonthly = "monthly"
)

// Folders in the bucket (docs/09): diario/ semanal/ mensal/ wal/ painel/.
var classFolder = map[string]string{
	ClassDaily: "diario", ClassWeekly: "semanal", ClassMonthly: "mensal",
}

const (
	folderWAL   = "wal"
	folderPanel = "painel"
)

// DefaultRetentionDays is how long each folder is kept by the suggested
// lifecycle rules. WAL is kept a little longer than a week so any minute of
// the last 7 days can be restored from a base backup of the same week.
var DefaultRetentionDays = map[string]int{
	"diario": 7, "semanal": 35, "mensal": 400, folderWAL: 9, folderPanel: 35,
}

// Folders lists the bucket folders in display order.
var Folders = []string{"diario", "semanal", "mensal", folderWAL, folderPanel}

// TimeFormat is the timestamp in object names (UTC, sortable).
const TimeFormat = "20060102T150405Z"

// Extensions by content.
const (
	ExtDump = ".dump.age"
	ExtTar  = ".tar.zst.age"
	ExtWAL  = ".zst.age"
)

// FolderOf returns the folder a retention class lives in.
func FolderOf(class string) string { return classFolder[class] }

// DumpKey names a logical (pg_dump) backup.
func DumpKey(class, project, service string, t time.Time) string {
	return classFolder[class] + "/" + project + "/" + service + "/" + t.UTC().Format(TimeFormat) + ExtDump
}

// BaseKey names a base backup (physical copy for point-in-time recovery).
// startSegment is the first WAL segment it needs.
func BaseKey(project, service string, t time.Time, startSegment string) string {
	return folderWAL + "/" + project + "/" + service + "/base/" + t.UTC().Format(TimeFormat) + "_" + startSegment + ExtTar
}

// WALPrefix is where a service's WAL and base backups live.
func WALPrefix(project, service string) string {
	return folderWAL + "/" + project + "/" + service + "/"
}

// WALKey names an archived WAL file (segment, .history or .backup).
func WALKey(project, service, name string) string {
	return WALPrefix(project, service) + "seg/" + name + ExtWAL
}

// PanelKey names a backup of the panel itself.
func PanelKey(t time.Time) string {
	return folderPanel + "/" + t.UTC().Format(TimeFormat) + ExtTar
}

// PanelPrefix is where panel backups live.
const PanelPrefix = folderPanel + "/"

// Object is what a key says about a backup.
type Object struct {
	Key     string
	Kind    string
	Class   string // dumps only
	Project string
	Service string
	Time    time.Time
	// Name is the WAL file name (WAL objects only).
	Name string
	// StartSegment is the first WAL segment a base backup needs.
	StartSegment string
}

var (
	slugPart  = `[a-z][a-z0-9-]{0,30}[a-z0-9]`
	tsPart    = `[0-9]{8}T[0-9]{6}Z`
	dumpKeyRE = regexp.MustCompile(`^(diario|semanal|mensal)/(` + slugPart + `)/(` + slugPart + `)/(` + tsPart + `)\.dump\.age$`)
	baseKeyRE = regexp.MustCompile(`^wal/(` + slugPart + `)/(` + slugPart + `)/base/(` + tsPart + `)_([0-9A-F]{24})\.tar\.zst\.age$`)
	walKeyRE  = regexp.MustCompile(`^wal/(` + slugPart + `)/(` + slugPart + `)/seg/(` + WALNamePattern + `)\.zst\.age$`)
	panelRE   = regexp.MustCompile(`^painel/(` + tsPart + `)\.tar\.zst\.age$`)
)

// WALNamePattern matches the files PostgreSQL archives: segments,
// timeline history and backup history files.
const WALNamePattern = `[0-9A-F]{24}|[0-9A-F]{8}\.history|[0-9A-F]{24}\.[0-9A-F]{8}\.backup`

// WALNameRE validates a WAL file name taken from the archive outbox: only
// these names ever reach a command or an object key.
var WALNameRE = regexp.MustCompile(`^(` + WALNamePattern + `)$`)

var folderClass = map[string]string{"diario": ClassDaily, "semanal": ClassWeekly, "mensal": ClassMonthly}

// ParseKey reads a key (without the target's prefix). ok is false for
// anything that is not a Hangar backup.
func ParseKey(key string) (Object, bool) {
	if m := dumpKeyRE.FindStringSubmatch(key); m != nil {
		t, err := time.Parse(TimeFormat, m[4])
		return Object{Key: key, Kind: KindDump, Class: folderClass[m[1]], Project: m[2], Service: m[3], Time: t}, err == nil
	}
	if m := baseKeyRE.FindStringSubmatch(key); m != nil {
		t, err := time.Parse(TimeFormat, m[3])
		return Object{Key: key, Kind: KindBase, Project: m[1], Service: m[2], Time: t, StartSegment: m[4]}, err == nil
	}
	if m := walKeyRE.FindStringSubmatch(key); m != nil {
		return Object{Key: key, Kind: KindWAL, Project: m[1], Service: m[2], Name: m[3]}, true
	}
	if m := panelRE.FindStringSubmatch(key); m != nil {
		t, err := time.Parse(TimeFormat, m[1])
		return Object{Key: key, Kind: KindPanel, Time: t}, err == nil
	}
	return Object{}, false
}

// LocalName is the file name used when a backup is saved on a computer:
// the key with folders flattened is unique and still readable.
func LocalName(key string) string {
	return strings.ReplaceAll(key, "/", "_")
}
