// Package backup runs Hangar's backups (docs/09): logical dumps tested in
// a throwaway database before they leave, continuous WAL for restoring any
// minute, the panel itself with its master key, and restores. Everything
// is encrypted with age to the operator's public keys and sent to
// S3-compatible buckets with Object Lock, through a credential that cannot
// delete.
package backup

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/secrets"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// Errors the UI translates.
var (
	ErrNotReady    = &i18n.Error{Key: "backup.error.not_ready"}
	ErrUnsupported = &i18n.Error{Key: "backup.error.unsupported"}
	ErrNotRunning  = &i18n.Error{Key: "backup.error.not_running"}
	ErrBusy        = &i18n.Error{Key: "backup.error.busy"}
	ErrNoDocker    = &i18n.Error{Key: "error.docker_unavailable"}
)

// Options configure the Manager.
type Options struct {
	// StagingDir holds encrypted files between creation and upload
	// (0700). Plaintext never lands here: dumps are encrypted on the way.
	StagingDir string
	// AllowPrivateEndpoints lets a destination live on a private address
	// (a MinIO in the lab). Off in production: anti-SSRF (docs/17).
	AllowPrivateEndpoints bool
	// Panel backup inputs.
	DBPath        string
	MasterKeyFile string
	ConfigFile    string
	CertsDir      string
	Version       string
}

// Manager is the backup engine.
type Manager struct {
	db       *sql.DB
	q        *dbq.Queries
	box      *secrets.Box
	projects *projects.Manager
	audit    *audit.Logger
	log      *slog.Logger
	opt      Options
	now      func() time.Time
	// openStore builds the client of a destination (tests swap it).
	openStore func(TargetConfig) (ObjectStore, error)

	locksMu sync.Mutex
	locks   map[string]*sync.Mutex
	jobs    chan job
	wg      sync.WaitGroup

	dlMu      sync.Mutex
	downloads map[string]*download

	walMu   sync.Mutex
	walSeen map[string]time.Time // outbox file -> first seen

	alertMu sync.Mutex
	alertN  int
	alertAt time.Time
}

// New creates the Manager.
func New(db *sql.DB, box *secrets.Box, pm *projects.Manager, al *audit.Logger, log *slog.Logger, opt Options) (*Manager, error) {
	if opt.StagingDir == "" {
		return nil, errors.New("backup: staging dir required")
	}
	if err := os.MkdirAll(opt.StagingDir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: staging dir: %w", err)
	}
	m := &Manager{
		db: db, q: dbq.New(db), box: box, projects: pm, audit: al, log: log, opt: opt, now: time.Now,
		locks: map[string]*sync.Mutex{}, jobs: make(chan job, 64),
		downloads: map[string]*download{}, walSeen: map[string]time.Time{},
	}
	m.openStore = m.defaultStore
	return m, nil
}

// Actor is who is acting, for the audit log.
type Actor = projects.Actor

// System is the scheduler acting on its own.
var System = Actor{}

func (m *Manager) record(ctx context.Context, a Actor, action, targetType, targetID string, outcome audit.Outcome, summary map[string]any) {
	if m.audit == nil {
		return
	}
	if err := m.audit.Record(context.WithoutCancel(ctx), audit.Entry{
		ActorID: a.UserID, IP: a.IP, Action: action, Outcome: outcome,
		TargetType: targetType, TargetID: targetID, Summary: summary,
	}); err != nil {
		m.log.Error("audit backup action", "action", action, "error", err)
	}
}

func outcomeOf(err error) audit.Outcome {
	if err != nil {
		return audit.Error
	}
	return audit.OK
}

// lock serializes work on one service (dump, base backup, restore).
func (m *Manager) lock(label string) func() {
	m.locksMu.Lock()
	l, ok := m.locks[label]
	if !ok {
		l = &sync.Mutex{}
		m.locks[label] = l
	}
	m.locksMu.Unlock()
	l.Lock()
	return l.Unlock
}

// tryLock is lock without waiting.
func (m *Manager) tryLock(label string) (func(), bool) {
	m.locksMu.Lock()
	l, ok := m.locks[label]
	if !ok {
		l = &sync.Mutex{}
		m.locks[label] = l
	}
	m.locksMu.Unlock()
	if !l.TryLock() {
		return nil, false
	}
	return l.Unlock, true
}

func (m *Manager) tasker() (node.Node, node.Tasker, error) {
	n := m.projects.Node()
	if n == nil {
		return nil, nil, ErrNoDocker
	}
	t, ok := n.(node.Tasker)
	if !ok {
		return nil, nil, ErrNoDocker
	}
	return n, t, nil
}

// --- recipients (the recovery kit's public keys) ------------------------------

// Recipient is a public key of a recovery kit.
type Recipient struct {
	ID        string
	Label     string
	PublicKey string
	Confirmed bool
	CreatedAt time.Time
}

// Recipients lists the kit keys.
func (m *Manager) Recipients(ctx context.Context) ([]Recipient, error) {
	rows, err := m.q.ListBackupRecipients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Recipient, 0, len(rows))
	for _, r := range rows {
		out = append(out, Recipient{ID: r.ID, Label: r.Label, PublicKey: r.AgePublicKey, Confirmed: r.ConfirmedAt.Valid, CreatedAt: time.Unix(r.CreatedAt, 0)})
	}
	return out, nil
}

// AddRecipient stores the public key of a kit generated in the browser,
// with the hash of its confirmation code. It only counts once confirmed.
func (m *Manager) AddRecipient(ctx context.Context, a Actor, label, publicKey, codeHash string) (string, error) {
	if label == "" || len(label) > 60 {
		return "", i18n.E("backup.error.label")
	}
	if _, err := age.ParseX25519Recipient(publicKey); err != nil {
		return "", i18n.E("backup.error.public_key")
	}
	if len(codeHash) != 64 {
		return "", i18n.E("backup.error.public_key")
	}
	id := ids.New("bkk_")
	if err := m.q.CreateBackupRecipient(ctx, dbq.CreateBackupRecipientParams{
		ID: id, Label: label, AgePublicKey: publicKey, ConfirmHash: codeHash,
		CreatedBy: nullStr(a.UserID), CreatedAt: m.now().Unix(),
	}); err != nil {
		return "", i18n.E("backup.error.key_exists")
	}
	m.record(ctx, a, "backup.key.add", "backup_recipient", id, audit.OK, map[string]any{"label": label, "public_key": publicKey})
	return id, nil
}

// ConfirmRecipient checks the code typed back from the kit (docs/09: the
// panel only turns backups on after you prove you kept the kit).
func (m *Manager) ConfirmRecipient(ctx context.Context, a Actor, id, code string) error {
	r, err := m.q.GetBackupRecipient(ctx, id)
	if err != nil {
		return projects.ErrNotFound
	}
	if archive.CodeHash(code) != r.ConfirmHash {
		m.record(ctx, a, "backup.key.confirm", "backup_recipient", id, audit.Denied, map[string]any{"reason": "wrong_code"})
		return i18n.E("backup.error.code")
	}
	if err := m.q.ConfirmBackupRecipient(ctx, dbq.ConfirmBackupRecipientParams{ConfirmedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, ID: id}); err != nil {
		return err
	}
	m.record(ctx, a, "backup.key.confirm", "backup_recipient", id, audit.OK, map[string]any{"label": r.Label})
	return nil
}

// DeleteRecipient removes a kit key. The last confirmed key cannot go:
// backups would have nobody to encrypt to.
func (m *Manager) DeleteRecipient(ctx context.Context, a Actor, id string) error {
	rs, err := m.Recipients(ctx)
	if err != nil {
		return err
	}
	confirmed, target := 0, Recipient{}
	for _, r := range rs {
		if r.Confirmed {
			confirmed++
		}
		if r.ID == id {
			target = r
		}
	}
	if target.ID == "" {
		return projects.ErrNotFound
	}
	if target.Confirmed && confirmed == 1 {
		return i18n.E("backup.error.last_key")
	}
	if _, err := m.q.DeleteBackupRecipient(ctx, id); err != nil {
		return err
	}
	m.record(ctx, a, "backup.key.remove", "backup_recipient", id, audit.OK, map[string]any{"label": target.Label})
	return nil
}

// recipients are the confirmed public keys every backup is encrypted to.
func (m *Manager) recipients(ctx context.Context) ([]age.Recipient, error) {
	rs, err := m.Recipients(ctx)
	if err != nil {
		return nil, err
	}
	var keys []string
	for _, r := range rs {
		if r.Confirmed {
			keys = append(keys, r.PublicKey)
		}
	}
	if len(keys) == 0 {
		return nil, ErrNotReady
	}
	return archive.ParseRecipients(keys)
}

// Ready reports whether backups can run: a confirmed kit key and a
// destination.
func (m *Manager) Ready(ctx context.Context) bool {
	if _, err := m.recipients(ctx); err != nil {
		return false
	}
	ts, err := m.q.ListBackupTargets(ctx)
	return err == nil && len(ts) > 0
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: s != ""} }

// stagingFile creates an encrypted-output file in the staging dir.
func (m *Manager) stagingFile(pattern string) (*os.File, error) {
	return os.CreateTemp(m.opt.StagingDir, pattern)
}

func removeFile(f *os.File) {
	if f == nil {
		return
	}
	_ = f.Close()
	_ = os.Remove(f.Name())
}

// cleanStaging removes leftovers of a previous run (a crash mid-backup).
func (m *Manager) cleanStaging() {
	entries, err := os.ReadDir(m.opt.StagingDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(m.opt.StagingDir, e.Name()))
	}
}
