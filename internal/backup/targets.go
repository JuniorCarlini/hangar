package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/s3"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/ids"
	"github.com/JuniorCarlini/hangar/internal/netguard"
	"github.com/JuniorCarlini/hangar/internal/projects"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
)

// ObjectStore is what a destination must do (s3.Client in production).
type ObjectStore interface {
	Put(ctx context.Context, key string, f s3.File, size int64, o s3.PutOptions) error
	Head(ctx context.Context, key string) (s3.ObjectInfo, error)
	Get(ctx context.Context, key string) (io.ReadCloser, s3.ObjectInfo, error)
	List(ctx context.Context, prefix string, fn func(s3.ObjectInfo) error) error
	Delete(ctx context.Context, key, versionID string) error
	PresignGet(key string, expires time.Duration) string
}

// TargetConfig is the encrypted part of a destination.
type TargetConfig struct {
	Endpoint  string `json:"endpoint"`
	Region    string `json:"region"`
	Bucket    string `json:"bucket"`
	Prefix    string `json:"prefix"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
	PathStyle bool   `json:"path_style"`
}

// Providers the form knows (hints and defaults only).
var Providers = []string{"b2", "wasabi", "aws", "r2", "custom"}

var (
	bucketRE = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	regionRE = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)
	prefixRE = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]{0,62}/){0,4}$`)
	nameRE   = regexp.MustCompile(`^[\p{L}\p{N} ._()-]{1,60}$`)
)

// TargetInput is the destination form.
type TargetInput struct {
	Name     string
	Provider string
	Config   TargetConfig
	LockMode string
	LockDays int
	Primary  bool
}

// Target is a destination as the UI shows it (never the credential).
type Target struct {
	ID         string
	Name       string
	Provider   string
	Endpoint   string
	Bucket     string
	Prefix     string
	LockMode   string
	LockDays   int
	Primary    bool
	CheckedAt  time.Time
	CheckError string
}

type target struct {
	Target
	store ObjectStore
}

func targetAD(id string) string { return "backup_targets|" + id + "|config" }

func (m *Manager) defaultStore(c TargetConfig) (ObjectStore, error) {
	if _, err := netguard.CheckURL(c.Endpoint, m.opt.AllowPrivateEndpoints); err != nil {
		return nil, i18n.E("backup.error.endpoint")
	}
	return s3.New(s3.Config{
		Endpoint: c.Endpoint, Region: c.Region, Bucket: c.Bucket,
		AccessKey: c.AccessKey, SecretKey: c.SecretKey, PathStyle: c.PathStyle,
	}, netguard.Client(m.opt.AllowPrivateEndpoints, 30*time.Minute))
}

func (in *TargetInput) validate() error {
	in.Name = strings.TrimSpace(in.Name)
	c := &in.Config
	c.Endpoint = strings.TrimRight(strings.TrimSpace(c.Endpoint), "/")
	c.Bucket, c.Region = strings.TrimSpace(c.Bucket), strings.TrimSpace(c.Region)
	c.AccessKey, c.SecretKey = strings.TrimSpace(c.AccessKey), strings.TrimSpace(c.SecretKey)
	c.Prefix = strings.Trim(strings.TrimSpace(c.Prefix), "/")
	if c.Prefix != "" {
		c.Prefix += "/"
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	switch {
	case !nameRE.MatchString(in.Name):
		return i18n.E("backup.error.target_name")
	case !bucketRE.MatchString(c.Bucket):
		return i18n.E("backup.error.bucket")
	case !regionRE.MatchString(c.Region):
		return i18n.E("backup.error.region")
	case !prefixRE.MatchString(c.Prefix):
		return i18n.E("backup.error.prefix")
	case c.AccessKey == "" || c.SecretKey == "" || len(c.AccessKey) > 256 || len(c.SecretKey) > 256:
		return i18n.E("backup.error.credentials")
	case in.LockMode != s3.Compliance && in.LockMode != s3.Governance:
		return i18n.E("backup.error.lock_mode")
	case in.LockDays < 1 || in.LockDays > 3650:
		return i18n.E("backup.error.lock_days")
	}
	valid := false
	for _, p := range Providers {
		valid = valid || p == in.Provider
	}
	if !valid {
		in.Provider = "custom"
	}
	return nil
}

// AddTarget checks the destination for real (docs/09) and saves it only
// when it passes: writes with a lock, reads back, and refuses a credential
// that can delete.
func (m *Manager) AddTarget(ctx context.Context, a Actor, in TargetInput) (string, error) {
	if err := in.validate(); err != nil {
		return "", err
	}
	store, err := m.openStore(in.Config)
	if err != nil {
		return "", err
	}
	if err := checkStore(ctx, store, in.Config.Prefix, in.LockMode, m.now()); err != nil {
		m.record(ctx, a, "backup.target.add", "backup_target", "", audit.Denied, map[string]any{"name": in.Name, "reason": err.Error()})
		return "", err
	}
	id := ids.New("bkt_")
	raw, _ := json.Marshal(in.Config) //nolint:gosec // sealed with the master key on the next line, never stored in clear
	sealed, err := m.box.Seal(raw, targetAD(id))
	if err != nil {
		return "", err
	}
	existing, err := m.q.ListBackupTargets(ctx)
	if err != nil {
		return "", err
	}
	primary := int64(0)
	if in.Primary || len(existing) == 0 {
		primary = 1
	}
	now := m.now().Unix()
	if err := m.q.CreateBackupTarget(ctx, dbq.CreateBackupTargetParams{
		ID: id, Name: in.Name, Provider: in.Provider, ConfigEnc: sealed, LockMode: in.LockMode,
		ObjectLockDays: int64(in.LockDays), IsPrimary: primary, CheckedAt: sql.NullInt64{Int64: now, Valid: true},
		CreatedBy: nullStr(a.UserID), CreatedAt: now,
	}); err != nil {
		return "", err
	}
	m.record(ctx, a, "backup.target.add", "backup_target", id, audit.OK, map[string]any{
		"name": in.Name, "provider": in.Provider, "bucket": in.Config.Bucket, "lock_mode": in.LockMode, "lock_days": in.LockDays,
	})
	m.ensurePanelPolicy(ctx)
	return id, nil
}

// checkStore proves what docs/09 relies on, with a small probe object.
func checkStore(ctx context.Context, store ObjectStore, prefix, mode string, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	key := prefix + "hangar-check/" + now.UTC().Format(archive.TimeFormat) + "-" + ids.New("") + ".txt"
	body := []byte("hangar backup destination check\n")
	sum := sha256.Sum256(body)
	err := store.Put(ctx, key, bytes.NewReader(body), int64(len(body)), s3.PutOptions{
		LockMode: mode, RetainUntil: now.Add(24 * time.Hour),
		Metadata: map[string]string{"hangar-sha256": hex.EncodeToString(sum[:])},
	})
	if err != nil {
		var se *s3.Error
		if errors.As(err, &se) && (se.Code == "InvalidRequest" || strings.Contains(strings.ToLower(se.Message), "lock")) {
			return i18n.E("backup.error.no_object_lock")
		}
		if s3.IsAccessDenied(err) {
			return i18n.E("backup.error.cannot_write")
		}
		return i18n.E("backup.error.unreachable", "error", err.Error())
	}
	info, err := store.Head(ctx, key)
	if err != nil {
		return i18n.E("backup.error.cannot_read", "error", err.Error())
	}
	if !strings.EqualFold(info.LockMode, mode) {
		return i18n.E("backup.error.no_object_lock")
	}
	rc, _, err := store.Get(ctx, key)
	if err != nil {
		return i18n.E("backup.error.cannot_read", "error", err.Error())
	}
	got, _ := io.ReadAll(io.LimitReader(rc, 1<<10))
	_ = rc.Close()
	if !bytes.Equal(got, body) {
		return i18n.E("backup.error.cannot_read", "error", "content differs")
	}
	// The credential must not be able to delete: that is the ransomware
	// protection. What counts is removing a version for good. A delete
	// without a version only adds a delete marker, which leaves the locked
	// version in place, and B2 lets any key that can write do it
	// (b2_hide_file needs only writeFiles), so it cannot be the test. A
	// locked version is no probe either: the lock refuses its deletion
	// whatever the credential. So a second, unlocked file is deleted by its
	// version id, and that has to be refused.
	vkey := strings.TrimSuffix(key, ".txt") + "-version.txt"
	if err := store.Put(ctx, vkey, bytes.NewReader(body), int64(len(body)), s3.PutOptions{}); err != nil {
		return i18n.E("backup.error.unreachable", "error", err.Error())
	}
	vinfo, err := store.Head(ctx, vkey)
	if err != nil {
		return i18n.E("backup.error.cannot_read", "error", err.Error())
	}
	if err := store.Delete(ctx, vkey, vinfo.VersionID); err == nil {
		return i18n.E("backup.error.can_delete")
	} else if !s3.IsAccessDenied(err) {
		return i18n.E("backup.error.unreachable", "error", err.Error())
	}
	return nil
}

// CheckTarget runs the destination check again (button "testar").
func (m *Manager) CheckTarget(ctx context.Context, a Actor, id string) error {
	t, err := m.target(ctx, id)
	if err != nil {
		return err
	}
	cerr := checkStore(ctx, t.store, t.Prefix, t.LockMode, m.now())
	msg := ""
	if cerr != nil {
		msg = i18n.Message("en", cerr)
	}
	_ = m.q.SetBackupTargetCheck(ctx, dbq.SetBackupTargetCheckParams{CheckedAt: sql.NullInt64{Int64: m.now().Unix(), Valid: true}, CheckError: msg, ID: id})
	m.record(ctx, a, "backup.target.check", "backup_target", id, outcomeOf(cerr), map[string]any{"name": t.Name})
	return cerr
}

// DeleteTarget forgets a destination (what is in the bucket stays there).
func (m *Manager) DeleteTarget(ctx context.Context, a Actor, id string) error {
	t, err := m.q.GetBackupTarget(ctx, id)
	if err != nil {
		return projects.ErrNotFound
	}
	if _, err := m.q.DeleteBackupTarget(ctx, id); err != nil {
		return err
	}
	m.record(ctx, a, "backup.target.remove", "backup_target", id, audit.OK, map[string]any{"name": t.Name})
	return nil
}

// Targets lists the destinations for the UI.
func (m *Manager) Targets(ctx context.Context) ([]Target, error) {
	rows, err := m.q.ListBackupTargets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(rows))
	for _, r := range rows {
		t, err := m.toTarget(r, false)
		if err != nil {
			return nil, err
		}
		out = append(out, t.Target)
	}
	return out, nil
}

func (m *Manager) toTarget(r dbq.BackupTarget, open bool) (target, error) {
	plain, err := m.box.Open(r.ConfigEnc, targetAD(r.ID))
	if err != nil {
		return target{}, fmt.Errorf("destination %s: %w", r.Name, err)
	}
	var c TargetConfig
	if err := json.Unmarshal(plain, &c); err != nil {
		return target{}, err
	}
	t := target{Target: Target{
		ID: r.ID, Name: r.Name, Provider: r.Provider, Endpoint: c.Endpoint, Bucket: c.Bucket, Prefix: c.Prefix,
		LockMode: r.LockMode, LockDays: int(r.ObjectLockDays), Primary: r.IsPrimary == 1, CheckError: r.CheckError,
	}}
	if r.CheckedAt.Valid {
		t.CheckedAt = time.Unix(r.CheckedAt.Int64, 0)
	}
	if open {
		if t.store, err = m.openStore(c); err != nil {
			return target{}, err
		}
	}
	return t, nil
}

func (m *Manager) target(ctx context.Context, id string) (target, error) {
	r, err := m.q.GetBackupTarget(ctx, id)
	if err != nil {
		return target{}, projects.ErrNotFound
	}
	return m.toTarget(r, true)
}

// targets opens every destination, the primary first.
func (m *Manager) targets(ctx context.Context) ([]target, error) {
	rows, err := m.q.ListBackupTargets(ctx)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotReady
	}
	out := make([]target, 0, len(rows))
	for _, r := range rows {
		t, err := m.toTarget(r, true)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// upload is how one destination took a file.
type upload struct {
	Target string `json:"target"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
}

// lockUntil is how long a new object stays locked: the destination's lock
// period, but never longer than its folder is kept (a daily backup does
// not need a 30-day lock to expire after 7).
func lockUntil(t target, folder string, now time.Time) time.Time {
	days := t.LockDays
	if keep := archive.DefaultRetentionDays[folder]; keep > 0 && keep < days {
		days = keep
	}
	return now.Add(time.Duration(days) * 24 * time.Hour)
}

// sendFile uploads the staged file to every destination and checks each
// copy (size and SHA-256 recorded in its metadata).
func (m *Manager) sendFile(ctx context.Context, ts []target, key, folder string, f s3.File, size int64, sha string, meta map[string]string) ([]upload, error) {
	md := map[string]string{"hangar-sha256": sha}
	for k, v := range meta {
		md[k] = v
	}
	var ups []upload
	var errs []error
	for _, t := range ts {
		err := t.store.Put(ctx, t.Prefix+key, f, size, s3.PutOptions{LockMode: t.LockMode, RetainUntil: lockUntil(t, folder, m.now()), Metadata: md})
		if err == nil {
			var info s3.ObjectInfo
			if info, err = t.store.Head(ctx, t.Prefix+key); err == nil && (info.Size != size || info.Metadata["hangar-sha256"] != sha) {
				err = fmt.Errorf("the copy in %s does not match (size %d, want %d)", t.Name, info.Size, size)
			}
		}
		u := upload{Target: t.Name, OK: err == nil}
		if err != nil {
			u.Error = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", t.Name, err))
		}
		ups = append(ups, u)
	}
	return ups, errors.Join(errs...)
}

// fetch opens key from the first destination that has it.
func (m *Manager) fetch(ctx context.Context, key string) (io.ReadCloser, s3.ObjectInfo, error) {
	ts, err := m.targets(ctx)
	if err != nil {
		return nil, s3.ObjectInfo{}, err
	}
	var errs []error
	for _, t := range ts {
		rc, info, err := t.store.Get(ctx, t.Prefix+key)
		if err == nil {
			return rc, info, nil
		}
		errs = append(errs, err)
	}
	return nil, s3.ObjectInfo{}, errors.Join(errs...)
}

// list lists prefix in the first destination that answers.
func (m *Manager) list(ctx context.Context, prefix string) ([]archive.Listed, error) {
	ts, err := m.targets(ctx)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, t := range ts {
		var out []archive.Listed
		err := t.store.List(ctx, t.Prefix+prefix, func(o s3.ObjectInfo) error {
			out = append(out, archive.Listed{Key: strings.TrimPrefix(o.Key, t.Prefix), Size: o.Size, LastModified: o.LastModified})
			return nil
		})
		if err == nil {
			return out, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}
