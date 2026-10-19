package projects

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/JuniorCarlini/hangar/internal/audit"
	"github.com/JuniorCarlini/hangar/internal/i18n"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/store/dbq"
	"github.com/JuniorCarlini/hangar/internal/volumes"
)

// Size limits on volumes (docs/05, internal/volumes). By default a volume
// has none: it grows on the server's disk and the panel shows how much it
// uses. With a limit, its files live in a disk image of that size; the
// panel writes what it wants (desired.json) and the root unit
// hangar-volumes does it, answering in applied.json. The panel drives the
// rest itself: it stops the services that mount the volume while its data
// is moved, switches the Docker volume to the image and starts them again.
//
// Each step is stored (volume_limits.state and step), so a panel restarted
// in the middle carries on where it was, and every step can run twice.

// Limit states (volume_limits.state).
const (
	limitNew     = "new"     // the volume did not exist: wait for the image
	limitActive  = "active"  // in place
	limitMigrate = "migrate" // existing data moves into the image
	limitUnlimit = "unlimit" // the data moves back to a plain volume
	limitRemove  = "remove"  // the image is deleted (the volume or service was)
	limitFailed  = "failed"  // could not be applied; error says why
)

// Steps of a migrate (mount, stop, import, switch) and an unlimit (stop,
// switch, export); a failed limit cleans its image up first.
const (
	stepMount   = "mount"
	stepStop    = "stop"
	stepImport  = "import"
	stepSwitch  = "switch"
	stepExport  = "export"
	stepCleanup = "cleanup"
)

// The unit has this long to answer before the panel says it is silent.
const unitPatience = 2 * time.Minute

// newVolumeWait is how long a deploy waits for a new limited volume's
// image to be ready.
const newVolumeWait = 3 * time.Minute

// volumePoll is how often a waiting deploy looks again.
var volumePoll = time.Second

// headroom is what a limit must leave free above the data it receives,
// and what must stay free on the server for a copy.
const headroom = 256 << 20

// ErrVolumeMoving refuses a deploy while a volume's data is moving.
var ErrVolumeMoving = &i18n.Error{Key: "service.error.volume_moving"}

// SetVolumeLimits connects the volume limits: w writes the desired state,
// usage reads a plain volume's bytes (by Docker name) from the last
// "docker system df". Without it, limits are not offered.
func (m *Manager) SetVolumeLimits(w *volumes.Writer, usage func(name string) (int64, bool)) {
	if usage == nil {
		usage = func(string) (int64, bool) { return 0, false }
	}
	m.vols, m.volUsage = w, usage
	m.volKick = make(chan struct{}, 1)
}

// VolumeLimitsAvailable reports whether limits can be set here: the root
// unit answered at least once and the node can switch volumes.
func (m *Manager) VolumeLimitsAvailable() bool {
	_, ok := m.node.(node.VolumeBinder)
	return ok && m.vols != nil && m.vols.Available()
}

func (m *Manager) kickVolumes() {
	if m.volKick == nil {
		return
	}
	select {
	case m.volKick <- struct{}{}:
	default:
	}
}

// VolumeLimit is a volume's limit as the panel shows it.
type VolumeLimit struct {
	Size  int64
	State string
	Error string
	// Used and Total are the filesystem inside the image (Total 0: not
	// measured yet).
	Used, Total uint64
	// Pending: the unit has not applied this size (or state) yet.
	Pending bool
	// Cleaned: a failed limit whose image is gone (its notice can go).
	Cleaned bool
}

// Busy reports whether the limit is changing (not yet in place, data
// moving, being removed).
func (l VolumeLimit) Busy() bool {
	return l.State != limitActive && l.State != limitFailed || l.Pending
}

// Moving reports whether the volume's data is being copied (the services
// that mount it are stopped meanwhile).
func (l VolumeLimit) Moving() bool { return l.State == limitMigrate || l.State == limitUnlimit }

// Active reports whether the limit is in place.
func (l VolumeLimit) Active() bool { return l.State == limitActive }

// Failed reports whether the limit could not be applied.
func (l VolumeLimit) Failed() bool { return l.State == limitFailed }

// limitOf reads the limit of the Docker volume name, if any.
func (m *Manager) limitOf(ctx context.Context, name string) (dbq.VolumeLimit, bool) {
	r, err := m.q.GetVolumeLimit(ctx, name)
	return r, err == nil
}

// volumeLimitView is what the disks tab shows of a limit.
func (m *Manager) volumeLimitView(r dbq.VolumeLimit, res map[string]volumes.Result, current bool) *VolumeLimit {
	v := &VolumeLimit{Size: r.SizeBytes, State: r.State, Error: r.Error, Cleaned: r.State == limitFailed && r.Step == ""}
	got, ok := res[r.Volume]
	if ok && got.Mounted {
		v.Used, v.Total = got.Used, got.Total
	}
	// Measured now when the panel sees the mount (it always should: the
	// unit mounts in the host's namespace, which the panel's follows).
	if mnt := m.vols.Paths.Mount(r.Volume); !volumes.SameDevice(mnt, m.vols.Paths.Mounts()) {
		if used, total, _, err := volumes.Statfs(mnt); err == nil {
			v.Used, v.Total = used, total
		}
	}
	if r.State == limitActive && (!current || !ok || !got.OK || got.Size < r.SizeBytes) {
		v.Pending = true
	}
	return v
}

// volumeDevice is the folder the Docker volume name binds to when it has
// a limit ("" for a plain volume).
func (m *Manager) volumeDevice(ctx context.Context, name string) string {
	if m.vols == nil {
		return ""
	}
	r, ok := m.limitOf(ctx, name)
	if !ok || (r.State != limitNew && r.State != limitActive) {
		return ""
	}
	return m.vols.Paths.Device(name)
}

// hostFree is the free space of the disk that holds the images.
func (m *Manager) hostFree() int64 {
	_, _, avail, err := volumes.Statfs(m.vols.Paths.Data)
	if err != nil {
		return 0
	}
	return int64(min(avail, 1<<62)) //nolint:gosec // bounded
}

// ownVolume finds a service's own volume by name.
func (m *Manager) ownVolume(ctx context.Context, s dbq.Service, name string) (dbq.ListVolumesRow, error) {
	rows, err := m.q.ListVolumes(ctx, s.ID)
	if err != nil {
		return dbq.ListVolumesRow{}, err
	}
	for _, v := range rows {
		if v.Name != name {
			continue
		}
		if v.OwnerSlug != "" {
			return v, i18n.E("volume.limit.error.owner", "service", v.OwnerSlug)
		}
		return v, nil
	}
	return dbq.ListVolumesRow{}, ErrNotFound
}

func gbText(b int64) string { return fmt.Sprintf("%d GB", (b+volumes.GiB-1)/volumes.GiB) }

// SetVolumeLimit limits a service's own volume to size bytes, or grows the
// limit it has. A volume that already holds data is moved into its image:
// the services that mount it stop for the copy and start again by
// themselves. A limit never shrinks.
func (m *Manager) SetVolumeLimit(ctx context.Context, a Actor, projectSlug, serviceSlug, name string, size int64) error {
	if !m.VolumeLimitsAvailable() {
		return i18n.E("volume.limit.error.unavailable")
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if _, err := m.ownVolume(ctx, s, name); err != nil {
		return err
	}
	if size < volumes.MinSize || size > volumes.MaxSize {
		return i18n.E("volume.limit.error.size", "max", volumes.MaxSize>>40)
	}
	docker := node.VolumeName(p.Slug, s.Slug, name)
	m.volMu.Lock()
	defer m.volMu.Unlock()
	free := m.hostFree()
	if cur, ok := m.limitOf(ctx, docker); ok && cur.State != limitFailed {
		if cur.State != limitActive {
			return i18n.E("volume.limit.error.busy")
		}
		if size <= cur.SizeBytes {
			return i18n.E("volume.limit.error.shrink", "size", gbText(cur.SizeBytes))
		}
		if size-cur.SizeBytes > free {
			return i18n.E("volume.limit.error.no_space", "free", gbText(free))
		}
		if n, err := m.q.GrowVolumeLimit(ctx, dbq.GrowVolumeLimitParams{
			SizeBytes: size, UpdatedAt: m.now().Unix(), Volume: docker, SizeBytes_2: size,
		}); err != nil {
			return err
		} else if n == 0 {
			return i18n.E("volume.limit.error.busy")
		}
		m.record(ctx, a, "service.volume.limit", "service", s.ID, audit.OK, map[string]any{
			"service": p.Slug + "/" + s.Slug, "volume": name, "from": cur.SizeBytes, "to": size,
		})
		m.kickVolumes()
		return nil
	}
	exists, _, err := m.node.(node.VolumeBinder).VolumeDevice(ctx, docker)
	if err != nil {
		return err
	}
	state, step := limitNew, ""
	var used int64
	if exists {
		state, step = limitMigrate, stepMount
		used, _ = m.volUsage(docker)
		if size < used+used/10+headroom {
			return i18n.E("volume.limit.error.too_small", "used", gbText(used))
		}
		if free < used+headroom {
			return i18n.E("volume.limit.error.no_space", "free", gbText(free))
		}
		for _, id := range m.volumeUsers(ctx, p, s.ID, name) {
			if err := m.noDeployRunning(ctx, id.id); err != nil {
				return err
			}
		}
	}
	if size > free+used {
		return i18n.E("volume.limit.error.no_space", "free", gbText(free))
	}
	if err := m.createLimit(ctx, m.q, a, p.ID, s.ID, docker, name, size, state, step); err != nil {
		return err
	}
	m.record(ctx, a, "service.volume.limit", "service", s.ID, audit.OK, map[string]any{
		"service": p.Slug + "/" + s.Slug, "volume": name, "to": size, "moves_data": exists,
	})
	m.kickVolumes()
	return nil
}

func (m *Manager) createLimit(ctx context.Context, q *dbq.Queries, a Actor, projectID, serviceID, docker, name string, size int64, state, step string) error {
	now := m.now().Unix()
	n, err := q.CreateVolumeLimit(ctx, dbq.CreateVolumeLimitParams{
		Volume: docker, ProjectID: projectID, ServiceID: serviceID, Name: name, SizeBytes: size,
		State: state, Step: step, CreatedBy: sql.NullString{String: a.UserID, Valid: a.UserID != ""},
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return i18n.E("volume.limit.error.busy")
	}
	return nil
}

// RemoveVolumeLimit takes a volume's limit away: its data moves back to a
// plain volume (the services stop for the copy). On a limit that failed,
// it only forgets the error.
func (m *Manager) RemoveVolumeLimit(ctx context.Context, a Actor, projectSlug, serviceSlug, name string) error {
	if m.vols == nil {
		return i18n.E("volume.limit.error.unavailable")
	}
	p, s, err := m.GetService(ctx, projectSlug, serviceSlug)
	if err != nil {
		return err
	}
	if _, err := m.ownVolume(ctx, s, name); err != nil {
		return err
	}
	docker := node.VolumeName(p.Slug, s.Slug, name)
	m.volMu.Lock()
	defer m.volMu.Unlock()
	cur, ok := m.limitOf(ctx, docker)
	switch {
	case !ok:
		return ErrNotFound
	case cur.State == limitFailed && cur.Step == "":
		return m.q.DeleteVolumeLimit(ctx, docker)
	case cur.State != limitActive:
		return i18n.E("volume.limit.error.busy")
	}
	if !m.VolumeLimitsAvailable() {
		return i18n.E("volume.limit.error.unavailable")
	}
	res, _, _ := m.vols.Results()
	used := int64(min(res[docker].Used, 1<<62)) //nolint:gosec // bounded
	if free := m.hostFree(); free < used+headroom {
		return i18n.E("volume.limit.error.no_space", "free", gbText(free))
	}
	for _, u := range m.volumeUsers(ctx, p, s.ID, name) {
		if err := m.noDeployRunning(ctx, u.id); err != nil {
			return err
		}
	}
	if err := m.q.SetVolumeLimitState(ctx, dbq.SetVolumeLimitStateParams{
		State: limitUnlimit, Step: stepStop, UpdatedAt: m.now().Unix(), Volume: docker,
	}); err != nil {
		return err
	}
	m.record(ctx, a, "service.volume.unlimit", "service", s.ID, audit.OK, map[string]any{
		"service": p.Slug + "/" + s.Slug, "volume": name, "size": cur.SizeBytes,
	})
	m.kickVolumes()
	return nil
}

// volumeUser is a service that mounts a volume.
type volumeUser struct{ id, slug string }

// volumeUsers are the services that mount ownerID's volume name: the
// owner first, then the services that share it.
func (m *Manager) volumeUsers(ctx context.Context, p dbq.Project, ownerID, name string) []volumeUser {
	out := []volumeUser{}
	if s, err := m.q.GetServiceByID(ctx, ownerID); err == nil {
		out = append(out, volumeUser{s.ID, s.Slug})
	}
	sharers, err := m.q.ListVolumeSharers(ctx, sql.NullString{String: ownerID, Valid: true})
	if err != nil {
		return out
	}
	for _, r := range sharers {
		if r.Name != name {
			continue
		}
		if s, err := m.q.GetService(ctx, dbq.GetServiceParams{ProjectID: p.ID, Slug: r.ServiceSlug}); err == nil {
			out = append(out, volumeUser{s.ID, s.Slug})
		}
	}
	return out
}

// checkVolumesFree refuses a deploy while one of its volumes' data moves,
// and lists the new limited volumes it has to wait for.
func (m *Manager) checkVolumesFree(ctx context.Context, p dbq.Project, s dbq.Service, vols []node.Volume) (wait []string, err error) {
	if m.vols == nil {
		return nil, nil
	}
	for _, v := range vols {
		owner, _ := node.ServiceSpec{Service: s.Slug}.VolumeOwner(v)
		name := node.VolumeName(p.Slug, owner, v.Name)
		r, ok := m.limitOf(ctx, name)
		if !ok {
			continue
		}
		switch r.State {
		case limitMigrate, limitUnlimit, limitRemove:
			return nil, ErrVolumeMoving
		case limitNew:
			wait = append(wait, name)
		}
	}
	return wait, nil
}

// waitVolumesReady waits until the images of new limited volumes are
// mounted (the deploy then binds to them).
func (m *Manager) waitVolumesReady(ctx context.Context, names []string) error {
	deadline := m.now().Add(newVolumeWait)
	for {
		pending := ""
		for _, n := range names {
			r, ok := m.limitOf(ctx, n)
			switch {
			case !ok:
				return i18n.E("volume.limit.error.not_ready", "error", "the limit was removed")
			case r.State == limitFailed:
				return i18n.E("volume.limit.error.not_ready", "error", r.Error)
			case r.State == limitNew:
				pending = n
			}
		}
		if pending == "" {
			return nil
		}
		if m.now().After(deadline) {
			r, _ := m.limitOf(ctx, pending)
			msg := r.Error
			if msg == "" {
				msg = "the hangar-volumes unit did not mount the image in time"
			}
			return i18n.E("volume.limit.error.not_ready", "error", msg)
		}
		m.kickVolumes()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(volumePoll):
		}
	}
}

// forgetVolumeLimits marks the limits of a service's volumes for removal
// (the service or the volume is being deleted): the Docker volume goes,
// then the unit deletes the image. names nil means every volume.
func (m *Manager) forgetVolumeLimits(ctx context.Context, p dbq.Project, s dbq.Service, names []string) error {
	if m.vols == nil {
		return nil
	}
	m.volMu.Lock()
	defer m.volMu.Unlock()
	rows, err := m.q.ListVolumeLimits(ctx)
	if err != nil {
		return err
	}
	changed := false
	for _, r := range rows {
		if r.ServiceID != s.ID || (names != nil && !slices.Contains(names, r.Name)) {
			continue
		}
		if r.State == limitMigrate || r.State == limitUnlimit {
			return i18n.E("volume.limit.error.busy")
		}
		if r.State == limitRemove {
			continue
		}
		// The bound Docker volume holds no data of its own; without the
		// image it would only point at nothing.
		if vr, ok := m.node.(volumeRemover); ok {
			if err := vr.RemoveVolume(ctx, p.Slug, s.Slug, r.Name); err != nil {
				m.log.Warn("remove limited volume", "volume", r.Volume, "error", err)
			}
		}
		if err := m.q.SetVolumeLimitState(ctx, dbq.SetVolumeLimitStateParams{
			State: limitRemove, UpdatedAt: m.now().Unix(), Volume: r.Volume,
		}); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		m.kickVolumes()
	}
	return nil
}

// limitsMoving refuses to delete a service while one of its volumes' data
// moves.
func (m *Manager) limitsMoving(ctx context.Context, serviceID string) error {
	if m.vols == nil {
		return nil
	}
	rows, err := m.q.ListVolumeLimits(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.ServiceID == serviceID && (r.State == limitMigrate || r.State == limitUnlimit) {
			return i18n.E("volume.limit.error.busy")
		}
	}
	return nil
}

// limitEntry is what the unit must do for one limit (ok false: nothing).
func limitEntry(r dbq.VolumeLimit) (volumes.Entry, bool) {
	e := volumes.Entry{Name: r.Volume, Op: volumes.OpMount, Size: r.SizeBytes}
	switch r.State {
	case limitMigrate:
		if r.Step == stepImport {
			e.Op = volumes.OpImport
		}
	case limitUnlimit:
		if r.Step == stepExport {
			e = volumes.Entry{Name: r.Volume, Op: volumes.OpExport}
		}
	case limitRemove:
		e = volumes.Entry{Name: r.Volume, Op: volumes.OpRemove}
	case limitFailed:
		if r.Step != stepCleanup {
			return e, false
		}
		e = volumes.Entry{Name: r.Volume, Op: volumes.OpRemove}
	}
	return e, true
}

func (m *Manager) writeDesired(ctx context.Context, force bool) ([]dbq.VolumeLimit, error) {
	rows, err := m.q.ListVolumeLimits(ctx)
	if err != nil {
		return nil, err
	}
	entries := []volumes.Entry{}
	for _, r := range rows {
		if !volumes.ValidName(r.Volume) {
			continue
		}
		if e, ok := limitEntry(r); ok {
			entries = append(entries, e)
		}
	}
	return rows, m.vols.Write(entries, force)
}

// RunVolumeLimits drives the limits until ctx ends: it writes what the
// unit must do, reads its answers and takes each limit a step further. It
// writes once at start even when nothing changed, so the unit runs again
// after a boot that found Docker still down.
func (m *Manager) RunVolumeLimits(ctx context.Context) {
	if m.vols == nil {
		return
	}
	force := true
	for {
		busy := m.syncVolumeLimits(ctx, force)
		force = false
		wait := time.Minute
		if busy {
			wait = 2 * time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-m.volKick:
		case <-time.After(wait):
		}
	}
}

// syncVolumeLimits is one round; it reports whether a limit is changing.
func (m *Manager) syncVolumeLimits(ctx context.Context, force bool) bool {
	m.volMu.Lock()
	defer m.volMu.Unlock()
	rows, err := m.writeDesired(ctx, force)
	if err != nil {
		m.log.Error("write volume limits", "error", err)
		return true
	}
	res, current, _ := m.vols.Results()
	busy := false
	for _, r := range rows {
		if m.stepLimit(ctx, r, res, current) {
			busy = true
		}
	}
	if _, err := m.writeDesired(ctx, false); err != nil {
		m.log.Error("write volume limits", "error", err)
	}
	return busy
}

// stepLimit takes one limit a step further; it reports whether the limit
// is still changing.
func (m *Manager) stepLimit(ctx context.Context, r dbq.VolumeLimit, res map[string]volumes.Result, current bool) bool {
	want, _ := limitEntry(r)
	got, answered := res[r.Volume]
	answered = answered && current && got.Op == want.Op
	ok := answered && got.OK
	failed := answered && !got.OK
	mounted := ok && got.Size >= r.SizeBytes
	set := func(state, step, msg string) {
		if err := m.q.SetVolumeLimitState(ctx, dbq.SetVolumeLimitStateParams{
			State: state, Step: step, Error: msg, UpdatedAt: m.now().Unix(), Volume: r.Volume,
		}); err != nil {
			m.log.Error("volume limit state", "volume", r.Volume, "error", err)
		}
		if state != r.State || step != r.Step {
			m.log.Info("volume limit", "volume", r.Volume, "state", state, "step", step, "error", msg)
		}
	}
	setError := func(msg string) {
		if msg != r.Error {
			_ = m.q.SetVolumeLimitError(ctx, dbq.SetVolumeLimitErrorParams{Error: msg, UpdatedAt: m.now().Unix(), Volume: r.Volume})
		}
	}
	// The unit should answer every write within a few seconds (a copy
	// takes longer, but then the last answer is for an earlier write).
	silent := !current && m.now().Sub(m.vols.WrittenAt()) > unitPatience
	silentMsg := "the hangar-volumes unit is not answering (hangard system install-units installs it)"

	switch r.State {
	case limitNew:
		switch {
		case mounted:
			set(limitActive, "", "")
			return false
		case failed:
			set(limitFailed, stepCleanup, got.Error)
		case silent:
			setError(silentMsg)
		}
		return true
	case limitActive:
		switch {
		case failed:
			setError(got.Error)
		case mounted:
			setError("")
			return false
		case silent:
			setError(silentMsg)
		}
		return !mounted
	case limitMigrate:
		return m.stepMigrate(ctx, r, mounted, ok, failed, got.Error, set, setError)
	case limitUnlimit:
		return m.stepUnlimit(ctx, r, ok, failed, got.Error, set, setError)
	case limitRemove:
		switch {
		case ok:
			if err := m.q.DeleteVolumeLimit(ctx, r.Volume); err != nil {
				m.log.Error("delete volume limit", "error", err)
			}
			return false
		case failed:
			setError(got.Error)
		}
		return true
	case limitFailed:
		if r.Step == stepCleanup && ok {
			set(limitFailed, "", r.Error)
			return false
		}
		return r.Step == stepCleanup
	}
	return false
}

func (m *Manager) stepMigrate(ctx context.Context, r dbq.VolumeLimit, mounted, ok, failed bool, unitErr string,
	set func(state, step, msg string), setError func(string),
) bool {
	p, users, err := m.limitUsers(ctx, r)
	if err != nil {
		setError(err.Error())
		return true
	}
	switch r.Step {
	case stepMount:
		switch {
		case mounted:
			set(limitMigrate, stepStop, "")
		case failed:
			set(limitFailed, stepCleanup, unitErr)
		}
	case stepStop:
		restart, err := m.stopUsers(ctx, r, p, users)
		if err != nil {
			setError(err.Error())
			return true
		}
		if restart == nil { // a deploy is running: wait for it
			return true
		}
		set(limitMigrate, stepImport, "")
	case stepImport:
		switch {
		case ok:
			set(limitMigrate, stepSwitch, "")
		case failed:
			// The plain volume was never touched: back to it.
			set(limitFailed, stepCleanup, unitErr)
			m.restartUsers(ctx, r, p)
		}
	case stepSwitch:
		if err := m.switchVolume(ctx, r, p, m.vols.Paths.Device(r.Volume)); err != nil {
			setError(err.Error())
			return true
		}
		set(limitActive, "", "")
		m.restartUsers(ctx, r, p)
		return false
	}
	return true
}

func (m *Manager) stepUnlimit(ctx context.Context, r dbq.VolumeLimit, ok, failed bool, unitErr string,
	set func(state, step, msg string), setError func(string),
) bool {
	p, users, err := m.limitUsers(ctx, r)
	if err != nil {
		setError(err.Error())
		return true
	}
	switch r.Step {
	case stepStop:
		restart, err := m.stopUsers(ctx, r, p, users)
		if err != nil {
			setError(err.Error())
			return true
		}
		if restart == nil {
			return true
		}
		set(limitUnlimit, stepSwitch, "")
	case stepSwitch:
		if err := m.switchVolume(ctx, r, p, ""); err != nil {
			setError(err.Error())
			return true
		}
		set(limitUnlimit, stepExport, "")
	case stepExport:
		switch {
		case ok:
			if err := m.q.DeleteVolumeLimit(ctx, r.Volume); err != nil {
				setError(err.Error())
				return true
			}
			m.restartUsers(ctx, r, p)
			return false
		case failed:
			// The image still holds the data: bind to it again (the new
			// plain volume only held a partial copy).
			if err := m.switchVolume(ctx, r, p, m.vols.Paths.Device(r.Volume)); err != nil {
				setError(unitErr + "; " + err.Error())
				return true
			}
			set(limitActive, "", unitErr)
			m.restartUsers(ctx, r, p)
			return false
		}
	}
	return true
}

// limitUsers reads the project and the services that mount the volume.
func (m *Manager) limitUsers(ctx context.Context, r dbq.VolumeLimit) (dbq.Project, []volumeUser, error) {
	project, _, _, ok := splitVolumeName(r.Volume)
	if !ok {
		return dbq.Project{}, nil, fmt.Errorf("invalid volume name %q", r.Volume)
	}
	p, err := m.GetProject(ctx, project)
	if err != nil {
		return p, nil, err
	}
	return p, m.volumeUsers(ctx, p, r.ServiceID, r.Name), nil
}

// stopUsers removes the containers of the services that mount the volume
// (Docker cannot recreate a volume a container still refers to) and keeps
// which of them were meant to be running. nil, nil: a deploy is running,
// try again.
func (m *Manager) stopUsers(ctx context.Context, r dbq.VolumeLimit, p dbq.Project, users []volumeUser) ([]string, error) {
	for _, u := range users {
		if n, err := m.q.HasRunningDeployment(ctx, u.id); err != nil {
			return nil, err
		} else if n > 0 {
			return nil, nil
		}
	}
	restart := []string{}
	if r.RestartJson != "" && r.RestartJson != "[]" {
		_ = json.Unmarshal([]byte(r.RestartJson), &restart) // a step that ran before
	} else {
		ids := make([]string, len(users))
		for i, u := range users {
			ids[i] = u.id
		}
		states, err := m.q.ServiceDesiredStates(ctx, ids)
		if err != nil {
			return nil, err
		}
		running := map[string]bool{}
		for _, st := range states {
			running[st.ID] = st.DesiredState == "running"
		}
		for _, u := range users {
			if running[u.id] {
				restart = append(restart, u.slug)
			}
		}
		b, _ := json.Marshal(restart)
		if err := m.q.SetVolumeLimitRestart(ctx, dbq.SetVolumeLimitRestartParams{RestartJson: string(b), UpdatedAt: m.now().Unix(), Volume: r.Volume}); err != nil {
			return nil, err
		}
	}
	for _, u := range users {
		if err := m.node.Remove(ctx, p.Slug, u.slug); err != nil {
			return nil, err
		}
	}
	return restart, nil
}

// restartUsers deploys again the services stopUsers stopped.
func (m *Manager) restartUsers(ctx context.Context, r dbq.VolumeLimit, p dbq.Project) {
	var restart []string
	_ = json.Unmarshal([]byte(r.RestartJson), &restart)
	for _, slug := range restart {
		if _, err := m.Deploy(ctx, Actor{}, p.Slug, slug, "volume-limit"); err != nil {
			m.log.Warn("start after moving a volume", "service", p.Slug+"/"+slug, "error", err)
		}
	}
	_ = m.q.SetVolumeLimitRestart(ctx, dbq.SetVolumeLimitRestartParams{RestartJson: "[]", UpdatedAt: m.now().Unix(), Volume: r.Volume})
}

// switchVolume recreates the limit's Docker volume bound to device (or
// plain), with the owner's labels.
func (m *Manager) switchVolume(ctx context.Context, r dbq.VolumeLimit, p dbq.Project, device string) error {
	vb, ok := m.node.(node.VolumeBinder)
	if !ok {
		return errors.New("the node cannot switch volumes")
	}
	s, err := m.q.GetServiceByID(ctx, r.ServiceID)
	if err != nil {
		return err
	}
	spec := node.ServiceSpec{ProjectID: p.ID, Project: p.Slug, ServiceID: s.ID, Service: s.Slug}
	return vb.SwitchVolume(ctx, spec, node.Volume{Name: r.Name, Device: device}, device)
}

// splitVolumeName reads hangar_<project>_<service>_<name> (slugs have no
// underscore).
func splitVolumeName(docker string) (project, service, name string, ok bool) {
	parts := strings.Split(docker, "_")
	if len(parts) != 4 || parts[0]+"_" != node.NetworkPrefix {
		return "", "", "", false
	}
	return parts[1], parts[2], parts[3], true
}

// LimitedVolume is a limited volume's usage, for the alert rules.
type LimitedVolume struct {
	Key   string // the Docker name
	Name  string // project/service/volume
	Used  uint64
	Total uint64
}

// LimitedVolumes measures every limit in place.
func (m *Manager) LimitedVolumes(ctx context.Context) ([]LimitedVolume, error) {
	if m.vols == nil {
		return nil, nil
	}
	rows, err := m.q.ListVolumeLimits(ctx)
	if err != nil {
		return nil, err
	}
	res, current, _ := m.vols.Results()
	var out []LimitedVolume
	for _, r := range rows {
		if r.State != limitActive {
			continue
		}
		v := m.volumeLimitView(r, res, current)
		if v.Total == 0 {
			continue
		}
		project, service, name, _ := splitVolumeName(r.Volume)
		out = append(out, LimitedVolume{Key: r.Volume, Name: project + "/" + service + "/" + name, Used: v.Used, Total: v.Total})
	}
	return out, nil
}

// HostFree is the free space for new limits (the disk of the images).
func (m *Manager) HostFree() int64 {
	if m.vols == nil {
		return 0
	}
	return m.hostFree()
}
