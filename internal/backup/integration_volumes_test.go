//go:build integration

package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
	"github.com/JuniorCarlini/hangar/internal/backup/backuptest"
	"github.com/JuniorCarlini/hangar/internal/node"
	"github.com/JuniorCarlini/hangar/internal/projects"
)

// helper runs script in a throwaway VolumeHelperImage container with the
// Docker volume mounted at /v/data.
func (e *realEnv) helper(t *testing.T, ctx context.Context, volume, script string, readOnly bool, stdin io.Reader) string {
	t.Helper()
	var out bytes.Buffer
	err := e.pm.Node().(node.Tasker).RunTask(ctx, node.TaskSpec{
		Image: VolumeHelperImage, Cmd: []string{"bash", "-c", script},
		Mounts:      []node.TaskMount{{Volume: volume, Path: "/v/data", ReadOnly: readOnly}},
		MemoryBytes: 512 << 20, NanoCPUs: 2e9, PidsLimit: 64,
	}, stdin, &out)
	if err != nil {
		t.Fatalf("helper on %s: %v", volume, err)
	}
	return out.String()
}

// populate fills a volume with what an app may keep: owners and modes of
// all kinds, setuid and sticky bits, an empty folder, relative, absolute
// and dangling symlinks, a hard link, a FIFO, a sparse file, random data,
// user.* attributes and a POSIX ACL (both brought in through GNU tar,
// as the image has no setfattr or setfacl).
func (e *realEnv) populate(t *testing.T, ctx context.Context, volume string) {
	t.Helper()
	e.helper(t, ctx, volume, `set -euo pipefail
cd /v/data
mkdir -p dir/sub empty .rustfs.sys/config
echo hello > dir/hello.txt
head -c 3000000 /dev/urandom > dir/sub/random.bin
printf '{"users":{"app":{"policy":"readwrite"}}}' > .rustfs.sys/config/iam.json
chown 1000:1000 dir/hello.txt
chown -R 999:998 .rustfs.sys
chown 65534:65534 empty
chmod 0750 dir
chmod 0600 dir/sub/random.bin
chmod 4755 dir/hello.txt
chmod 1777 empty
ln -s hello.txt dir/link
ln -s /etc/passwd abs-link
ln -s missing/target dangling
ln dir/hello.txt hard
mkfifo fifo
truncate -s 64M sparse.img
printf x | dd of=sparse.img bs=1 seek=10485760 conv=notrunc status=none
touch -h -d '2024-01-02 03:04:05' dir/link
touch -d '2023-05-06 07:08:09' dir/hello.txt empty
`, false, nil)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range []struct {
		name string
		pax  map[string]string
	}{
		{"data/xattr.txt", map[string]string{"SCHILY.xattr.user.hangar": "kept", "SCHILY.xattr.user.other": "too"}},
		{"data/acl.txt", map[string]string{"SCHILY.acl.access": "user::rw-,user:1234:r--,group::r--,mask::r--,other::---"}},
	} {
		body := "attributes of " + f.name
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Typeflag: tar.TypeReg, Mode: 0o640, Uid: 1234, Gid: 1234, Size: int64(len(body)), PAXRecords: f.pax, Format: tar.FormatPAX, ModTime: time.Unix(1700000000, 0)}); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(tw, body)
	}
	_ = tw.Close()
	e.helper(t, ctx, volume, `tar -xpf - -C /v --numeric-owner --acls --xattrs --xattrs-include='user.*'`, false, &buf)
}

// manifestScript lists every entry of the volume (path, type, mode,
// owner, size, hard links, link target, mtime), the SHA-256 of every file,
// and a tar of it with every extended attribute and ACL (read in Go).
const manifestScript = `set -euo pipefail
cd /v
find data -printf 'E %p %y %m %U:%G %s %n %l %Ts\n' | LC_ALL=C sort
find data -type f -exec sha256sum {} + | LC_ALL=C sort -k2
echo TAR
tar -cf - --format=posix --numeric-owner --acls --xattrs --xattrs-include='*' --sparse data | base64 -w0
echo
echo BLOCKS "$(stat -c %b data/sparse.img 2>/dev/null || echo 0)"
`

// manifest is everything that must survive a backup and a restore.
func (e *realEnv) manifest(t *testing.T, ctx context.Context, volume string) (string, int64) {
	t.Helper()
	out := e.helper(t, ctx, volume, manifestScript, true, nil)
	head, rest, ok := strings.Cut(out, "TAR\n")
	if !ok {
		t.Fatalf("manifest: %s", out)
	}
	tarB64, tail, _ := strings.Cut(rest, "\n")
	var blocks int64
	_, _ = fmt.Sscanf(strings.TrimSpace(tail), "BLOCKS %d", &blocks)
	raw, err := decodeB64(tarB64)
	if err != nil {
		t.Fatal(err)
	}
	var attrs []string
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		for k, v := range h.PAXRecords {
			if strings.HasPrefix(k, "SCHILY.xattr.") || strings.HasPrefix(k, "SCHILY.acl.") {
				attrs = append(attrs, "A "+h.Name+" "+k+"="+v)
			}
		}
	}
	sort.Strings(attrs)
	return head + strings.Join(attrs, "\n"), blocks
}

func decodeB64(s string) ([]byte, error) {
	cmd := exec.Command("base64", "-d")
	cmd.Stdin = strings.NewReader(s)
	return cmd.Output()
}

func (e *realEnv) volumeService(t *testing.T, ctx context.Context, slug string) svcRef {
	t.Helper()
	if _, err := e.pm.CreateService(ctx, e.who, e.project, projects.ServiceInput{Name: slug, Image: "nginx:1.31-alpine"}); err != nil {
		t.Fatal(err)
	}
	if err := e.pm.AddServiceVolume(ctx, e.who, e.project, slug, "data", "/data"); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait() // creating the service deploys it
	s, err := e.m.ref(ctx, e.project, slug)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.m.deployAndWait(ctx, e.who, s, "create"); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	return s
}

func (e *realEnv) running(t *testing.T, ctx context.Context, slug string) bool {
	t.Helper()
	st, err := e.pm.Status(ctx, e.project, slug)
	return err == nil && st.Running && st.State == "running"
}

// A service's volume, backed up with the service paused, comes back
// exactly (paths, types, modes, owners, sizes, links, hard links, times,
// contents, attributes, ACLs, sparse files) into a new service and over
// the same service.
func TestVolumeBackupAndRestore(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E volumes"); err != nil {
		t.Fatal(err)
	}
	s := e.volumeService(t, ctx, "files")
	vol := s.Vols[0].Docker
	e.populate(t, ctx, vol)
	want, blocks := e.manifest(t, ctx, vol)
	for _, must := range []string{"user.hangar=kept", "SCHILY.acl.access", "abs-link l 777 0:0 11 1 /etc/passwd", "hello.txt f 4755 1000:1000 6 2", "empty d 1777 65534:65534", "fifo p 644"} {
		if !strings.Contains(want, must) {
			t.Fatalf("the sample lacks %q:\n%s", must, want)
		}
	}
	if blocks == 0 || blocks > 2048 {
		t.Fatalf("sparse.img should be sparse: %d blocks", blocks)
	}

	// 1. Backup, paused: tested and uploaded.
	runID, err := e.m.backupVolume(ctx, e.who, s, TriggerManual, "")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	var c VolumeCheck
	_ = json.Unmarshal([]byte(run.CheckJson), &c)
	if run.Status != "ok" || run.Verified != 1 || c.Mode != ConsistencyPause || !slices.Equal(c.Paused, []string{"files"}) || c.Files < 15 {
		t.Fatalf("run: %+v %s", run, run.CheckJson)
	}
	t.Logf("copy: %d entries, %d bytes, tar %d, sealed %d, paused %d ms", c.Files, c.Bytes, c.TarBytes, run.SizeBytes, c.PauseMS)
	if !e.running(t, ctx, "files") {
		t.Fatal("the service must run again after the copy")
	}
	writer := backuptest.Client(t, e.minio.Writer)
	if info, err := writer.Head(ctx, run.ObjectKey); err != nil || info.LockMode == "" {
		t.Fatalf("locked object: %+v %v", info, err)
	}

	// 2. Into a new service.
	rid, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "files", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "files-copy",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("restore into a new service: %+v", r)
	}
	if got, b := e.manifest(t, ctx, node.VolumeName(e.project, "files-copy", "data")); got != want || b != blocks {
		t.Fatalf("the new service's volume differs (blocks %d, want %d):\n%s", b, blocks, diffLines(want, got))
	}
	if !e.running(t, ctx, "files-copy") {
		t.Fatal("the new service must run")
	}

	// 3. Over the same service, after the data changed.
	e.helper(t, ctx, vol, `rm -rf /v/data/dir && echo new > /v/data/extra && chmod 600 /v/data/hard`, false, nil)
	if got, _ := e.manifest(t, ctx, vol); got == want {
		t.Fatal("the change did not happen")
	}
	time.Sleep(1100 * time.Millisecond) // the copy of the current state gets its own key
	rid, err = e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "files", Mode: ModeDump, Key: run.ObjectKey, Destination: DestOverwrite, Confirm: "files",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("restore over the service: %+v", r)
	}
	if got, b := e.manifest(t, ctx, vol); got != want || b != blocks {
		t.Fatalf("the volume differs after overwriting:\n%s", diffLines(want, got))
	}
	if !e.running(t, ctx, "files") {
		t.Fatal("the service must run after the restore")
	}
	runs, _ := e.m.ServiceRuns(ctx, s.ID, 10)
	if !slices.ContainsFunc(runs, func(r Run) bool {
		return r.Trigger == TriggerPreRestore && r.Status == "ok" && r.Kind == archive.KindVolume
	}) {
		t.Fatalf("no copy of the state before overwriting: %+v", runs)
	}
}

func diffLines(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	var out []string
	for _, l := range w {
		if !slices.Contains(g, l) {
			out = append(out, "- "+l)
		}
	}
	for _, l := range g {
		if !slices.Contains(w, l) {
			out = append(out, "+ "+l)
		}
	}
	return strings.Join(out, "\n")
}

// How long a service stays paused while ~1 GB of its volume is copied,
// tested, compressed and encrypted (docs/09). Logged, and bounded so a
// regression shows.
func TestVolumePauseTime(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E pause"); err != nil {
		t.Fatal(err)
	}
	s := e.volumeService(t, ctx, "big")
	for _, sample := range []struct{ name, script string }{
		{"random", `head -c 1073741824 /dev/urandom > /v/data/big.bin`},
		{"text", `rm -f /v/data/big.bin && yes 'a line of an app log, 2026-10-28 12:00:00 GET /api/orders 200' | head -c 1073741824 > /v/data/big.log`},
	} {
		e.helper(t, ctx, s.Vols[0].Docker, sample.script, false, nil)
		start := time.Now()
		runID, err := e.m.backupVolume(ctx, e.who, s, TriggerManual, "")
		if err != nil {
			t.Fatal(err)
		}
		run, _ := e.m.q.GetBackupRun(ctx, runID)
		var c VolumeCheck
		_ = json.Unmarshal([]byte(run.CheckJson), &c)
		t.Logf("1 GiB %s: paused %d ms, whole backup %s, tar %d bytes, sealed %d bytes", sample.name, c.PauseMS, time.Since(start).Round(time.Millisecond), c.TarBytes, run.SizeBytes)
		if c.PauseMS <= 0 || c.PauseMS > 120_000 {
			t.Fatalf("pause: %d ms", c.PauseMS)
		}
		if limit := os.Getenv("HANGAR_PAUSE_MS_MAX"); limit != "" {
			var max int64
			_, _ = fmt.Sscan(limit, &max)
			if c.PauseMS > max {
				t.Fatalf("pause %d ms over %d", c.PauseMS, max)
			}
		}
		time.Sleep(1100 * time.Millisecond)
	}
}

// RustFS keeps its buckets, objects, users and policies in /data: a copy
// of the disk, paused, restored into a new service is a full clone. The
// clone serves the object, to its IAM user too.
func TestRustFSClone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	e := newRealEnv(t, ctx)
	if _, err := e.pm.CreateProject(ctx, e.who, e.project, "E2E rustfs"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pm.CreateFromTemplate(ctx, e.who, e.project, "rustfs", "s3", nil); err != nil {
		t.Fatal(err)
	}
	e.pm.Wait()
	s, err := e.m.ref(ctx, e.project, "s3")
	if err != nil {
		t.Fatal(err)
	}
	if s.Method != projects.BackupVolume {
		t.Fatalf("rustfs is backed up as %q", s.Method)
	}
	waitRunning := func(slug string) {
		deadline := time.Now().Add(3 * time.Minute)
		for time.Now().Before(deadline) {
			if st, err := e.pm.Status(ctx, e.project, slug); err == nil && st.Running && st.Health == "healthy" {
				return
			}
			time.Sleep(2 * time.Second)
		}
		t.Fatalf("%s did not get healthy", slug)
	}
	waitRunning("s3")
	var access, secret string
	env, _ := e.pm.ListEnvValues(ctx, s.ID)
	for _, v := range env {
		switch v.Key {
		case "RUSTFS_ACCESS_KEY":
			access = v.Value
		case "RUSTFS_SECRET_KEY":
			secret = v.Value
		}
	}
	mc := func(slug, user, pass, script string) (string, error) {
		args := []string{
			"run", "--rm", "--network", "container:" + node.ContainerName(e.project, slug),
			"-e", "MC_HOST_local=http://" + user + ":" + pass + "@127.0.0.1:9000",
			"--entrypoint", "sh", backuptest.MCImage, "-c", script,
		}
		out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput() //nolint:gosec // test helper, fixed image
		return string(out), err
	}
	must := func(out string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatalf("mc: %v\n%s", err, out)
		}
		return out
	}
	must(mc("s3", access, secret, `set -e
mc mb local/photos
echo 'a photo of the shop' | mc pipe local/photos/2026/shop.txt
mc admin user add local app-user app-secret-123456
mc admin policy attach local readwrite --user app-user`))
	if out := must(mc("s3", "app-user", "app-secret-123456", "mc cat local/photos/2026/shop.txt")); !strings.Contains(out, "a photo of the shop") {
		t.Fatalf("the IAM user cannot read on the original: %s", out)
	}

	runID, err := e.m.backupVolume(ctx, e.who, s, TriggerManual, "")
	if err != nil {
		t.Fatalf("backup: %v", err)
	}
	run, _ := e.m.q.GetBackupRun(ctx, runID)
	t.Logf("rustfs copy: %s", run.CheckJson)
	rid, err := e.m.StartRestore(ctx, e.who, RestoreRequest{
		Project: e.project, Service: "s3", Mode: ModeDump, Key: run.ObjectKey, Destination: DestNew, NewService: "s3-clone",
		Identities: []age.Identity{e.id},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := e.waitRestore(t, ctx, s.ID, rid); r.Status != "ok" {
		t.Fatalf("restore: %+v", r)
	}
	waitRunning("s3-clone")
	var out string
	deadline := time.Now().Add(time.Minute)
	for {
		out, err = mc("s3-clone", "app-user", "app-secret-123456", "mc cat local/photos/2026/shop.txt")
		if err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil || !strings.Contains(out, "a photo of the shop") {
		t.Fatalf("the clone does not serve the object to the IAM user: %v\n%s", err, out)
	}
	if out := must(mc("s3-clone", access, secret, "mc admin user info local app-user")); !strings.Contains(out, "readwrite") {
		t.Fatalf("the clone lost the user's policy: %s", out)
	}
}
