// Package pgwal holds how a PostgreSQL service archives its WAL for
// point-in-time restore (docs/09). PostgreSQL copies each finished WAL file
// into an outbox inside the data volume (outside PGDATA); hangard picks
// them up, encrypts them with age and sends them to the bucket. Nothing
// extra is installed in the database image and no key is ever inside it.
package pgwal

import "path"

// OutboxName is the outbox directory, next to PGDATA in the data volume.
const OutboxName = "hangar-wal"

// DataVolume is the template volume that holds the database.
const DataVolume = "data"

// Outbox returns the outbox path for a data volume mounted at volumePath.
func Outbox(volumePath string) string { return path.Join(volumePath, OutboxName) }

// Args are the server options appended to the "postgres" command while
// archiving is on. archive_timeout=60 bounds the data at risk to about a
// minute even when the database is quiet. A file already in the outbox
// with the same content counts as archived (PostgreSQL may retry after a
// crash); a different one fails loudly, as the PostgreSQL docs require.
func Args(volumePath string) []string {
	dir := Outbox(volumePath)
	cmd := "mkdir -p " + dir + " && if [ -f " + dir + "/%f ]; then cmp -s %p " + dir + "/%f; " +
		"else cp %p " + dir + "/%f.tmp && mv " + dir + "/%f.tmp " + dir + "/%f; fi"
	return []string{
		"-c", "wal_level=replica",
		"-c", "archive_mode=on",
		"-c", "archive_timeout=60",
		"-c", "archive_command=" + cmd,
	}
}

// Supports reports whether the service's command can take Args: the
// image's own server started as "postgres ...".
func Supports(cmd []string) bool { return len(cmd) > 0 && cmd[0] == "postgres" }
