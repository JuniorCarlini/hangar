package archive

import (
	"archive/zip"
	"io"
	"strings"
	"time"
)

// A download of a database backup is one .zip with everything a restore
// elsewhere needs: the pg_dump, the roles of its server and a README that
// says how to put them back. Zip is written as a stream (sizes after each
// file), so a dump of any size goes out without being staged twice, and
// every system opens it.

// ExtBundle is the extension of a downloaded backup.
const ExtBundle = ".zip"

// Decrypted roles files: pg_dumpall's output, and the script that
// recreates from it only the roles a server lacks (pgroles.RestoreScript).
const (
	ExtRolesSQL     = ".roles.sql"
	ExtRolesRestore = ".roles-restore.sql"
)

// BundleFile is one file of a bundle.
type BundleFile struct {
	Name string
	Body io.Reader
	// Text files are compressed; dumps (compressed) and .age files
	// (encrypted) are stored as they are.
	Text bool
}

// WriteBundle writes files, in order, as a zip to w.
func WriteBundle(w io.Writer, modified time.Time, files ...BundleFile) error {
	zw := zip.NewWriter(w)
	for _, f := range files {
		method := zip.Store
		if f.Text {
			method = zip.Deflate
		}
		fw, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: method, Modified: modified})
		if err != nil {
			return err
		}
		if _, err := io.Copy(fw, f.Body); err != nil {
			return err
		}
	}
	return zw.Close()
}

// BundleName is the base name of the files of a bundle made at t for a
// service ("project_service-20261028T120000Z").
func BundleName(project, service string, t time.Time) string {
	return project + "_" + service + "-" + t.UTC().Format(TimeFormat)
}

// TextFile is a text BundleFile.
func TextFile(name, body string) BundleFile {
	return BundleFile{Name: name, Body: strings.NewReader(body), Text: true}
}
