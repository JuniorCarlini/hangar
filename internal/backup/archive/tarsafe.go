package archive

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// TarLimits bound a tar stream.
type TarLimits struct {
	MaxBytes   int64 // total of file sizes
	MaxEntries int
}

// DefaultTarLimits fit a database directory.
var DefaultTarLimits = TarLimits{MaxBytes: 1 << 40, MaxEntries: 2_000_000}

// ErrUnsafePath is returned for entries that would land outside the target
// directory: absolute paths, "..", links pointing out.
var ErrUnsafePath = errors.New("archive: unsafe path in the backup")

// CleanName validates a tar entry name and returns it cleaned and relative.
func CleanName(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "\x00\\") {
		return "", ErrUnsafePath
	}
	if strings.HasPrefix(name, "/") {
		return "", ErrUnsafePath
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return "", ErrUnsafePath
		}
	}
	clean := path.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", ErrUnsafePath
	}
	return clean, nil
}

// safeLinkTarget accepts a symlink target only when it stays inside the
// tree (PostgreSQL itself only uses links for tablespaces, which base
// backups in tar-to-stdout mode never contain).
func safeLinkTarget(entry, target string) bool {
	if target == "" || strings.HasPrefix(target, "/") || strings.ContainsAny(target, "\x00\\") {
		return false
	}
	joined := path.Clean(path.Join(path.Dir(entry), target))
	return joined != ".." && !strings.HasPrefix(joined, "../")
}

// Edit is called for every regular file while copying a tar. It returns
// the content to write instead (replace=true) or leaves it as is.
type Edit func(name string, body io.Reader) (content []byte, replace bool, err error)

// CopyTar copies the entries of tr into tw after checking each one:
// regular files, directories and contained symlinks only, safe names,
// within limits. Owners are kept numeric only. edit may rewrite files.
func CopyTar(tw *tar.Writer, tr *tar.Reader, lim TarLimits, edit Edit) error {
	var total int64
	entries := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read backup: %w", err)
		}
		entries++
		if lim.MaxEntries > 0 && entries > lim.MaxEntries {
			return ErrTooLarge
		}
		name, err := CleanName(h.Name)
		if err != nil {
			return err
		}
		out := &tar.Header{
			Name: name, Mode: h.Mode & 0o7777, Uid: h.Uid, Gid: h.Gid,
			ModTime: h.ModTime, Typeflag: h.Typeflag, Format: tar.FormatPAX,
		}
		switch h.Typeflag {
		case tar.TypeDir:
			out.Name += "/"
			if err := tw.WriteHeader(out); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if !safeLinkTarget(name, h.Linkname) {
				return ErrUnsafePath
			}
			out.Linkname = h.Linkname
			if err := tw.WriteHeader(out); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if lim.MaxBytes > 0 && total > lim.MaxBytes {
				return ErrTooLarge
			}
			body := io.LimitReader(tr, h.Size)
			if edit != nil {
				content, replace, err := edit(name, body)
				if err != nil {
					return err
				}
				if replace {
					out.Size = int64(len(content))
					if err := tw.WriteHeader(out); err != nil {
						return err
					}
					if _, err := tw.Write(content); err != nil {
						return err
					}
					continue
				}
			}
			out.Size = h.Size
			if err := tw.WriteHeader(out); err != nil {
				return err
			}
			if _, err := io.Copy(tw, body); err != nil {
				return err
			}
		default:
			// Hard links, devices, FIFOs: never part of a backup Hangar makes.
			return fmt.Errorf("%w: unsupported entry type %q for %s", ErrUnsafePath, h.Typeflag, name)
		}
	}
}

// Extract writes a tar stream into dir (created with 0700) with the same
// checks as CopyTar. Existing files are never overwritten and symlinks are
// never followed while writing.
func Extract(r io.Reader, dir string, lim TarLimits) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tr := tar.NewReader(r)
	var total int64
	entries := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read backup: %w", err)
		}
		entries++
		if lim.MaxEntries > 0 && entries > lim.MaxEntries {
			return ErrTooLarge
		}
		name, err := CleanName(h.Name)
		if err != nil {
			return err
		}
		local := filepath.FromSlash(name)
		switch h.Typeflag {
		case tar.TypeDir:
			if err := root.MkdirAll(local, 0o700); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if !safeLinkTarget(name, h.Linkname) {
				return ErrUnsafePath
			}
			if err := root.MkdirAll(filepath.Dir(local), 0o700); err != nil {
				return err
			}
			if err := root.Symlink(h.Linkname, local); err != nil {
				return err
			}
		case tar.TypeReg:
			total += h.Size
			if lim.MaxBytes > 0 && total > lim.MaxBytes {
				return ErrTooLarge
			}
			if err := root.MkdirAll(filepath.Dir(local), 0o700); err != nil {
				return err
			}
			f, err := root.OpenFile(local, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return err
			}
			_, cerr := io.Copy(f, io.LimitReader(tr, h.Size))
			if err := f.Close(); err != nil && cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return cerr
			}
		default:
			return fmt.Errorf("%w: unsupported entry type %q for %s", ErrUnsafePath, h.Typeflag, name)
		}
	}
}
