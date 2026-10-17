// Package archive is the format of Hangar backups, shared by hangard and
// hangar-cofre (docs/09): files are encrypted with age to the operator's
// public keys (optionally compressed with zstd first), named by a fixed key
// layout in the bucket, and opened only with the recovery kit.
//
// The server can seal but never open: nothing here needs a private key
// except Open, which runs on the operator's computer or, during a restore,
// with a key held only in memory.
package archive

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
	"github.com/klauspost/compress/zstd"
)

// zstdMagic starts every zstd frame.
var zstdMagic = []byte{0x28, 0xB5, 0x2F, 0xFD}

// ErrTooLarge is returned when a stream passes the size or compression
// ratio limit (an archive bomb).
var ErrTooLarge = errors.New("archive: content exceeds the size limit")

// ParseRecipients parses age X25519 public keys ("age1..."). Only that type
// is accepted: it is what the recovery kit generates.
func ParseRecipients(keys []string) ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(keys))
	for _, k := range keys {
		r, err := age.ParseX25519Recipient(strings.TrimSpace(k))
		if err != nil {
			return nil, fmt.Errorf("public key %q: %w", short(k), err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, errors.New("no public key to encrypt to")
	}
	return out, nil
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// sealer chains zstd (optional) and age; Close finishes both in order.
type sealer struct {
	z   *zstd.Encoder
	age io.WriteCloser
}

func (s *sealer) Write(p []byte) (int, error) {
	if s.z != nil {
		return s.z.Write(p)
	}
	return s.age.Write(p)
}

func (s *sealer) Close() error {
	if s.z != nil {
		if err := s.z.Close(); err != nil {
			return err
		}
	}
	return s.age.Close()
}

// Seal returns a writer that encrypts to every recipient (any one of the
// matching private keys opens it). With compress, data is zstd-compressed
// before encryption. Close must be called to finish the file.
func Seal(dst io.Writer, recipients []age.Recipient, compress bool) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no public key to encrypt to")
	}
	aw, err := age.Encrypt(dst, recipients...)
	if err != nil {
		return nil, err
	}
	s := &sealer{age: aw}
	if compress {
		z, err := zstd.NewWriter(aw, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(2))
		if err != nil {
			return nil, err
		}
		s.z = z
	}
	return s, nil
}

// Limits bound what Open hands out, so a hostile or corrupted archive
// cannot fill the disk or the memory.
type Limits struct {
	// MaxBytes is the most plaintext Open returns (0 = no limit).
	MaxBytes int64
	// MaxRatio is the most plaintext per byte of ciphertext once past
	// 64 MiB (0 = no limit). Real backups compress 3-20x; a bomb does
	// thousands.
	MaxRatio int64
}

// DefaultLimits suit database backups: up to 1 TiB, at most 200x expansion.
var DefaultLimits = Limits{MaxBytes: 1 << 40, MaxRatio: 200}

// Open decrypts src with the identities and decompresses zstd content
// transparently. The result is bounded by lim.
func Open(src io.Reader, ids []age.Identity, lim Limits) (io.ReadCloser, error) {
	in := &countingReader{r: src}
	plain, err := age.Decrypt(in, ids...)
	if err != nil {
		var nm *age.NoIdentityMatchError
		if errors.As(err, &nm) {
			return nil, ErrWrongKey
		}
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	br := bufio.NewReaderSize(plain, 64<<10)
	head, _ := br.Peek(len(zstdMagic))
	var out io.Reader = br
	closer := func() {}
	if bytes.Equal(head, zstdMagic) {
		z, err := zstd.NewReader(br, zstd.WithDecoderMaxMemory(256<<20), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("decompress: %w", err)
		}
		out, closer = z, z.Close
	}
	return &boundedReader{r: out, in: in, lim: lim, close: closer}, nil
}

// ErrWrongKey means none of the given private keys opens the file.
var ErrWrongKey = errors.New("archive: the key does not open this backup")

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

type boundedReader struct {
	r     io.Reader
	in    *countingReader
	lim   Limits
	n     int64
	close func()
}

func (b *boundedReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.n += int64(n)
	if b.lim.MaxBytes > 0 && b.n > b.lim.MaxBytes {
		return n, ErrTooLarge
	}
	if b.lim.MaxRatio > 0 && b.n > 64<<20 && b.n > b.lim.MaxRatio*max(b.in.n, 1) {
		return n, ErrTooLarge
	}
	return n, err
}

func (b *boundedReader) Close() error {
	b.close()
	return nil
}
