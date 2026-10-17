package gitsrc

import (
	"context"
	"errors"
	"io"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// ErrTooLarge means a file read from the repository is over the caller's
// limit.
var ErrTooLarge = errors.New("file too large")

// Snapshot is the tree of a branch's last commit, read without checking any
// file out: the panel only peeks at a few files (the compose file, a
// Dockerfile) and never writes the working tree to disk.
type Snapshot struct {
	tree *object.Tree
}

// Fetch makes a shallow, bare clone of the branch into dir (which must not
// exist or be empty) and returns its tree. The caller removes dir.
func Fetch(ctx context.Context, dir string, src Source) (*Snapshot, Commit, error) {
	repo, err := git.PlainCloneContext(ctx, dir, true, &git.CloneOptions{
		URL:               src.URL,
		Auth:              src.auth(),
		ReferenceName:     plumbing.NewBranchReferenceName(src.Branch),
		SingleBranch:      true,
		Depth:             1,
		Tags:              git.NoTags,
		NoCheckout:        true,
		RecurseSubmodules: git.NoRecurseSubmodules,
	})
	if err != nil {
		return nil, Commit{}, mapErr(err)
	}
	head, err := repo.Head()
	if err != nil {
		return nil, Commit{}, err
	}
	c, err := repo.CommitObject(head.Hash())
	if err != nil {
		return nil, Commit{}, err
	}
	tree, err := c.Tree()
	if err != nil {
		return nil, Commit{}, err
	}
	return &Snapshot{tree: tree}, Commit{SHA: head.Hash().String()}, nil
}

// ReadFile returns a regular file of the snapshot. ok is false when the path
// does not exist or is not a regular file; a file over maxBytes is
// ErrTooLarge. p must already be clean (CleanPath).
func (s *Snapshot) ReadFile(p string, maxBytes int64) ([]byte, bool, error) {
	if p == "" {
		return nil, false, nil
	}
	f, err := s.tree.File(p)
	if errors.Is(err, object.ErrFileNotFound) || errors.Is(err, object.ErrDirectoryNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !f.Mode.IsFile() {
		return nil, false, nil
	}
	if f.Size > maxBytes {
		return nil, true, ErrTooLarge
	}
	r, err := f.Reader()
	if err != nil {
		return nil, true, err
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, true, err
	}
	if int64(len(b)) > maxBytes {
		return nil, true, ErrTooLarge
	}
	return b, true, nil
}
