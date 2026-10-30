package main

import (
	"regexp"
	"testing"

	"github.com/JuniorCarlini/hangar/internal/backup"
	"github.com/JuniorCarlini/hangar/internal/cofre"
	"github.com/JuniorCarlini/hangar/internal/config"
)

// SEC-021: the helper images the panel and hangar-cofre run on their own
// (as root over volumes, or with a decrypted dump) are pinned by digest,
// with the tag kept beside it for people and update tooling.
func TestHelperImagesArePinnedByDigest(t *testing.T) {
	pinned := regexp.MustCompile(`^[a-z0-9./-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$`)
	for name, ref := range map[string]string{
		"backup.VolumeHelperImage": backup.VolumeHelperImage,
		"cofre.DefaultImage":       cofre.DefaultImage,
		"config.DefaultEdgeImage":  config.DefaultEdgeImage,
	} {
		if !pinned.MatchString(ref) {
			t.Errorf("%s = %q: want name:tag@sha256:<digest>", name, ref)
		}
	}
}
