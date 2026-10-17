package web

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"testing"
)

func TestVendoredTucanoMatchesPinnedHashes(t *testing.T) {
	for name, want := range map[string]string{
		"assets/vendor/tucano/tucano.min.css": tucanoCSSSHA256,
		"assets/vendor/tucano/tucano.min.js":  tucanoJSSHA256,
		"assets/vendor/xterm/xterm.js":        xtermJSSHA256,
		"assets/vendor/xterm/xterm.css":       xtermCSSSHA256,
		"assets/vendor/xterm/addon-fit.js":    xtermFitJSSHA256,
	} {
		b, err := fs.ReadFile(assetsFS, name)
		if err != nil {
			t.Fatalf("%s not embedded: %v", name, err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s (Tucano %s, xterm %s/%s): sha256 %s, pinned %s", name, tucanoVersion, xtermVersion, xtermFitVersion, got, want)
		}
	}
}
