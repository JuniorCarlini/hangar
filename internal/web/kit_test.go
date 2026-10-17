package web

import (
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"

	"filippo.io/age"

	"github.com/JuniorCarlini/hangar/internal/backup/archive"
)

// kit.js generates the recovery kit in the browser; Go opens it. Both must
// agree on the key encoding and the confirmation code, so this runs the
// real kit.js under node (skipped where node is missing).
func TestKitJSMatchesGo(t *testing.T) {
	nodeBin, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	const secret = "AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX"
	script := `
const K = require(process.argv[1]);
(async () => {
  const secret = process.argv[2];
  const pub = await K.publicOf(secret);
  const code = await K.confirmCode(secret);
  const hash = await K.codeHash(code.toLowerCase());
  const g = await K.generate();
  const derived = await K.publicOf(g.secret);
  const kit = K.kitText("Hangar\nChave: {public}\nCódigo: {code}", { public: g.public, code: "X" }, g.secret);
  process.stdout.write(JSON.stringify({ pub, code, hash, gsecret: g.secret, gpub: g.public, derived, kit, found: K.findSecret(kit) }));
})().catch((e) => { console.error(e); process.exit(1); });`
	path, _ := filepath.Abs("assets/kit.js")
	out, err := exec.Command(nodeBin, "-e", script, path, secret).Output() //nolint:gosec // test with fixed arguments
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	var got struct{ Pub, Code, Hash, Gsecret, Gpub, Derived, Kit, Found string }
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	id, _ := age.ParseX25519Identity(secret)
	if got.Pub != id.Recipient().String() {
		t.Errorf("public key: js %s, go %s", got.Pub, id.Recipient())
	}
	if got.Code != archive.ConfirmCode(id) {
		t.Errorf("confirmation code: js %s, go %s", got.Code, archive.ConfirmCode(id))
	}
	if got.Hash != archive.CodeHash(got.Code) {
		t.Error("code hash differs")
	}
	gid, err := age.ParseX25519Identity(got.Gsecret)
	if err != nil {
		t.Fatalf("a generated key does not parse in age: %v", err)
	}
	if gid.Recipient().String() != got.Gpub || got.Derived != got.Gpub {
		t.Errorf("generated pair does not match: %s / %s / %s", gid.Recipient(), got.Gpub, got.Derived)
	}
	keys, err := archive.ParseKit([]byte(got.Kit), "")
	if err != nil || len(keys) != 1 || keys[0].String() != got.Gsecret || got.Found != got.Gsecret {
		t.Fatalf("the kit file does not parse: %v\n%s", err, got.Kit)
	}
}
