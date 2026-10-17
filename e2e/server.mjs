// Starts a throwaway hangard for the E2E run: builds the binary, writes a
// config into a temporary directory (database, master key, everything),
// creates the owner through the CLI and serves on HANGAR_E2E_PORT. The
// directory is removed when Playwright stops the server.
//
// Docker is optional: without it the panel runs read-only for projects and
// the Docker-dependent tests skip themselves.
import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { OWNER_EMAIL, OWNER_PASSWORD } from './constants.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const port = process.env.HANGAR_E2E_PORT;
if (!port) {
  console.error('HANGAR_E2E_PORT is not set (the Playwright config sets it)');
  process.exit(1);
}

const dir = mkdtempSync(join(tmpdir(), 'hangar-e2e-'));
const bin = join(dir, 'hangard');
const config = join(dir, 'hangar.toml');
let cleaned = false;
function cleanup() {
  if (cleaned) return;
  cleaned = true;
  rmSync(dir, { recursive: true, force: true });
}

execFileSync('go', ['build', '-o', bin, './cmd/hangard'], { cwd: root, stdio: 'inherit' });

writeFileSync(config, `# Throwaway config for the E2E tests.
data_dir = "data"
master_key_file = "master.key"

[panel]
listen = ["127.0.0.1:${port}"]
hosts = ["127.0.0.1:${port}", "localhost:${port}"]

[update]
# Never ask GitHub during the tests: nothing listens on the discard port.
api_base = "http://127.0.0.1:9"

[scan]
# No daily scan and no OSV.dev during the tests (the discard port again).
enabled = false
osv_api = "http://127.0.0.1:9"

[alerts]
# Same for Telegram: alerts to the channels the tests create go nowhere.
telegram_api = "http://127.0.0.1:9"
`);

// The CLI reads the password twice from stdin when it is not a terminal.
execFileSync(bin, ['user', 'create', '-config', config, '-email', OWNER_EMAIL, '-role', 'owner', '-no-2fa'], {
  input: `${OWNER_PASSWORD}\n${OWNER_PASSWORD}\n`,
  stdio: ['pipe', 'ignore', 'inherit'],
});

const server = spawn(bin, ['serve', '-config', config], { stdio: 'inherit' });
server.on('exit', (code) => {
  cleanup();
  process.exit(code ?? 0);
});
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => server.kill('SIGTERM'));
}
process.on('exit', () => {
  server.kill('SIGTERM');
  cleanup();
});
