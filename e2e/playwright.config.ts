import { execFileSync } from 'node:child_process';

import { defineConfig, devices } from '@playwright/test';

import { AUTH_STATE } from './constants.mjs';

// One free port per run. The config is also loaded by every worker, so the
// port goes into the environment, which the workers inherit.
if (!process.env.HANGAR_E2E_PORT) {
  process.env.HANGAR_E2E_PORT = execFileSync(process.execPath, [
    '-e',
    "const s=require('net').createServer();s.listen(0,'127.0.0.1',()=>{process.stdout.write(String(s.address().port));s.close()})",
  ]).toString();
}
const port = process.env.HANGAR_E2E_PORT;
// localhost (not 127.0.0.1): the panel's __Host- cookies are Secure, and
// browsers only accept those over plain HTTP on localhost.
const baseURL = `http://localhost:${port}`;

export default defineConfig({
  testDir: './tests',
  // The tests share one panel (and one user's preferences): keep them in
  // order, one at a time.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : [['list']],
  globalTeardown: './teardown.ts',
  use: {
    baseURL,
    locale: 'pt-BR',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'setup', testMatch: /auth\.setup\.ts/ },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: AUTH_STATE },
      dependencies: ['setup'],
    },
  ],
  webServer: {
    command: 'node server.mjs',
    url: `${baseURL}/healthz`,
    // The first run compiles hangard.
    timeout: 180_000,
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'pipe',
    gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
  },
});
