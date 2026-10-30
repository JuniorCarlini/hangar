import { createHmac } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

import { expect, type Page } from '@playwright/test';

import { OWNER_EMAIL, OWNER_PASSWORD, PROJECT_PREFIX, RECOVERY_STATE } from '../constants.mjs';

// totp is the authenticator app: the current 6-digit code of a base32
// secret (RFC 6238, SHA-1, 30 s).
export function totp(secret: string, at = Date.now()): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of secret.replace(/=+$/, '').toUpperCase()) {
    bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  }
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac('sha1', key).update(counter).digest();
  const off = h[h.length - 1] & 0xf;
  const n = (h.readUInt32BE(off) & 0x7fffffff) % 1_000_000;
  return n.toString().padStart(6, '0');
}

// recoveryCode hands out the next unused recovery code of the owner (the
// tests run one at a time, so a file is enough to share them).
export function recoveryCode(): string {
  const state = JSON.parse(readFileSync(RECOVERY_STATE, 'utf8')) as { codes: string[] };
  const code = state.codes.shift();
  if (!code) throw new Error('out of recovery codes');
  writeFileSync(RECOVERY_STATE, JSON.stringify(state));
  return code;
}

// loginAsOwner signs in on a fresh page: password, then a recovery code in
// the second step.
export async function loginAsOwner(page: Page) {
  await page.goto('/login');
  await page.locator('#email').fill(OWNER_EMAIL);
  await page.locator('#password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await expect(page).toHaveURL('/login/2fa');
  await page.locator('#code').fill(recoveryCode());
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page).toHaveURL('/');
}

// newSlug is a project slug unique to this run, with the prefix the
// teardown looks for.
export function newSlug(): string {
  return PROJECT_PREFIX + Date.now().toString(36) + Math.floor(Math.random() * 1296).toString(36);
}

// hasDocker asks the panel itself: without Docker the overview shows the
// "Docker unavailable" alert.
export async function hasDocker(page: Page): Promise<boolean> {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  return !(await page.getByText('Docker indisponível').isVisible());
}

// openAccountMenu opens the account dropdown in the top bar.
export async function openAccountMenu(page: Page) {
  await page.locator('[data-tuc-dropdown="#user-menu"]').click();
  await expect(page.locator('#user-menu')).toBeVisible();
}

// createProject creates a project through the sidebar dialog and waits for
// its (empty) canvas. The dialog only asks for a name and the server derives
// the technical name from it: a slug-shaped name keeps that name as is.
export async function createProject(page: Page, slug: string) {
  await page.goto('/');
  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Nome', { exact: true }).fill(slug);
  await dialog.getByRole('button', { name: 'Criar projeto' }).click();
  await expect(page).toHaveURL(new RegExp(`/p/${slug}$`));
}
