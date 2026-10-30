import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { expect, test as setup } from '@playwright/test';

import { AUTH_STATE, OWNER_EMAIL, OWNER_PASSWORD, RECOVERY_STATE } from '../constants.mjs';
import { totp } from './helpers';

// Logs in once and keeps the session for the other tests: logging in on
// every test would trip the panel's login rate limit. The owner has no 2FA
// yet, and an owner must: the panel opens nothing but the enrollment page
// until it is on (no way to skip it).
setup('entrar como dono e ativar a 2FA obrigatória', async ({ page }) => {
  await page.goto('/login');
  await page.locator('#email').fill(OWNER_EMAIL);
  await page.locator('#password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await expect(page).toHaveURL('/account/2fa');
  // Any other page sends the session back here.
  await page.goto('/backups');
  await expect(page).toHaveURL('/account/2fa');
  await expect(page.getByRole('heading', { level: 1, name: 'Ative a verificação em duas etapas' })).toBeVisible();

  const secret = (await page.locator('input[name="secret"]').inputValue()).trim();
  await page.locator('#totp-code').fill(totp(secret));
  await page.locator('#totp-password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Ativar 2FA' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Verificação em duas etapas ativada' })).toBeVisible();
  const codes = (await page.locator('.select-all').allTextContents()).map((c) => c.trim());
  expect(codes).toHaveLength(10);
  mkdirSync(dirname(RECOVERY_STATE), { recursive: true });
  writeFileSync(RECOVERY_STATE, JSON.stringify({ codes }));

  await page.getByRole('link', { name: 'Abrir o painel' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  await page.context().storageState({ path: AUTH_STATE });
});
