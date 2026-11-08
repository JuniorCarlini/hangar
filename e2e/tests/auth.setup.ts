import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

import { expect, test as setup } from '@playwright/test';

import { AUTH_STATE, OWNER_EMAIL, OWNER_PASSWORD, RECOVERY_STATE } from '../constants.mjs';
import { totp } from './helpers';

// Logs in once and keeps the session for the other tests: logging in on
// every test would trip the panel's login rate limit. 2FA is optional, so
// the owner lands on the panel right away; it then turns 2FA on from "My
// account", as recommended there, because the other tests sign in with it.
setup('entrar como dono e ativar a 2FA', async ({ page }) => {
  await page.goto('/login');
  await page.locator('#email').fill(OWNER_EMAIL);
  await page.locator('#password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();

  await page.goto('/account#totp');
  const card = page.locator('#totp');
  await expect(card.getByText('Recomendado: sua conta alcança todos os projetos')).toBeVisible();
  const secret = (await card.locator('input[name="secret"]').inputValue()).trim();
  await card.locator('#totp-code').fill(totp(secret));
  await card.locator('#totp-password').fill(OWNER_PASSWORD);
  await card.getByRole('button', { name: 'Ativar 2FA' }).click();
  const codes = (await page.locator('#totp span.select-all').allTextContents()).map((c) => c.trim());
  expect(codes).toHaveLength(10);
  mkdirSync(dirname(RECOVERY_STATE), { recursive: true });
  writeFileSync(RECOVERY_STATE, JSON.stringify({ codes }));

  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  await page.context().storageState({ path: AUTH_STATE });
});
