import { expect, test as setup } from '@playwright/test';

import { AUTH_STATE, OWNER_EMAIL, OWNER_PASSWORD } from '../constants.mjs';

// Logs in once and keeps the session for the other tests: logging in on
// every test would trip the panel's login rate limit.
setup('entrar como dono', async ({ page }) => {
  await page.goto('/login');
  await page.locator('#email').fill(OWNER_EMAIL);
  await page.locator('#password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  await page.context().storageState({ path: AUTH_STATE });
});
