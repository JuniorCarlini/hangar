import { expect, test } from '@playwright/test';

import { OWNER_EMAIL, OWNER_PASSWORD } from '../constants.mjs';
import { openAccountMenu, recoveryCode } from './helpers';

// "Trancar painel" ends every session, the saved one included, so this file
// runs last (the name sorts after the others) and the panel stays locked
// until the throwaway server goes away.

test('trancar o painel derruba a sessão e só o servidor entra', async ({ page }) => {
  await page.goto('/');
  await openAccountMenu(page);
  await page.locator('#user-menu').getByText('Trancar painel', { exact: true }).click();

  const dialog = page.getByRole('dialog', { name: 'Trancar o painel?' });
  await expect(dialog).toBeVisible();
  // Cancel first: nothing happens.
  await dialog.getByRole('button', { name: 'Cancelar' }).click();
  await expect(dialog).toBeHidden();
  await page.reload();
  await expect(page).toHaveURL('/');

  await openAccountMenu(page);
  await page.locator('#user-menu').getByText('Trancar painel', { exact: true }).click();
  await page.getByRole('dialog', { name: 'Trancar o painel?' }).getByRole('button', { name: 'Trancar agora' }).click();

  await expect(page).toHaveURL('/login');
  await expect(page.getByRole('status')).toContainText('hangard lockdown off');

  // The old session is gone.
  await page.goto('/');
  await expect(page).toHaveURL('/login');

  // The tests reach the panel on localhost, like an SSH tunnel: logging in
  // still works and every page says the panel is locked.
  await page.locator('#email').fill(OWNER_EMAIL);
  await page.locator('#password').fill(OWNER_PASSWORD);
  await page.getByRole('button', { name: 'Continuar' }).click();
  await expect(page).toHaveURL('/login/2fa');
  await page.locator('#code').fill(recoveryCode());
  await page.getByRole('button', { name: 'Entrar' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByText(/Painel trancado: só responde pelo próprio servidor/)).toBeVisible();
  await page.goto('/alerts');
  await expect(page.locator('#history')).toContainText('Painel trancado');
});
