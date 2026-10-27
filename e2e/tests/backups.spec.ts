import { readFileSync } from 'node:fs';

import { expect, test } from '@playwright/test';

import { OWNER_EMAIL, OWNER_PASSWORD } from '../constants.mjs';

// Backups (docs/09). None of these needs Docker: the kit is generated and
// confirmed entirely in the browser, and the panel only ever sees the
// public key and the confirmation code.

test('página de backups mostra a configuração e o menu', async ({ page }) => {
  await page.goto('/');
  const nav = page.getByRole('navigation', { name: 'Navegação' });
  await nav.getByRole('link', { name: 'Backups' }).click();
  await expect(page).toHaveURL('/backups');
  await expect(page.getByRole('heading', { level: 1, name: 'Backups' })).toBeVisible();
  // Nothing configured yet: the list tab points to the configuration.
  await expect(page.getByText('Para começar, cadastre um destino.')).toBeVisible();
  await page.getByRole('link', { name: 'Abrir configuração' }).click();
  await expect(page).toHaveURL('/backups?tab=config');
  await expect(page.getByRole('heading', { name: 'Segurança dos backups' })).toBeVisible();
  await expect(page.getByText('Limpeza automática no bucket')).toBeVisible();
});

test.describe('kit', () => {
  // Re-confirming identity rotates the session: use a session of its own,
  // so the shared one the other tests use stays valid.
  test.use({ storageState: { cookies: [], origins: [] } });

  test('kit gerado no navegador: baixar, registrar e confirmar com o arquivo', async ({ page }) => {
    await page.goto('/login');
    await page.locator('#email').fill(OWNER_EMAIL);
    await page.locator('#password').fill(OWNER_PASSWORD);
    await page.getByRole('button', { name: 'Continuar' }).click();
    await expect(page).toHaveURL('/');
    await page.goto('/backups/kit');
    // Keys and destinations ask to confirm it's you first.
    await page.locator('#sudo-code').fill(OWNER_PASSWORD);
    await page.getByRole('button', { name: 'Confirmar' }).click();
    await expect(page).toHaveURL('/backups/kit');

    // No request may carry the private key: watch every one.
    const sent: string[] = [];
    page.on('request', (r) => sent.push((r.url() + ' ' + (r.postData() ?? '')).toUpperCase()));

    await page.locator('#kit-label').fill('E2E');
    await page.getByRole('button', { name: 'Gerar chaves no navegador' }).click();
    await expect(page.locator('#kit-out')).toBeVisible();
    const publicKey = (await page.locator('#kit-public').textContent())?.trim() ?? '';
    expect(publicKey).toMatch(/^age1[02-9ac-hj-np-z]{58}$/);

    // The register button waits until the kit was downloaded and the box ticked.
    const register = page.getByRole('button', { name: 'Registrar chave pública' });
    await expect(register).toBeDisabled();
    const [download] = await Promise.all([
      page.waitForEvent('download'),
      page.getByRole('button', { name: 'Baixar hangar-kit.txt' }).click(),
    ]);
    expect(download.suggestedFilename()).toBe('hangar-kit.txt');
    const kitPath = await download.path();
    const kit = readFileSync(kitPath, 'utf8');
    expect(kit).toContain(publicKey);
    const secret = kit.split('\n').find((l) => l.startsWith('AGE-SECRET-KEY-1')) ?? '';
    expect(secret).toMatch(/^AGE-SECRET-KEY-1[02-9AC-HJ-NP-Z]{58}$/);
    await page.getByLabel('Guardei o kit em lugar seguro, fora do servidor.').check();
    await expect(register).toBeEnabled();
    await register.click();
    // The redirect's ?ok= becomes a toast and leaves the address right away.
    await expect(page.getByText('Chave pública registrada.')).toBeVisible();
    await expect(page).toHaveURL('/backups');
    // The keys card lives on the configuration tab now.
    await page.goto('/backups?tab=config');
    await expect(page.getByText('aguardando confirmação')).toBeVisible();

    // Confirm with the file: read in the browser, only the code is sent.
    // The download is saved under a random name without extension, which
    // the picker (.txt/.age only) would refuse: hand it over as the user's
    // own hangar-kit.txt.
    await page.locator('input[data-kit-file]').setInputFiles({
      name: 'hangar-kit.txt',
      mimeType: 'text/plain',
      buffer: Buffer.from(kit),
    });
    await expect(page.getByText('Kit conferido: código preenchido.')).toBeVisible();
    await page.getByRole('button', { name: 'Confirmar que guardei' }).click();
    await expect(page.getByText('Kit confirmado. Esta chave já cifra os backups.')).toBeVisible();
    await page.goto('/backups?tab=config');
    await expect(page.locator('td', { hasText: 'confirmada' }).first()).toBeVisible();

    for (const s of sent) {
      expect(s).not.toContain(secret.slice(16, 40));
    }
  });
});
