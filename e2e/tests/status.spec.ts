import { expect, test } from '@playwright/test';

import { OWNER_EMAIL, OWNER_PASSWORD } from '../constants.mjs';

// Updates page and public status links (Etapa 11). None of it needs Docker.

test('página de atualizações abre pelo menu', async ({ page }) => {
  await page.goto('/');
  const nav = page.getByRole('navigation', { name: 'Navegação' });
  await nav.getByRole('link', { name: 'Atualizações', exact: true }).click();
  await expect(page).toHaveURL('/updates');
  await expect(page.getByRole('heading', { level: 1, name: 'Atualizações e vulnerabilidades' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Verificar agora' })).toBeVisible();
  await expect(page.getByText('Nenhuma verificação ainda.')).toBeVisible();
});

test.describe('links de status', () => {
  // At a stricter level, confirming sudo replaces the session, which would
  // log the saved session of the other tests out: this test logs in on its own.
  test.use({ storageState: { cookies: [], origins: [] } });

  test('criar, abrir sem login e revogar', async ({ page, browser }) => {
    await page.goto('/login');
    await page.locator('#email').fill(OWNER_EMAIL);
    await page.locator('#password').fill(OWNER_PASSWORD);
    await page.getByRole('button', { name: 'Continuar' }).click();
    await expect(page).toHaveURL('/');

    await page.getByRole('navigation', { name: 'Navegação' }).getByRole('link', { name: 'Links de status' }).click();
    await expect(page).toHaveURL('/status-links');
    await expect(page.getByRole('heading', { level: 1, name: 'Links de status' })).toBeVisible();

    // At the default security level (Médio) creating a link only asks for
    // the password again at Avançado: the form opens straight away.
    await page.getByRole('button', { name: 'Novo link' }).click();
    const dialog = page.locator('dialog#new-status-link');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('#sudo-code')).toHaveCount(0);
    await dialog.getByLabel('Nome', { exact: true }).fill('Monitor E2E');
    await dialog.getByRole('button', { name: 'Criar link' }).click();

    const created = page.getByRole('status').filter({ hasText: 'Link criado' });
    await expect(created).toBeVisible();
    const url = (await created.locator('code').first().textContent())?.trim() ?? '';
    expect(url).toMatch(/\/s\/[A-Za-z0-9_-]{43}$/);

    // Anyone with the link sees the status, without a session.
    const visitor = await browser.newContext();
    const pub = await visitor.newPage();
    await pub.goto(url);
    await expect(pub.getByRole('heading', { level: 1 })).toHaveCount(0);
    await expect(pub.getByText('Status do servidor')).toBeVisible();
    await expect(pub.getByText('Tudo funcionando')).toBeVisible();
    const json = await pub.request.get(url + '.json');
    expect(json.status()).toBe(200);
    expect(await json.json()).toHaveProperty('server.cpu_pct');
    const prom = await pub.request.get(url + '/metrics');
    expect(await prom.text()).toContain('hangar_server_cpu_percent');

    // The list counts the visit and never shows the token again.
    await page.goto('/status-links');
    const row = page.getByRole('row').filter({ hasText: 'Monitor E2E' });
    await expect(row).toBeVisible();
    await expect(page.locator('body')).not.toContainText(url.split('/s/')[1]);

    // Revoking asks first (red) and the link answers 404 right away.
    await row.getByRole('button', { name: /Revogar/ }).click();
    const confirm = page.getByRole('dialog', { name: 'Revogar este link?' });
    await expect(confirm).toBeVisible();
    await confirm.getByRole('button', { name: 'Revogar' }).click();
    await expect(page.getByText('Link revogado')).toBeVisible();

    for (const target of [url, url + '.json', url + '/metrics', url + '?tv=1']) {
      const res = await pub.request.get(target);
      expect(res.status(), target).toBe(404);
    }
    await visitor.close();
  });
});
