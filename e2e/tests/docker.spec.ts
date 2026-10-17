import { expect, test } from '@playwright/test';

import { createProject, hasDocker, newSlug } from './helpers';

// Flows that start real containers. They skip themselves when the panel
// has no Docker (e.g. a CI runner without it); the teardown removes what
// they create.

test.describe('com Docker', () => {
  test.describe.configure({ mode: 'serial' });
  // Pulling an image can take a while on a cold machine.
  test.setTimeout(240_000);

  const slug = newSlug();

  test.beforeEach(async ({ page }) => {
    test.skip(!(await hasDocker(page)), 'Docker indisponível para o painel');
  });

  test('criar serviço a partir de template', async ({ page }) => {
    await createProject(page, slug, 'Projeto E2E Docker');
    // "Novo serviço" opens a modal over the canvas.
    await page.getByRole('link', { name: 'Novo serviço' }).first().click();
    const dialog = page.locator('dialog#new-service');
    await expect(dialog).toBeVisible();

    await dialog.getByText('Redis (cache)', { exact: true }).click();
    // The name follows the template and shows the internal address.
    await expect(dialog.locator('#ns-tpl-name')).toHaveValue('cache');
    await expect(dialog.locator('[data-template-form] [data-slug-out]')).toHaveText('cache');
    await dialog.getByRole('button', { name: 'Criar serviço' }).click();

    // The card shows up on the canvas and the container comes up.
    const card = page.locator('.node[data-slug="cache"]');
    await expect(card).toBeVisible({ timeout: 30_000 });
    await expect(async () => {
      await page.goto(`/p/${slug}`);
      await expect(page.locator('.node[data-slug="cache"] .node-state.is-ok')).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 180_000 });
  });

  test('gaveta do serviço abre com as abas', async ({ page }) => {
    await page.goto(`/p/${slug}`);
    await page.locator('.node[data-slug="cache"] .node-link').click();
    await expect(page).toHaveURL(new RegExp(`/p/${slug}/s/cache`));

    const drawer = page.locator('dialog#svc-panel');
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('heading', { name: 'cache' })).toBeVisible();
    const tabs = drawer.getByRole('tablist');
    for (const tab of ['Visão', 'Variáveis', 'Rede', 'Logs', 'Configurações']) {
      await expect(tabs.getByRole('tab', { name: tab })).toBeVisible();
    }

    await tabs.getByRole('tab', { name: 'Variáveis' }).click();
    await expect(page).toHaveURL(/tab=variables/);
    await expect(drawer.getByText('REDIS_PASSWORD')).toBeVisible();

    // Closing goes back to the canvas.
    await drawer.getByRole('button', { name: 'Fechar' }).first().click();
    await expect(page).toHaveURL(new RegExp(`/p/${slug}$`));
  });

  test('aba Repositório Git recusa endereço sem HTTPS e não devolve o token', async ({ page }) => {
    await page.goto(`/p/${slug}/new`);
    await page.getByRole('tab', { name: 'Repositório Git' }).click();
    await page.locator('#ns-git-repo').fill('http://github.com/dono/app');
    // The name is suggested from the repository.
    await expect(page.locator('#ns-git-name')).toHaveValue('app');
    await page.locator('#git-credential').selectOption('new');
    await page.locator('#git-token').fill('ghp_naoDeveVoltar123');
    await page.getByRole('button', { name: 'Criar e fazer deploy' }).click();

    await expect(page.getByRole('alert')).toContainText('HTTPS');
    await expect(page.getByRole('tab', { name: 'Repositório Git' })).toHaveAttribute('aria-selected', 'true');
    await expect(page.locator('#ns-git-repo')).toHaveValue('http://github.com/dono/app');
    await expect(page.locator('#git-token')).toHaveValue('');
    expect(await page.content()).not.toContain('ghp_naoDeveVoltar123');
  });

  test('logs do serviço chegam ao vivo', async ({ page }) => {
    await page.goto(`/p/${slug}/s/cache?tab=logs`);
    const logs = page.locator('#logs');
    await expect(logs).toBeVisible();
    // Redis prints its banner on start.
    await expect(logs).toContainText(/Ready to accept connections|Server initialized/i, { timeout: 30_000 });
  });
});
