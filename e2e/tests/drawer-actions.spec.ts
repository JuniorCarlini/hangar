import { expect, test } from '@playwright/test';

import { createProject, hasDocker, newSlug } from './helpers';

// Acting on a service from its drawer (stop, start) keeps the drawer open on
// the same service: the operator stays where they were.

test.describe('ações na gaveta', () => {
  test.describe.configure({ mode: 'serial' });
  test.setTimeout(240_000);

  const slug = newSlug();

  test.beforeEach(async ({ page }) => {
    test.skip(!(await hasDocker(page)), 'Docker indisponível para o painel');
  });

  test('parar e iniciar mantêm a gaveta aberta', async ({ page }) => {
    await createProject(page, slug);
    await page.getByRole('link', { name: 'Novo serviço' }).first().click();
    const dialog = page.locator('dialog#new-service');
    await dialog.getByText('Redis (cache)', { exact: true }).click();
    const detail = page.getByRole('dialog', { name: /Novo Redis \(cache\)/ });
    await detail.getByRole('button', { name: 'Criar serviço' }).click();
    await expect(async () => {
      await page.goto(`/p/${slug}`);
      await expect(page.locator('.node[data-slug="cache"] .node-state.is-ok')).toBeVisible({ timeout: 2_000 });
    }).toPass({ timeout: 180_000 });

    await page.locator('.node[data-slug="cache"] .node-link').click();
    const drawer = page.locator('dialog#svc-panel');
    await expect(drawer).toBeVisible();

    // A marker on the page: it survives only if the page was not loaded again.
    await page.evaluate(() => { (window as any).__semRecarregar = true; });

    await drawer.getByRole('button', { name: 'Parar serviço' }).click();
    await page.getByRole('button', { name: 'Parar', exact: true }).click();

    await expect(page).toHaveURL(new RegExp(`/p/${slug}/s/cache`), { timeout: 60_000 });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('button', { name: 'Iniciar serviço', exact: true })).toBeVisible({ timeout: 60_000 });

    await drawer.getByRole('button', { name: 'Iniciar serviço', exact: true }).click();
    await expect(page).toHaveURL(new RegExp(`/p/${slug}/s/cache`), { timeout: 60_000 });
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('button', { name: 'Parar serviço', exact: true })).toBeVisible({ timeout: 60_000 });
    expect(await page.evaluate(() => (window as any).__semRecarregar)).toBe(true);
    // The card on the canvas follows the state without a reload too.
    await expect(page.locator('.node[data-slug="cache"] .node-state.is-ok')).toBeVisible({ timeout: 60_000 });
  });

  test('botão Logs abre os logs em tela cheia', async ({ page }) => {
    await page.goto(`/p/${slug}/s/cache`);
    const drawer = page.locator('dialog#svc-panel');
    await drawer.locator('[data-logs-open]').click();
    await expect(page).toHaveURL(/tab=logs&expand=1/);
    const full = page.locator('dialog.expand-dialog');
    await expect(full).toBeVisible();
    await expect(full.locator('#logs')).toBeVisible();
    // Escape puts the logs back in the drawer, which stays open.
    await page.keyboard.press('Escape');
    await expect(full).toHaveCount(0);
    await expect(drawer.locator('#logs')).toBeVisible();
  });

  test('largura da gaveta: arrastar, lembrar, alargar e voltar', async ({ page }) => {
    await page.setViewportSize({ width: 1400, height: 900 });
    await page.goto(`/p/${slug}/s/cache`);
    const drawer = page.locator('dialog#svc-panel');
    const panel = drawer.locator('.tuc-drawer__panel');
    await expect(panel).toBeVisible();
    const width = async () => (await panel.boundingBox())!.width;
    expect(Math.round(await width())).toBe(520);

    // Drag the grip on the left edge 300px to the left.
    const grip = drawer.locator('.svc-grip');
    const g = (await grip.boundingBox())!;
    await page.mouse.move(g.x + g.width / 2, g.y + 200);
    await page.mouse.down();
    await page.mouse.move(g.x + g.width / 2 - 150, g.y + 200, { steps: 5 });
    await page.mouse.move(g.x + g.width / 2 - 300, g.y + 200, { steps: 5 });
    await page.mouse.up();
    await expect(drawer).toBeVisible();
    expect(Math.abs((await width()) - 820)).toBeLessThan(6);

    // Remembered on the next page.
    await page.reload();
    await expect(panel).toBeVisible();
    expect(Math.abs((await width()) - 820)).toBeLessThan(6);

    // Double-click on the grip goes back to the default width.
    await drawer.locator('.svc-grip').dblclick();
    await expect.poll(width).toBe(520);

    // The head button widens, and again goes back.
    const wide = drawer.locator('[data-svc-wide]');
    await wide.click();
    await expect(wide).toHaveAttribute('aria-pressed', 'true');
    expect(await width()).toBeGreaterThan(800);
    await wide.click();
    await expect(wide).toHaveAttribute('aria-pressed', 'false');
    await expect.poll(width).toBe(520);
    await expect(drawer).toBeVisible();
  });
});
