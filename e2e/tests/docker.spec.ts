import { expect, test } from '@playwright/test';

import { createProject, hasDocker, loginAsOwner, newSlug, recoveryCode } from './helpers';

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
    await createProject(page, slug);
    // "Novo serviço" opens a modal over the canvas.
    await page.getByRole('link', { name: 'Novo serviço' }).first().click();
    const dialog = page.locator('dialog#new-service');
    await expect(dialog).toBeVisible();

    // Picking a template opens its own modal with the details and the form.
    await dialog.getByText('Redis (cache)', { exact: true }).click();
    const detail = page.getByRole('dialog', { name: /Novo Redis \(cache\)/ });
    await expect(detail).toBeVisible();
    // The name follows the template and shows the internal address.
    await expect(detail.getByLabel('Nome', { exact: true })).toHaveValue('cache');
    await expect(detail.locator('[data-slug-out]')).toHaveText('cache');
    await detail.getByRole('button', { name: 'Criar serviço' }).click();

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
    await expect(drawer.getByRole('cell', { name: 'REDIS_PASSWORD', exact: true })).toBeVisible();

    // Closing goes back to the canvas.
    await drawer.getByRole('button', { name: 'Fechar' }).first().click();
    await expect(page).toHaveURL(new RegExp(`/p/${slug}$`));
  });

  test('link direto abre a gaveta na aba pedida', async ({ page }) => {
    // A fresh page on the service's address: the drawer opens with the
    // page (not only after every image loaded) and stays on that address.
    await page.goto(`/p/${slug}/s/cache?tab=variables`);
    const drawer = page.locator('dialog#svc-panel');
    await expect(drawer).toBeVisible();
    await expect(drawer.getByRole('tab', { name: 'Variáveis' })).toHaveAttribute('aria-selected', 'true');
    await page.waitForTimeout(2500); // past the canvas's first refresh
    await expect(drawer).toBeVisible();
    await expect(page).toHaveURL(new RegExp(`/p/${slug}/s/cache\\?tab=variables$`));
  });

  test('segredos ficam mascarados até revelar com confirmação de identidade', async ({ page }) => {
    // Confirming identity replaces the session: sign in on a session of its
    // own, so the shared one of the other tests stays valid.
    await page.context().clearCookies();
    await loginAsOwner(page);
    await page.goto(`/p/${slug}/s/cache?tab=variables`);
    const drawer = page.locator('dialog#svc-panel');
    const row = drawer.getByRole('row', { name: /REDIS_PASSWORD/ });
    await expect(row.locator('[data-secret-mask]')).toBeVisible();
    // The .env editor holds the secret as a placeholder that saving keeps.
    await drawer.getByRole('button', { name: '.env', exact: true }).click();
    const modal = page.locator('dialog#env-bulk');
    await expect(modal).toBeVisible();
    expect(await modal.locator('#bulk-env').inputValue()).toContain('REDIS_PASSWORD=••••');
    await modal.getByRole('button', { name: 'Cancelar' }).click();

    // Revealing asks who you are first (sudo), then shows the value once.
    await row.getByRole('button', { name: 'Revelar o valor de REDIS_PASSWORD' }).click();
    const sudo = page.locator('dialog#sudo-dialog');
    await expect(sudo).toBeVisible();
    await sudo.locator('#sudo-code').fill(recoveryCode());
    await sudo.getByRole('button', { name: 'Confirmar' }).click();
    await drawer.getByRole('row', { name: /REDIS_PASSWORD/ }).getByRole('button', { name: 'Revelar o valor de REDIS_PASSWORD' }).click();
    await expect(page.getByText('Valor revelado nesta tela')).toBeVisible();
    await expect(drawer.getByRole('row', { name: /REDIS_PASSWORD/ }).locator('[data-secret-mask]')).toHaveCount(0);
    // A plain visit masks it again.
    await page.goto(`/p/${slug}/s/cache?tab=variables`);
    await expect(drawer.getByRole('row', { name: /REDIS_PASSWORD/ }).locator('[data-secret-mask]')).toBeVisible();
  });

  test('gráfico do serviço mostra a barra apontada por cima da gaveta', async ({ page }) => {
    // The panel reads the container every 10 s: wait for the first bar.
    const drawer = page.locator('dialog#svc-panel');
    const cpu = drawer.locator('svg[data-spark]').first();
    await expect(async () => {
      await page.goto(`/p/${slug}/s/cache`);
      await expect(cpu.locator('rect[data-at]').first()).toBeAttached({ timeout: 1_000 });
    }).toPass({ timeout: 60_000 });
    await cpu.scrollIntoViewIfNeeded();
    const box = await cpu.boundingBox();
    if (!box) throw new Error('chart without a box');
    await page.mouse.move(box.x + 2, box.y + box.height / 2);
    // The card is in the top layer, so it shows over the drawer.
    const tip = page.locator('#spark-tip');
    await expect(tip).toBeVisible();
    await expect(tip).toContainText('CPU');
    expect(await tip.evaluate((el) => el.matches(':popover-open'))).toBeTruthy();
  });

  test('repositório por URL recusa endereço sem HTTPS e não devolve o token', async ({ page }) => {
    await page.goto(`/p/${slug}/new`);
    // Without a GitHub credential, "Meus repositórios" offers the address
    // form, a modal over the new-service one.
    await page.getByRole('tab', { name: 'Meus repositórios' }).click();
    await page.getByRole('button', { name: 'Usar o endereço de um repositório (URL)' }).click();
    const dialog = page.locator('dialog#repo-url');
    await expect(dialog).toBeVisible();
    await dialog.locator('#ns-git-repo').fill('http://github.com/dono/app');
    // The name is suggested from the repository.
    await expect(dialog.locator('#ns-git-name')).toHaveValue('app');
    await dialog.locator('#git-credential').selectOption('new');
    await dialog.locator('#git-token').fill('ghp_naoDeveVoltar123');
    await dialog.getByRole('button', { name: 'Criar e fazer deploy' }).click();

    // The server answers with the same modal open, the error and the address.
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('alert')).toContainText('HTTPS');
    await expect(dialog.locator('#ns-git-repo')).toHaveValue('http://github.com/dono/app');
    await expect(dialog.locator('#git-token')).toHaveValue('');
    expect(await page.content()).not.toContain('ghp_naoDeveVoltar123');
  });

  test('logs do serviço chegam ao vivo', async ({ page }) => {
    await page.goto(`/p/${slug}/s/cache?tab=logs`);
    const logs = page.locator('#logs');
    await expect(logs).toBeVisible();
    // Redis prints its banner on start.
    await expect(logs).toContainText(/Ready to accept connections|Server initialized/i, { timeout: 30_000 });
  });

  // Last: it changes the service's variables (a reference to a service
  // that does not exist only warns until the next deploy).
  test('editor do .env colore enquanto digita, numera as linhas e rola de lado', async ({ page }) => {
    await page.goto(`/p/${slug}/s/cache?tab=variables`);
    const drawer = page.locator('dialog#svc-panel');
    await drawer.getByRole('button', { name: '.env', exact: true }).click();
    const modal = page.locator('dialog#env-bulk');
    await expect(modal).toBeVisible();
    const editor = modal.locator('[data-env-editor]');
    await expect(editor).toHaveClass(/is-live/);
    const ta = modal.locator('#bulk-env');

    // Big: almost the whole viewport, like the terminal.
    const vp = page.viewportSize()!;
    // (polled: the panel grows from 95% as it opens)
    const panel = modal.locator('.tuc-modal__panel');
    await expect.poll(async () => (await panel.boundingBox())!.width).toBeGreaterThan(vp.width * 0.9);
    await expect.poll(async () => (await panel.boundingBox())!.height).toBeGreaterThan(vp.height * 0.9);

    // Keep what is there (saving replaces the whole file) and type below it.
    const before = await ta.inputValue();
    await ta.focus();
    await ta.evaluate((el: HTMLTextAreaElement) => el.setSelectionRange(el.value.length, el.value.length));
    const long =
      'FCM_SERVICE_ACCOUNT={"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\\nMIIE' +
      'A'.repeat(400) +
      '\\n-----END PRIVATE KEY-----\\n"}';
    let typed = before && !before.endsWith('\n') ? '\n' : '';
    typed += '\n# =====\n# Banco\n# =====\nDB_HOST=${{db.HOST}}\nDB_URL=postgres://${DB_USER}@host/db\n\n# Firebase\n';
    await page.keyboard.type(typed);
    // Colored as typed, not only on load.
    await expect(editor.locator('.env-ref')).toHaveText('${{db.HOST}}');
    await expect(editor.locator('.env-k', { hasText: 'DB_HOST' })).toBeVisible();
    await expect(editor.locator('.env-c', { hasText: '# Banco' })).toBeVisible();
    await expect(editor.locator('.env-c', { hasText: '# =====' })).toHaveCount(2);
    await expect(editor.locator('.env-var')).toHaveText('${DB_USER}');
    // A long value pasted in one go, then a line without "=".
    await page.keyboard.insertText(long + '\n');
    await page.keyboard.type('linha sem igual\n');
    await expect(editor.locator('.env-bad')).toHaveText('linha sem igual');
    await expect(modal.locator('[data-env-invalid]')).toHaveText('1 linha sem “=”');

    const value = await ta.inputValue();
    expect(value).toBe(before + typed + long + '\nlinha sem igual\n');
    // One number per line.
    const nums = await editor.locator('[data-env-gutter]').textContent();
    expect(nums!.split('\n').length).toBe(value.split('\n').length);

    // No soft wrap: the long line scrolls sideways inside the editor, the
    // colored text follows and the gutter stays put.
    expect(await ta.evaluate((el) => el.scrollWidth > el.clientWidth)).toBe(true);
    await ta.evaluate((el) => {
      el.scrollLeft = 300;
      el.scrollTop = 0;
    });
    await expect(editor.locator('.env-editor__hl')).toHaveCSS('transform', 'matrix(1, 0, 0, 1, -300, 0)');
    await expect(editor.locator('[data-env-gutter]')).toHaveCSS('transform', /none|matrix\(1, 0, 0, 1, 0, -?0\)/);

    // The marked line only warns here (the server refuses it): take it out
    // as one would, and the mark goes with it.
    await ta.evaluate((el: HTMLTextAreaElement) => {
      const at = el.value.lastIndexOf('linha sem igual\n');
      el.focus();
      el.setSelectionRange(at, at + 'linha sem igual\n'.length);
    });
    await page.keyboard.press('Backspace');
    await expect(modal.locator('[data-env-invalid]')).toBeHidden();
    await expect(editor.locator('.env-bad')).toHaveCount(0);
    const saved = await ta.inputValue();
    expect(saved).toBe(before + typed + long + '\n');

    // Saved as written, and the editor reopens with the same text.
    await modal.getByRole('button', { name: 'Salvar' }).click();
    // The page cleans ?ok=env off the address: wait for the saved state,
    // the warning about the reference to a service that does not exist.
    await expect(page.getByText('DB_HOST aponta para o serviço db')).toBeVisible();
    await page.goto(`/p/${slug}/s/cache?tab=variables`);
    await drawer.getByRole('button', { name: '.env', exact: true }).click();
    await expect(modal).toBeVisible();
    expect((await ta.inputValue()).trimEnd()).toBe(saved.trimEnd());
    await expect(editor.locator('.env-ref')).toHaveText('${{db.HOST}}');
  });
});
