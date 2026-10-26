import { expect, test } from '@playwright/test';

// Alerts and notifications (Etapa 8). Nothing here sends a real message:
// the channel created is never tested, so no request leaves the machine.

test('página de alertas abre pelo menu lateral', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('navigation', { name: 'Navegação' }).getByRole('link', { name: 'Alertas' }).click();
  await expect(page).toHaveURL('/alerts');
  await expect(page.getByRole('heading', { level: 1, name: 'Alertas e notificações' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Canais' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Regras do servidor' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Alertas de segurança' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Histórico' })).toBeVisible();
});

test('adicionar canal do Telegram sem mostrar o token', async ({ page }) => {
  const token = '123456789:AAH-e2e_token_que_nunca_aparece_na_tela0';
  await page.goto('/alerts');
  await page.getByRole('button', { name: 'Novo canal' }).click();
  await page.locator('#new-channel-menu').getByText('Telegram', { exact: true }).click();
  const dialog = page.locator('dialog#channel-telegram');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Nome').fill('Plantão E2E');
  await dialog.getByLabel('Token do bot').fill(token);
  await dialog.getByLabel('Chat ID').fill('-100123');
  await dialog.getByRole('button', { name: 'Adicionar canal' }).click();

  // The redirect's ?ok= becomes a toast and leaves the address right away.
  await expect(page.getByText('Canal adicionado.')).toBeVisible();
  await expect(page).toHaveURL(/\/alerts#channels$/);
  const row = page.getByRole('row', { name: /Plantão E2E/ });
  await expect(row).toContainText('chat -100123');
  await expect(row).toContainText('Ativo');
  expect(await page.content()).not.toContain(token);

  // Adding a channel is a security alert: it shows in the history.
  await expect(page.locator('#history')).toContainText('Canal de alerta adicionado');
});

test('canal com dados inválidos volta com a janela aberta', async ({ page }) => {
  await page.goto('/alerts');
  await page.getByRole('button', { name: 'Novo canal' }).click();
  await page.locator('#new-channel-menu').getByText('Telegram', { exact: true }).click();
  const dialog = page.locator('dialog#channel-telegram');
  await dialog.getByLabel('Token do bot').fill('token-errado');
  await dialog.getByLabel('Chat ID').fill('-1');
  await dialog.getByRole('button', { name: 'Adicionar canal' }).click();
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('alert')).toContainText('Token do bot inválido');
  await expect(dialog.getByLabel('Token do bot')).toHaveValue('');
});

test('regras do servidor são salvas', async ({ page }) => {
  await page.goto('/alerts');
  const disk = page.locator('input[name="v_host_disk"]');
  await disk.fill('80');
  await page.getByRole('button', { name: 'Salvar regras' }).click();
  await expect(page.getByText('Regras salvas.')).toBeVisible();
  await expect(page.locator('input[name="v_host_disk"]')).toHaveValue('80');
  await disk.fill('85');
  await page.getByRole('button', { name: 'Salvar regras' }).click();
  await expect(page.locator('input[name="v_host_disk"]')).toHaveValue('85');
});

test('silenciar e reativar alertas do servidor', async ({ page }) => {
  await page.goto('/alerts');
  await page.getByRole('button', { name: 'Silenciar' }).click();
  await expect(page.getByText(/Alertas do servidor silenciados até/)).toBeVisible();
  await page.getByRole('button', { name: 'Reativar alertas' }).click();
  await expect(page.getByRole('button', { name: 'Silenciar' })).toBeVisible();
});

test('sino mostra os alertas recentes', async ({ page }) => {
  await page.goto('/');
  await page.locator('[data-tuc-dropdown="#alerts-menu"]').click();
  const menu = page.locator('#alerts-menu');
  await expect(menu).toBeVisible();
  await expect(menu).toContainText('Alertas recentes');
  await menu.getByText('Ver todos os alertas').click();
  await expect(page).toHaveURL('/alerts');
  // Opening the page marks everything as seen: no dot on the bell.
  await page.goto('/');
  await expect(page.locator('[data-unread]')).toHaveCount(0);
});

test('revelar segredo do canal pede confirmação de identidade', async ({ page }) => {
  await page.goto('/alerts');
  const row = page.getByRole('row', { name: /Plantão E2E/ });
  await row.getByRole('button', { name: 'Revelar o segredo de Plantão E2E' }).click();
  const dialog = page.locator('dialog#sudo-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('heading')).toBeVisible();
  await dialog.getByRole('button', { name: 'Fechar' }).click();
  await expect(dialog).toBeHidden();
});
