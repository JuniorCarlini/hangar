import { expect, test } from '@playwright/test';

// The /_pista catalog: tokens in both themes and the components working.

test('catálogo mostra tokens e componentes', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));

  await page.goto('/_pista');
  await expect(page.getByRole('heading', { level: 1, name: 'Catálogo do Pista' })).toBeVisible();
  for (const section of ['Cores', 'Tipografia', 'Botões', 'Etiquetas', 'Avisos', 'Campos', 'Tabela', 'Cartões do canvas']) {
    await expect(page.getByRole('heading', { level: 2, name: section })).toBeVisible();
  }

  // Each theme panel paints the same token with its own value.
  const bg = (theme: string) =>
    page.locator(`[data-pista-theme="${theme}"] .bg-bg`).first().evaluate((el) => getComputedStyle(el).backgroundColor);
  expect(await bg('dark')).toBe('rgb(11, 13, 16)');
  expect(await bg('light')).toBe('rgb(255, 255, 255)');

  // The custom select is mounted by Tucano.
  await expect(page.locator('#pista-forms .tuc-select').first()).toBeVisible();

  // No CSP violations or script errors on the page.
  expect(errors).toEqual([]);
});

test('catálogo abre os diálogos de confirmação em cada tom', async ({ page }) => {
  await page.goto('/_pista');
  const feedback = page.locator('#pista-feedback');
  for (const [label, tone] of [['Padrão', ''], ['Sucesso', 'is-success'], ['Atenção', 'is-warning'], ['Perigo', 'is-danger']]) {
    await feedback.getByRole('button', { name: label, exact: true }).first().click();
    const dialog = page.getByRole('dialog', { name: 'Confirmar esta ação?' });
    await expect(dialog).toBeVisible();
    if (tone) await expect(dialog).toHaveClass(new RegExp(tone));
    await dialog.getByRole('button', { name: 'Cancelar' }).click();
    await expect(dialog).toBeHidden();
  }
  // Nothing was submitted: still on the catalog.
  await expect(page).toHaveURL('/_pista');
});

test('catálogo mostra toasts', async ({ page }) => {
  await page.goto('/_pista');
  await page.locator('#pista-feedback [data-demo-toast][data-type="success"]').click();
  await expect(page.getByText('Variável salva.')).toBeVisible();
});
