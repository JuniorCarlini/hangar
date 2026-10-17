import { expect, test } from '@playwright/test';

import { OWNER_EMAIL } from '../constants.mjs';
import { createProject, hasDocker, newSlug, openAccountMenu } from './helpers';

// Core flows: none of them needs Docker.

test.describe('login', () => {
  // A fresh browser, without the saved session.
  test.use({ storageState: { cookies: [], origins: [] } });

  test('sem sessão vai para o login', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL('/login');
    await expect(page.getByRole('button', { name: 'Continuar' })).toBeVisible();
  });

  test('senha errada mostra a mensagem genérica', async ({ page }) => {
    await page.goto('/login');
    await page.locator('#email').fill(OWNER_EMAIL);
    await page.locator('#password').fill('senha-errada-de-proposito');
    await page.getByRole('button', { name: 'Continuar' }).click();
    await expect(page.getByRole('alert')).toContainText('E-mail ou senha incorretos');
  });
});

test('visão geral abre com o menu lateral', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  const nav = page.getByRole('navigation', { name: 'Navegação' });
  await expect(nav.getByRole('link', { name: 'Visão geral' })).toBeVisible();
  await expect(nav.getByRole('link', { name: 'Domínios dinâmicos' })).toBeVisible();
  await expect(nav.getByRole('link', { name: 'Portas abertas' })).toBeVisible();
});

test('navegação pelo menu lateral', async ({ page }) => {
  await page.goto('/');
  const nav = page.getByRole('navigation', { name: 'Navegação' });

  await nav.getByRole('link', { name: 'Portas abertas' }).click();
  await expect(page).toHaveURL('/ports');
  await expect(page.getByRole('heading', { level: 1, name: 'Portas abertas no servidor' })).toBeVisible();

  await nav.getByRole('link', { name: 'Domínios dinâmicos' }).click();
  await expect(page).toHaveURL('/domains');
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible();

  await nav.getByRole('link', { name: 'Visão geral' }).click();
  await expect(page).toHaveURL('/');
});

// Clicking on before the page transition ends aborts it; the browser used
// to print "Transition was aborted" (vt.js marks those promises handled).
// Also no 404 for the favicon.
test('navegação rápida não deixa erro no console', async ({ page }) => {
  const errors: string[] = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(e.message));
  await page.addInitScript(() => {
    window.addEventListener('unhandledrejection', (e) => console.error('unhandled: ' + String(e.reason)));
  });
  await page.goto('/');
  const nav = page.getByRole('navigation', { name: 'Navegação' });
  for (const name of ['Portas abertas', 'Domínios dinâmicos', 'Alertas', 'Backups', 'Visão geral', 'Portas abertas', 'Visão geral']) {
    await nav.getByRole('link', { name }).first().click({ noWaitAfter: true });
    await page.waitForTimeout(60);
  }
  for (const q of ['Portas', 'Alertas', 'Visão geral']) {
    await page.keyboard.press('ControlOrMeta+k');
    await page.keyboard.type(q);
    await page.keyboard.press('Enter');
    await page.waitForTimeout(150);
  }
  await page.goBack();
  await page.goForward();
  await page.waitForLoadState('load');
  await page.waitForTimeout(800);
  expect(errors).toEqual([]);
});

test('página de portas sem portas mostra o estado vazio', async ({ page }) => {
  await page.goto('/ports');
  await expect(page.getByText('Nenhuma porta aberta')).toBeVisible();
});

test('menu da conta abre e leva para Minha conta', async ({ page }) => {
  await page.goto('/');
  await openAccountMenu(page);
  const menu = page.locator('#user-menu');
  await expect(menu).toContainText(OWNER_EMAIL);
  await menu.getByText('Minha conta', { exact: true }).click();
  await expect(page).toHaveURL('/account');
});

test('trocar o tema pelo menu da conta', async ({ page }) => {
  await page.goto('/');
  const html = page.locator('html');
  await expect(html).not.toHaveAttribute('data-theme', /.*/);

  await openAccountMenu(page);
  await page.locator('#user-menu').getByTitle('Claro', { exact: true }).click();
  await expect(html).toHaveAttribute('data-theme', 'light');

  await openAccountMenu(page);
  await page.locator('#user-menu').getByTitle('Escuro', { exact: true }).click();
  await expect(html).toHaveAttribute('data-theme', 'dark');

  // Back to "system", so the other tests see the default.
  await openAccountMenu(page);
  await page.locator('#user-menu').getByTitle('Sistema', { exact: true }).click();
  await expect(html).not.toHaveAttribute('data-theme', /.*/);
});

test('sair pede confirmação e cancelar mantém a sessão', async ({ page }) => {
  await page.goto('/');
  await openAccountMenu(page);
  await page.locator('#user-menu').getByText('Sair da conta', { exact: true }).click();

  const dialog = page.getByRole('dialog', { name: 'Sair da conta?' });
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancelar' }).click();
  await expect(dialog).toBeHidden();

  await page.reload();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
});

test('janela de novo projeto abre e fecha', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('heading', { name: 'Novo projeto' })).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancelar' }).click();
  await expect(dialog).toBeHidden();
});

// Creating a project creates its Docker network, so it needs Docker; without
// it the dialog must say why.
test('criar projeto abre o canvas vazio', async ({ page }) => {
  test.skip(!(await hasDocker(page)), 'Docker indisponível para o painel');
  const slug = newSlug();
  await createProject(page, slug);

  await expect(page.getByText('Nenhum serviço ainda.')).toBeVisible();
  await expect(page.getByRole('link', { name: 'Novo serviço' }).first()).toBeVisible();
  // The project shows up in the sidebar.
  await expect(page.getByRole('navigation', { name: 'Navegação' }).getByRole('link', { name: slug })).toBeVisible();
});

test('nome técnico inválido é barrado pelo navegador', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  const slug = dialog.getByLabel('Nome técnico');
  await slug.fill('Inválido!');
  // The pattern must be a valid regex for the browser (v flag), or the
  // check is silently skipped.
  expect(await slug.evaluate((el: HTMLInputElement) => el.validity.patternMismatch)).toBe(true);
  await dialog.getByRole('button', { name: 'Criar projeto' }).click();
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL('/');
});

test('sem Docker, criar projeto explica o motivo', async ({ page }) => {
  test.skip(await hasDocker(page), 'só sem Docker');
  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  await dialog.getByLabel('Nome técnico').fill(newSlug());
  await dialog.getByRole('button', { name: 'Criar projeto' }).click();
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('alert')).toContainText('Docker');
});

test('projeto repetido volta com erro na janela', async ({ page }) => {
  test.skip(!(await hasDocker(page)), 'Docker indisponível para o painel');
  const slug = newSlug();
  await createProject(page, slug);

  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  await dialog.getByLabel('Nome técnico').fill(slug);
  await dialog.getByRole('button', { name: 'Criar projeto' }).click();
  // The server answers with the dialog open again, the error and the value.
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('alert')).toBeVisible();
  await expect(dialog.getByLabel('Nome técnico')).toHaveValue(slug);
});
