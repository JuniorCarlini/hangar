import { expect, type Page } from '@playwright/test';

import { PROJECT_PREFIX } from '../constants.mjs';

// newSlug is a project slug unique to this run, with the prefix the
// teardown looks for.
export function newSlug(): string {
  return PROJECT_PREFIX + Date.now().toString(36) + Math.floor(Math.random() * 1296).toString(36);
}

// hasDocker asks the panel itself: without Docker the overview shows the
// "Docker unavailable" alert.
export async function hasDocker(page: Page): Promise<boolean> {
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1, name: 'Visão geral' })).toBeVisible();
  return !(await page.getByText('Docker indisponível').isVisible());
}

// openAccountMenu opens the account dropdown in the top bar.
export async function openAccountMenu(page: Page) {
  await page.locator('[data-tuc-dropdown="#user-menu"]').click();
  await expect(page.locator('#user-menu')).toBeVisible();
}

// createProject creates a project through the sidebar dialog and waits for
// its (empty) canvas.
export async function createProject(page: Page, slug: string, name = 'Projeto E2E') {
  await page.goto('/');
  await page.getByRole('link', { name: 'Novo projeto' }).click();
  const dialog = page.locator('dialog#new-project');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('Nome', { exact: true }).fill(name);
  await dialog.getByLabel('Nome técnico').fill(slug);
  await dialog.getByRole('button', { name: 'Criar projeto' }).click();
  await expect(page).toHaveURL(new RegExp(`/p/${slug}$`));
}
