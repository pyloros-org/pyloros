import { test, expect } from '../fixtures';

/**
 * Page shell: all panels render, the SSE stream connects, and the initial
 * empty states show. Runs first (numeric filename prefix) so the worker's
 * audit ring buffer is still empty when we assert "No audit entries."
 */
test.describe('dashboard shell', () => {
  test('renders panels, connects SSE, shows empty states', async ({ page, pyloros }) => {
    await page.goto(pyloros.dashboardUrl);

    // Panel headings present.
    await expect(page.getByRole('heading', { name: 'Pending approvals' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Active timeboxed rules' })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Audit log' })).toBeVisible();

    // SSE connected (onopen).
    await expect(page.locator('#stream-status')).toHaveText('connected');

    // Permissive bar starts off.
    await expect(page.locator('#perm-status')).toHaveText('permissive mode: off');
    await expect(page.locator('#perm-enable')).toBeVisible();
    await expect(page.locator('#perm-disable')).toBeHidden();

    // Empty states.
    await expect(page.locator('#pending-list .empty')).toHaveText('No pending approvals.');
    await expect(page.locator('#active-list .empty')).toHaveText('No timeboxed rules active.');
    await expect(page.locator('#audit-list .empty')).toHaveText('No audit entries.');
  });
});
