import { test, expect, uniqueHost } from '../fixtures';

/** Timeboxed permissive-mode bar + synthetic active row. */
test.describe('permissive mode', () => {
  test('enable via UI unblocks traffic; disable re-blocks', async ({ page, pyloros }) => {
    const host = uniqueHost('perm');
    const probe = `https://${host}/x`;

    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    // Baseline blocked.
    expect(await pyloros.sendRequest('GET', probe)).toBe(451);

    // Enable for 5 min via the UI.
    await page.locator('#perm-duration').selectOption('300');
    await page.locator('#perm-enable').click();

    await expect(page.locator('#perm-bar')).toHaveClass(/active/);
    await expect(page.locator('#perm-status')).toContainText('permissive mode: ON');
    await expect(page.locator('#perm-enable')).toBeHidden();
    await expect(page.locator('#perm-disable')).toBeVisible();

    // Synthetic row in the active panel.
    await expect(
      page.locator('#active-list .card', { hasText: 'permissive mode (timeboxed override)' }),
    ).toBeVisible();

    // Previously-blocked request now goes through.
    await expect
      .poll(async () => pyloros.sendRequest('GET', probe), { timeout: 10_000 })
      .not.toBe(451);

    // Disable via the UI.
    await page.locator('#perm-disable').click();
    await expect(page.locator('#perm-status')).toHaveText('permissive mode: off');
    await expect(page.locator('#perm-enable')).toBeVisible();
    await expect(
      page.locator('#active-list .card', { hasText: 'permissive mode (timeboxed override)' }),
    ).toHaveCount(0);

    // Blocked again.
    await expect
      .poll(async () => pyloros.sendRequest('GET', probe), { timeout: 10_000 })
      .toBe(451);
  });

  test('auto-expiry flips the UI off via the permissive_changed SSE event', async ({
    page,
    pyloros,
  }) => {
    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    // Use a 1s override (below the UI's 5-min minimum) to exercise the
    // auto-expire path quickly. The UI flips ON via SSE, then OFF on expiry.
    await pyloros.setPermissive(1);
    await expect(page.locator('#perm-bar')).toHaveClass(/active/);
    await expect(page.locator('#perm-status')).toContainText('permissive mode: ON');

    await expect(page.locator('#perm-status')).toHaveText('permissive mode: off', {
      timeout: 5_000,
    });
  });
});
