import { test, expect } from '../fixtures';

/**
 * Notification button state. We can't assert an actual OS toast from Playwright,
 * so coverage is limited to the permission-driven button state. (Absence of JS
 * errors on load is covered by the global invariant in the dashboard fixture.)
 */
test.describe('notifications', () => {
  test.use({ permissions: ['notifications'] });

  test('reflects granted permission in the notify button', async ({ dashboard, page }) => {
    expect(await page.evaluate(() => 'Notification' in window)).toBe(true);

    // Reaches "Notifications on" either via the load-time check (when the
    // browser already reports granted) or via the click handler's
    // requestPermission(). Headless Chromium reports "default" at load, so click.
    const btn = dashboard.notifyButton;
    if ((await btn.textContent())?.trim() !== 'Notifications on') {
      await btn.click();
    }
    await expect(btn).toHaveText('Notifications on');
    await expect(btn).toBeDisabled();
  });
});
