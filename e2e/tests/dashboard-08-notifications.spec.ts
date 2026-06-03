import { test, expect } from '../fixtures';

/**
 * Notification button state. We can't assert an actual OS toast from
 * Playwright, so coverage is limited to the permission-driven button state and
 * the absence of JS errors on load.
 */
test.describe('notifications', () => {
  test.use({ permissions: ['notifications'] });

  test('reflects granted permission in the notify button and logs no errors', async ({
    page,
    pyloros,
  }) => {
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    page.on('pageerror', (err) => consoleErrors.push(err.message));

    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    expect(await page.evaluate(() => 'Notification' in window)).toBe(true);

    // The button reaches "Notifications on" either via the load-time check
    // (when the browser already reports permission granted) or via the click
    // handler's requestPermission() — which resolves granted because the
    // context granted the permission. Headless Chromium reports permission as
    // "default" at load, so we click here.
    const btn = page.locator('#notify-btn');
    if ((await btn.textContent())?.trim() !== 'Notifications on') {
      await btn.click();
    }
    await expect(btn).toHaveText('Notifications on');
    await expect(btn).toBeDisabled();

    expect(consoleErrors).toEqual([]);
  });
});
