import { test, expect } from '../fixtures';

/**
 * HTML-escaping / XSS guards. The dangerous vector is `<img onerror>` — unlike
 * `<script>`, it executes when inserted via innerHTML (how the dashboard builds
 * cards). We assert the payload renders as inert text and never runs.
 * (The global no-console-errors invariant also fails if onerror fires.)
 */
test.describe('XSS guards', () => {
  test('escapes HTML in the approval reason', async ({ dashboard, page }) => {
    const payload = '<img src=x onerror="window.__xssReason=1">pwn';
    const s = await dashboard.seedPending({ reason: payload });

    await expect(s.card.reason).toHaveText(payload);
    await expect(s.card.root.locator('img')).toHaveCount(0);
    expect(
      await page.evaluate(() => (window as unknown as { __xssReason?: number }).__xssReason),
    ).toBeUndefined();
  });

  test('escapes HTML in the triggered-by URL', async ({ dashboard, page }) => {
    const evil = 'https://evil.example/<img src=x onerror="window.__xssTrig=1">';
    const s = await dashboard.seedPending({ triggeredBy: { method: 'GET', url: evil } });

    await expect(s.card.triggered).toContainText(evil);
    await expect(s.card.root.locator('img')).toHaveCount(0);
    expect(
      await page.evaluate(() => (window as unknown as { __xssTrig?: number }).__xssTrig),
    ).toBeUndefined();
  });
});
