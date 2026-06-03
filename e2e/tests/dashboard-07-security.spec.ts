import { test, expect, uniqueHost } from '../fixtures';

/**
 * HTML-escaping / XSS guards. The dangerous vector is an `<img onerror>`
 * payload — unlike `<script>`, it executes when inserted via innerHTML, which
 * is how the dashboard builds cards. We assert the payload renders as inert
 * text and never runs.
 */
test.describe('XSS guards', () => {
  test('escapes HTML in the approval reason', async ({ page, pyloros }) => {
    const host = uniqueHost('xssreason');
    const payload = '<img src=x onerror="window.__xssReason=1">pwn';
    const approval = await pyloros.createApproval(
      [{ method: 'GET', url: `https://${host}/*` }],
      { reason: payload },
    );

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    await expect(card.locator('.reason')).toHaveText(payload);
    await expect(card.locator('img')).toHaveCount(0);
    expect(await page.evaluate(() => (window as unknown as { __xssReason?: number }).__xssReason)).toBeUndefined();
  });

  test('escapes HTML in the triggered-by URL', async ({ page, pyloros }) => {
    const host = uniqueHost('xsstrig');
    const evil = `https://${host}/<img src=x onerror="window.__xssTrig=1">`;
    const approval = await pyloros.createApproval(
      [{ method: 'GET', url: `https://${host}/*` }],
      { triggeredBy: { method: 'GET', url: evil } },
    );

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    await expect(card.locator('.triggered')).toContainText(evil);
    await expect(card.locator('img')).toHaveCount(0);
    expect(await page.evaluate(() => (window as unknown as { __xssTrig?: number }).__xssTrig)).toBeUndefined();
  });
});
