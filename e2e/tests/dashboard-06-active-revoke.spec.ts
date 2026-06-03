import { test, expect, uniqueHost } from '../fixtures';

/** Active-timeboxed-rules panel: listing + revoke. */
test.describe('active timeboxed rules', () => {
  test('an added rule shows with a lifetime/countdown tag and can be revoked', async ({
    page,
    pyloros,
  }) => {
    const host = uniqueHost('revoke');
    const probe = `https://${host}/x`;
    const approvalId = await pyloros.addRule(
      [{ method: 'GET', url: `https://${host}/*` }],
      'one_hour',
    );
    expect(approvalId).toMatch(/^rul_/);

    // Rule is live.
    await expect
      .poll(async () => pyloros.sendRequest('GET', probe), { timeout: 10_000 })
      .not.toBe(451);

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator('#active-list .card', { hasText: approvalId });
    await expect(card).toBeVisible();
    await expect(card.locator('.tag.lifetime')).toContainText('one_hour');
    await expect(card.locator('.tag.lifetime')).toContainText('left');
    await expect(card.locator('.rule-toml')).toHaveValue(new RegExp(host.replace(/\./g, '\\.')));

    // Revoke → row disappears (active_rules_changed) and traffic is blocked again.
    await card.locator('.revoke').click();
    await expect(page.locator('#active-list .card', { hasText: approvalId })).toHaveCount(0);

    await expect
      .poll(async () => pyloros.sendRequest('GET', probe), { timeout: 10_000 })
      .toBe(451);
  });
});
