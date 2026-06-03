import { test, expect, uniqueHost } from '../fixtures';

/** Audit-log browser panel + "create rule from a blocked row". */
test.describe('audit log + create rule', () => {
  test('a blocked request appears live as an audit row with a Create-rule button', async ({
    page,
    pyloros,
  }) => {
    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    const host = uniqueHost('audit');
    expect(await pyloros.sendRequest('GET', `https://${host}/x`)).toBe(451);

    const row = page.locator('#audit-list .audit-row', { hasText: host });
    await expect(row).toBeVisible();
    await expect(row).toHaveClass(/blocked/);
    await expect(row.locator('.createrule')).toHaveText('Create rule');
  });

  test('the "also show allowed" checkbox surfaces rule-matched requests', async ({
    page,
    pyloros,
  }) => {
    const host = uniqueHost('allowed');
    await pyloros.addRule([{ method: 'GET', url: `https://${host}/*` }], 'one_hour');
    // Let the FilterEngine rebuild, then make an allowed request.
    await expect
      .poll(async () => pyloros.sendRequest('GET', `https://${host}/ping`), { timeout: 10_000 })
      .not.toBe(451);

    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    // Allowed entries live in recent_all only — hidden by default.
    const allowedRow = page.locator('#audit-list .audit-row.allowed', { hasText: host });
    await expect(allowedRow).toHaveCount(0);

    await page.locator('#audit-include-allowed').check();
    await expect(allowedRow).toBeVisible();
  });

  test('Create rule from a blocked row adds a live rule that unblocks the request', async ({
    page,
    pyloros,
  }) => {
    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    const host = uniqueHost('mkrule');
    const url = `https://${host}/api`;
    expect(await pyloros.sendRequest('GET', url)).toBe(451);

    const row = page.locator('#audit-list .audit-row', { hasText: host });
    await expect(row).toBeVisible();
    await row.locator('.createrule').click();

    // Inline create-rule card, pre-filled by /rules/suggest.
    const card = page.locator('.card', { hasText: 'Create rule from blocked request' });
    await expect(card).toBeVisible();
    await expect(card.locator('.rule-toml')).toHaveValue(new RegExp(host.replace(/\./g, '\\.')));
    await expect(card.locator('.rule-toml')).toHaveValue(/# Or, broader/);

    await card.locator('.approve').click(); // "Add rule"
    await expect(card).toHaveCount(0); // card.remove() on success

    await expect
      .poll(async () => pyloros.sendRequest('GET', url), { timeout: 10_000 })
      .not.toBe(451);
  });
});
