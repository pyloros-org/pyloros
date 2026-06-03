import { test, expect, uniqueHost } from '../fixtures';

/** Pending-approval card rendering + real-time SSE push. */
test.describe('pending approvals', () => {
  test('renders reason, triggered-by, lifetime default, and editable TOML', async ({
    page,
    pyloros,
  }) => {
    const host = uniqueHost('pending');
    const approval = await pyloros.createApproval(
      [{ method: 'GET', url: `https://${host}/*` }],
      {
        reason: 'needs the widgets API',
        suggestedTtl: 'one_hour',
        triggeredBy: { method: 'GET', url: `https://${host}/trigger` },
      },
    );

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    await expect(card.locator('.reason')).toHaveText('needs the widgets API');
    await expect(card.locator('.triggered')).toContainText(`GET https://${host}/trigger`);

    // Lifetime select: default honours suggested_ttl, options are exactly the
    // three post-#120 lifetimes (no "session").
    const select = card.locator('.controls select');
    await expect(select).toHaveValue('one_hour');
    await expect(select.locator('option')).toHaveText(['1 hour', '1 day', 'permanent']);
    const optionValues = await select
      .locator('option')
      .evaluateAll((opts) => opts.map((o) => (o as HTMLOptionElement).value));
    expect(optionValues).toEqual(['one_hour', 'one_day', 'permanent']);

    // Editable rule TOML is lazy-fetched (server-formatted) and contains the rule.
    await expect(card.locator('.rule-toml')).toHaveValue(new RegExp(host.replace(/\./g, '\\.')));
    await expect(card.locator('.rule-toml')).toHaveValue(/\[\[rules\]\]/);
  });

  test('new approval appears live without reload (SSE pending event)', async ({
    page,
    pyloros,
  }) => {
    await page.goto(pyloros.dashboardUrl);
    await expect(page.locator('#stream-status')).toHaveText('connected');

    const host = uniqueHost('live');
    const approval = await pyloros.createApproval([{ method: 'GET', url: `https://${host}/*` }], {
      reason: 'pushed live',
    });

    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();
    await expect(card.locator('.reason')).toHaveText('pushed live');
  });
});
