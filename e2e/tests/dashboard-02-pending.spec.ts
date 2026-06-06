import { test, expect } from '../fixtures';

test.describe('pending approvals', () => {
  test('renders reason, triggered-by, lifetime default, and editable TOML', async ({
    dashboard,
  }) => {
    const trigger = 'https://trigger.example/path';
    const s = await dashboard.seedPending({
      reason: 'needs the widgets API',
      suggestedTtl: 'one_hour',
      triggeredBy: { method: 'GET', url: trigger },
    });

    await expect(s.card.reason).toHaveText('needs the widgets API');
    await expect(s.card.triggered).toContainText(`GET ${trigger}`);

    // Lifetime default honours suggested_ttl; options are exactly the post-#120
    // lifetimes (no "session").
    await expect(s.card.lifetime).toHaveValue('one_hour');
    await expect(s.card.lifetime.locator('option')).toHaveText(['1 hour', '1 day', 'permanent']);
    const values = await s.card.lifetime
      .locator('option')
      .evaluateAll((opts) => opts.map((o) => (o as HTMLOptionElement).value));
    expect(values).toEqual(['one_hour', 'one_day', 'permanent']);

    // Editable rule TOML is lazy-fetched (server-formatted) and contains the rule.
    await expect(s.card.toml).toHaveValue(/\[\[rules\]\]/);
    await expect(s.card.toml).toHaveValue(new RegExp(s.host.replace(/\./g, '\\.')));

    // Also renders from the SSE snapshot after a reload, not just the live event.
    await dashboard.reload();
    await expect(dashboard.pending(s.id).root).toBeVisible();
  });

  test('new approval appears live without reload (SSE pending event)', async ({ dashboard }) => {
    const s = await dashboard.seedPending({ reason: 'pushed live' });
    await expect(s.card.reason).toHaveText('pushed live');
  });
});
