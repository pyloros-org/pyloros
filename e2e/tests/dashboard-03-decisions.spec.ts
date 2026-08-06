import { test, expect, uniqueHost } from '../fixtures';

test.describe('decisions', () => {
  test('approve (unedited TOML) makes the rule live; traffic reaches the origin', async ({
    dashboard,
    pyloros,
  }) => {
    const s = await dashboard.seedPending({ reason: 'fetch example', reachable: true });
    await expect(pyloros).toBlock(s.probe);

    await s.card.approve();
    await s.card.expectResolvedAs('approved');

    expect((await pyloros.waitForDecision(s.id)).status).toBe('approved');
    await expect(pyloros).toReachOrigin(s.probe);
  });

  test('approve with edited TOML applies the edited rule, not the proposed one', async ({
    dashboard,
    pyloros,
  }) => {
    const s = await dashboard.seedPending({ reason: 'agent proposed the wrong host' });
    const right = uniqueHost('right');

    await s.card.editRule(`[[rules]]\nmethod = "GET"\nurl = "https://${right}/*"\n`);
    await s.card.approve();
    await s.card.expectResolvedAs('approved');

    expect((await pyloros.waitForDecision(s.id)).status).toBe('approved');
    await expect(pyloros).toBlock(`https://${s.host}/x`);
    await expect(pyloros).toRouteThrough(`https://${right}/x`);
  });

  test('invalid TOML shows an inline parse error and leaves the approval pending', async ({
    dashboard,
  }) => {
    const s = await dashboard.seedPending();

    await s.card.editRule('this is not valid toml ~~~');
    await s.card.approve();

    await expect(s.card.parseError).toBeVisible();
    await expect(s.card.parseError).toContainText('TOML parse error');
    // No decision was sent: still pending (no tag).
    await expect(s.card.root.locator('.tag')).toHaveCount(0);
    await expect(s.card.root).toBeVisible();
  });

  test('deny with message resolves denied and returns the message to the agent', async ({
    dashboard,
    pyloros,
  }) => {
    const s = await dashboard.seedPending();

    await s.card.deny('use the internal mirror instead');
    await s.card.expectResolvedAs('denied');

    const decision = await pyloros.waitForDecision(s.id);
    expect(decision.status).toBe('denied');
    expect(decision.message).toBe('use the internal mirror instead');
  });
});
