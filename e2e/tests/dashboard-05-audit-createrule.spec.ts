import { test, expect, uniqueHost } from '../fixtures';

test.describe('audit log + create rule', () => {
  test('a blocked request appears live as an audit row with a Create-rule button', async ({
    dashboard,
    pyloros,
  }) => {
    const host = uniqueHost('audit');
    await expect(pyloros).toBlock(`https://${host}/x`);

    const row = dashboard.auditRow(host, 'blocked');
    await expect(row).toBeVisible();
    await expect(row.locator('.createrule')).toHaveText('Create rule');
  });

  test('the "also show allowed" checkbox surfaces rule-matched requests', async ({
    dashboard,
    pyloros,
  }) => {
    const host = uniqueHost('allowed');
    await pyloros.addRule([{ method: 'GET', url: `https://${host}/*` }], 'one_hour');
    await expect(pyloros).toRouteThrough(`https://${host}/ping`);

    // Allowed entries live in recent_all only — hidden by default.
    const allowed = dashboard.auditRow(host, 'allowed');
    await expect(allowed).toHaveCount(0);
    await dashboard.includeAllowed().check();
    await expect(allowed).toBeVisible();
  });

  test('Create rule from a blocked row adds a live rule that unblocks the request', async ({
    dashboard,
    pyloros,
  }) => {
    const host = uniqueHost('mkrule');
    const url = `https://${host}/api`;
    await expect(pyloros).toBlock(url);

    await dashboard.auditRow(host).locator('.createrule').click();

    const card = dashboard.createRuleCard();
    await expect(card).toBeVisible();
    await expect(card.locator('.rule-toml')).toHaveValue(new RegExp(host.replace(/\./g, '\\.')));
    await expect(card.locator('.rule-toml')).toHaveValue(/# Or, broader/);

    await card.locator('.approve').click(); // "Add rule"
    await expect(card).toHaveCount(0);
    await expect(pyloros).toRouteThrough(url);
  });
});
