import { test, expect, uniqueHost } from '../fixtures';

test('an added timeboxed rule shows with a countdown tag and can be revoked', async ({
  dashboard,
  pyloros,
}) => {
  const host = uniqueHost('revoke');
  const probe = `https://${host}/x`;
  const id = await pyloros.addRule([{ method: 'GET', url: `https://${host}/*` }], 'one_hour');
  expect(id).toMatch(/^rul_/);
  await expect(pyloros).toRouteThrough(probe);

  const card = dashboard.activeCard(id);
  await expect(card).toBeVisible();
  await expect(card.locator('.tag.lifetime')).toContainText('one_hour');
  await expect(card.locator('.tag.lifetime')).toContainText('left');
  await expect(card.locator('.rule-toml')).toHaveValue(new RegExp(host.replace(/\./g, '\\.')));

  // Revoke → row disappears (active_rules_changed) and traffic is blocked again.
  await card.locator('.revoke').click();
  await expect(dashboard.activeCard(id)).toHaveCount(0);
  await expect(pyloros).toBlock(probe);
});
