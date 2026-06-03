import { test, expect, uniqueHost, uniquePath } from '../fixtures';

/** Approve / deny decision flows, including editing the rule TOML. */
test.describe('decisions', () => {
  test('approve (unedited TOML) makes the rule live; traffic reaches the upstream', async ({
    page,
    pyloros,
  }) => {
    // Unique path on a real, reachable host so this is dedup-safe across
    // retries while still proving the request traverses the proxy.
    const seg = uniquePath('approve');
    const ruleUrl = `https://example.com/${seg}/*`;
    const probeUrl = `https://example.com/${seg}/ok`;

    const approval = await pyloros.createApproval([{ method: 'GET', url: ruleUrl }], {
      reason: 'fetch example',
    });

    // Blocked before approval.
    expect(await pyloros.sendRequest('GET', probeUrl)).toBe(451);

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();
    await card.locator('.approve').click();

    // Resolved → approved tag, then auto-removed after ~3s.
    await expect(card.locator('.tag.approved')).toHaveText('approved');
    await expect(page.locator(`#pending-list .card[data-id="${approval.id}"]`)).toHaveCount(0);

    // Agent long-poll sees the approval.
    const decision = await pyloros.waitForDecision(approval.id);
    expect(decision.status).toBe('approved');

    // Now the request reaches example.com (404 from the origin for an unknown
    // path — a proxy block would be 451). Poll: FilterEngine rebuild is async.
    await expect
      .poll(async () => pyloros.sendRequest('GET', probeUrl), { timeout: 10_000 })
      .toBe(404);
  });

  test('approve with edited TOML applies the edited rule, not the proposed one', async ({
    page,
    pyloros,
  }) => {
    const wrong = uniqueHost('wrong');
    const right = uniqueHost('right');
    const approval = await pyloros.createApproval(
      [{ method: 'GET', url: `https://${wrong}/*` }],
      { reason: 'agent proposed the wrong host' },
    );

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    // User corrects the host in the editable TOML, then approves.
    await card
      .locator('.rule-toml')
      .fill(`[[rules]]\nmethod = "GET"\nurl = "https://${right}/*"\n`);
    await card.locator('.approve').click();
    await expect(card.locator('.tag.approved')).toHaveText('approved');

    expect((await pyloros.waitForDecision(approval.id)).status).toBe('approved');

    // The proposed (wrong) host stays blocked; the edited (right) host matches.
    expect(await pyloros.sendRequest('GET', `https://${wrong}/x`)).toBe(451);
    await expect
      .poll(async () => pyloros.sendRequest('GET', `https://${right}/x`), { timeout: 10_000 })
      .not.toBe(451);
  });

  test('invalid TOML shows an inline parse error and leaves the approval pending', async ({
    page,
    pyloros,
  }) => {
    const host = uniqueHost('badtoml');
    const approval = await pyloros.createApproval([{ method: 'GET', url: `https://${host}/*` }]);

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    await card.locator('.rule-toml').fill('this is not valid toml ~~~');
    await card.locator('.approve').click();

    const err = card.locator('.parse-error');
    await expect(err).toBeVisible();
    await expect(err).toContainText('TOML parse error');

    // No decision was sent: still pending (no tag), and the long-poll times out.
    await expect(card.locator('.tag')).toHaveCount(0);
    await expect(card).toBeVisible();
  });

  test('deny with message resolves denied and returns the message to the agent', async ({
    page,
    pyloros,
  }) => {
    const host = uniqueHost('deny');
    const approval = await pyloros.createApproval([{ method: 'GET', url: `https://${host}/*` }]);

    await page.goto(pyloros.dashboardUrl);
    const card = page.locator(`#pending-list .card[data-id="${approval.id}"]`);
    await expect(card).toBeVisible();

    await card.locator('.deny-msg').fill('use the internal mirror instead');
    await card.locator('.deny').click();

    await expect(card.locator('.tag.denied')).toHaveText('denied');

    const decision = await pyloros.waitForDecision(approval.id);
    expect(decision.status).toBe('denied');
    expect(decision.message).toBe('use the internal mirror instead');
  });
});
