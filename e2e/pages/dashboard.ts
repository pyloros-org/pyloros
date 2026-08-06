/**
 * Page objects for the approvals dashboard. All CSS selectors live here, so a
 * markup change breaks one file instead of every spec, and tests read in domain
 * terms (cards, panels, lifetimes) rather than locators.
 */
import { type Locator, type Page, expect } from '@playwright/test';

import { uniqueHost, uniquePath } from '../helpers/ids';
import type { CreateApprovalOpts, Lifetime, PylorosInstance, Rule } from '../helpers/pyloros';

/** One pending-approval card. */
export class PendingCard {
  constructor(readonly root: Locator) {}

  get reason() {
    return this.root.locator('.reason');
  }
  get triggered() {
    return this.root.locator('.triggered');
  }
  get toml() {
    return this.root.locator('.rule-toml');
  }
  get parseError() {
    return this.root.locator('.parse-error');
  }
  get lifetime() {
    return this.root.locator('.controls select');
  }
  tag(kind: 'approved' | 'denied') {
    return this.root.locator(`.tag.${kind}`);
  }

  editRule(toml: string) {
    return this.toml.fill(toml);
  }
  setLifetime(value: Lifetime) {
    return this.lifetime.selectOption(value);
  }
  approve() {
    return this.root.locator('.approve').click();
  }
  async deny(message?: string) {
    if (message !== undefined) await this.root.locator('.deny-msg').fill(message);
    await this.root.locator('.deny').click();
  }

  /** Assert the card resolved to `kind` (tag shown) and was then auto-removed. */
  async expectResolvedAs(kind: 'approved' | 'denied') {
    await expect(this.tag(kind)).toHaveText(kind);
    await expect(this.root).toHaveCount(0); // auto-removed ~3s after resolution
  }
}

/** Seed handle returned by `DashboardPage.seedPending`. */
export interface PendingScenario {
  id: string;
  host: string;
  rule: Rule;
  probe: string;
  card: PendingCard;
}

export class DashboardPage {
  constructor(
    readonly page: Page,
    readonly pyloros: PylorosInstance,
  ) {}

  // ---- top bar / permissive ----
  get streamStatus() {
    return this.page.locator('#stream-status');
  }
  get permStatus() {
    return this.page.locator('#perm-status');
  }
  get permBar() {
    return this.page.locator('#perm-bar');
  }
  get notifyButton() {
    return this.page.locator('#notify-btn');
  }
  permissiveRow() {
    return this.page.locator('#active-list .card', {
      hasText: 'permissive mode (timeboxed override)',
    });
  }
  async enablePermissive(durationSecs: '300' | '900' | '3600') {
    await this.page.locator('#perm-duration').selectOption(durationSecs);
    await this.page.locator('#perm-enable').click();
  }
  disablePermissive() {
    return this.page.locator('#perm-disable').click();
  }

  // ---- panels ----
  heading(name: string) {
    return this.page.getByRole('heading', { name });
  }
  emptyOf(panel: 'pending-list' | 'active-list' | 'audit-list') {
    return this.page.locator(`#${panel} .empty`);
  }
  pending(id: string) {
    return new PendingCard(this.page.locator(`#pending-list .card[data-id="${id}"]`));
  }
  activeCard(id: string) {
    return this.page.locator('#active-list .card', { hasText: id });
  }
  auditRow(text: string, kind?: 'blocked' | 'allowed' | 'permitted') {
    const sel = kind ? `#audit-list .audit-row.${kind}` : '#audit-list .audit-row';
    return this.page.locator(sel, { hasText: text });
  }
  includeAllowed() {
    return this.page.locator('#audit-include-allowed');
  }
  createRuleCard() {
    return this.page.locator('.card', { hasText: 'Create rule from blocked request' });
  }

  // ---- navigation ----
  async open() {
    await this.page.goto(this.pyloros.dashboardUrl);
    await expect(this.streamStatus).toHaveText('connected');
    return this;
  }
  async reload() {
    await this.page.reload();
    await expect(this.streamStatus).toHaveText('connected');
    return this;
  }

  /**
   * Create a pending approval via the agent API and return its rendered card
   * plus the unique host / probe URL. `reachable: true` targets a unique path
   * on the real `example.com` (so the probe reaches a live origin).
   */
  async seedPending(
    opts: CreateApprovalOpts & { reachable?: boolean } = {},
  ): Promise<PendingScenario> {
    const { reachable, ...approvalOpts } = opts;
    let host: string;
    let rule: Rule;
    let probe: string;
    if (reachable) {
      const base = `https://example.com/${uniquePath('seed')}`;
      host = 'example.com';
      rule = { method: 'GET', url: `${base}/*` };
      probe = `${base}/ok`;
    } else {
      host = uniqueHost('seed');
      rule = { method: 'GET', url: `https://${host}/*` };
      probe = `https://${host}/x`;
    }
    const approval = await this.pyloros.createApproval([rule], approvalOpts);
    const card = this.pending(approval.id);
    await expect(card.root).toBeVisible();
    return { id: approval.id, host, rule, probe, card };
  }
}
