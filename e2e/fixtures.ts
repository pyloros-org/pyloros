/**
 * Fixtures: one live `pyloros` binary per worker, plus a `dashboard` fixture
 * that hands each test an already-open, SSE-connected DashboardPage.
 *
 * The `dashboard` fixture also enforces invariants that should hold for EVERY
 * test, without each test restating them (see teardown below):
 *   - the binary never crashed mid-test
 *   - no console errors / uncaught page errors fired
 *   - no unexpected alert()/confirm() dialogs appeared
 *   - the SSE stream is still connected
 *   - permissive mode is cleared (and stays cleared between tests)
 */
import { test as base } from '@playwright/test';

import { expect } from './matchers';
import { DashboardPage } from './pages/dashboard';
import { PylorosInstance, startPyloros } from './helpers/pyloros';

export { expect };
export { uniqueHost, uniquePath } from './helpers/ids';
export type { PendingScenario } from './pages/dashboard';

// The invariant targets uncaught exceptions and app-level console.error — not
// the browser's automatic logging of non-2xx fetches (which the dashboard
// handles deliberately, e.g. a 400 from /rules/parse on invalid TOML) or a
// missing favicon. Those HTTP semantics are covered by explicit assertions.
const BENIGN_CONSOLE = [/Failed to load resource/i, /favicon/i];

type WorkerFixtures = { pyloros: PylorosInstance };
type TestFixtures = { dashboard: DashboardPage };

export const test = base.extend<TestFixtures, WorkerFixtures>({
  pyloros: [
    async ({}, use) => {
      const inst = await startPyloros();
      await use(inst);
      await inst.stop();
    },
    { scope: 'worker' },
  ],

  dashboard: async ({ page, pyloros }, use, testInfo) => {
    const consoleErrors: string[] = [];
    const dialogs: string[] = [];
    page.on('console', (m) => {
      if (m.type() === 'error' && !BENIGN_CONSOLE.some((r) => r.test(m.text()))) {
        consoleErrors.push(m.text());
      }
    });
    page.on('pageerror', (e) => consoleErrors.push(`pageerror: ${e.message}`));
    page.on('dialog', (d) => {
      dialogs.push(`${d.type()}: ${d.message()}`);
      void d.dismiss();
    });

    const dashboard = await new DashboardPage(page, pyloros).open();
    await use(dashboard);

    // Never let permissive mode bleed into the next test.
    try {
      await pyloros.setPermissive(0);
    } catch {
      // binary may already be shutting down at end of worker
    }

    // Assert invariants only when the test body itself passed, so the primary
    // failure is surfaced rather than buried under invariant noise.
    if (testInfo.status === testInfo.expectedStatus) {
      expect(pyloros.isAlive(), 'pyloros binary should still be running').toBe(true);
      expect(consoleErrors, 'no console / page errors during the test').toEqual([]);
      expect(dialogs, 'no unexpected alert()/confirm() dialogs').toEqual([]);
      await expect(dashboard.streamStatus, 'SSE stream should still be connected').toHaveText(
        'connected',
      );
      await expect(dashboard.permStatus, 'permissive mode should be cleared').toHaveText(
        'permissive mode: off',
      );
    }
  },
});
