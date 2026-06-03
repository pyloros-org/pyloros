/**
 * Test fixtures: one live `pyloros` binary per worker, exposed to tests as
 * `pyloros`. The dashboard's permissive-mode / active-rules / audit state is
 * process-global, so tests must use unique hosts (see `uniqueHost`) and the
 * `cleanup` auto-fixture clears any leftover permissive override after each
 * test.
 */
import { test as base, expect } from '@playwright/test';

import { PylorosInstance, startPyloros } from './helpers/pyloros';

type WorkerFixtures = {
  pyloros: PylorosInstance;
};

type TestFixtures = {
  cleanup: void;
};

export const test = base.extend<TestFixtures, WorkerFixtures>({
  pyloros: [
    async ({}, use) => {
      const inst = await startPyloros();
      await use(inst);
      await inst.stop();
    },
    { scope: 'worker' },
  ],

  cleanup: [
    async ({ pyloros }, use) => {
      await use();
      // Best-effort: make sure a test that enabled permissive mode doesn't
      // bleed into the next one.
      try {
        await pyloros.setPermissive(0);
      } catch {
        // binary may already be shutting down at end of worker
      }
    },
    { auto: true },
  ],
});

export { expect };

let hostCounter = 0;

/**
 * A unique, syntactically-valid host for a test, so per-test rules and audit
 * rows never collide across the shared per-worker binary. Not expected to
 * resolve — through the proxy, the proxy (not the client) does DNS, so a
 * blocked request 451s before resolution and an allowed one ~502s.
 */
export function uniqueHost(label = 'h'): string {
  hostCounter += 1;
  return `t${hostCounter}-${label}.example.com`;
}

let pathCounter = 0;

/**
 * A unique path segment, used to build dedup-safe rules against a real
 * reachable host (`example.com`). A fresh segment each call means CI retries
 * never hit the "already covered → 200 approved, no pending card" dedup path.
 */
export function uniquePath(label = 'p'): string {
  pathCounter += 1;
  return `e2e-${label}-${pathCounter}`;
}
