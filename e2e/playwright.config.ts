import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the pyloros approvals-dashboard browser E2E tests.
 *
 * One worker, no intra-file parallelism: each worker owns a single live
 * `pyloros` binary (see fixtures.ts), and the dashboard's permissive-mode /
 * active-rules / audit state is process-global. Serial execution + unique
 * hosts per test keeps assertions isolated. The binary itself is built (or
 * asserted present) once by global-setup.ts.
 */
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 30_000,
  expect: { timeout: 10_000 },
  globalSetup: require.resolve('./global-setup'),
  reporter: process.env.CI
    ? [['html', { open: 'never' }], ['github'], ['list']]
    : [['html', { open: 'never' }], ['list']],
  use: {
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
  ],
});
