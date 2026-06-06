import { test, expect } from '../fixtures';

/**
 * Page shell: panels render, the SSE stream connects, initial empty states
 * show. Runs first (numeric prefix) so the worker's audit ring is still empty.
 */
test('shell renders panels, connects SSE, shows empty states', async ({ dashboard }) => {
  await expect(dashboard.heading('Pending approvals')).toBeVisible();
  await expect(dashboard.heading('Active timeboxed rules')).toBeVisible();
  await expect(dashboard.heading('Audit log')).toBeVisible();

  await expect(dashboard.streamStatus).toHaveText('connected');
  await expect(dashboard.permStatus).toHaveText('permissive mode: off');

  await expect(dashboard.emptyOf('pending-list')).toHaveText('No pending approvals.');
  await expect(dashboard.emptyOf('active-list')).toHaveText('No timeboxed rules active.');
  await expect(dashboard.emptyOf('audit-list')).toHaveText('No audit entries.');
});
