import { test, expect, uniqueHost } from '../fixtures';

test.describe('permissive mode', () => {
  test('enable via UI unblocks traffic; disable re-blocks', async ({ dashboard, pyloros }) => {
    const probe = `https://${uniqueHost('perm')}/x`;
    await expect(pyloros).toBlock(probe);

    await dashboard.enablePermissive('300');
    await expect(dashboard.permBar).toHaveClass(/active/);
    await expect(dashboard.permStatus).toContainText('permissive mode: ON');
    await expect(dashboard.permissiveRow()).toBeVisible();
    await expect(pyloros).toRouteThrough(probe);

    await dashboard.disablePermissive();
    await expect(dashboard.permStatus).toHaveText('permissive mode: off');
    await expect(dashboard.permissiveRow()).toHaveCount(0);
    await expect(pyloros).toBlock(probe);
  });

  test('auto-expiry flips the UI off via the permissive_changed SSE event', async ({
    dashboard,
    pyloros,
  }) => {
    // 1s override (below the UI's 5-min minimum) to exercise auto-expire fast.
    await pyloros.setPermissive(1);
    await expect(dashboard.permBar).toHaveClass(/active/);
    await expect(dashboard.permStatus).toContainText('permissive mode: ON');

    await expect(dashboard.permStatus).toHaveText('permissive mode: off', { timeout: 5_000 });
  });
});
