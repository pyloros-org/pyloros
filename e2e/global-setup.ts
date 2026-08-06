import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';

import { pylorosBinaryPath, repoRoot } from './helpers/pyloros';

/**
 * Ensure the `pyloros` debug binary exists before any test spawns it.
 *
 * - In CI (`PYLOROS_SKIP_BUILD=1`) the binary is downloaded as an artifact
 *   from the `test` job, so we only assert it's present — never rebuild.
 * - Locally, build it on demand.
 */
export default function globalSetup(): void {
  const bin = pylorosBinaryPath();
  if (process.env.PYLOROS_SKIP_BUILD) {
    if (!existsSync(bin)) {
      throw new Error(
        `PYLOROS_SKIP_BUILD is set but ${bin} is missing. ` +
          `In CI this binary should be downloaded from the test job's artifact.`,
      );
    }
    return;
  }
  if (existsSync(bin)) return;
  // eslint-disable-next-line no-console
  console.log(`[global-setup] building pyloros (${path.relative(repoRoot(), bin)})…`);
  execFileSync('cargo', ['build', '--bin', 'pyloros'], {
    cwd: repoRoot(),
    stdio: 'inherit',
  });
}
