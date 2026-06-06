/**
 * Per-run unique identifiers, so tests sharing one worker binary never collide
 * on hosts/rules/audit rows. Kept in their own module to avoid an import cycle
 * between `fixtures.ts` and `pages/dashboard.ts`.
 */
let hostCounter = 0;

/**
 * A unique, syntactically-valid host. Not expected to resolve — through the
 * proxy, the proxy (not the client) does DNS, so a blocked request 451s before
 * resolution and an allowed one reaches the upstream-connect failure (~502).
 */
export function uniqueHost(label = 'h'): string {
  hostCounter += 1;
  return `t${hostCounter}-${label}.example.com`;
}

let pathCounter = 0;

/**
 * A unique path segment, for building dedup-safe rules against a real reachable
 * host (`example.com`). A fresh segment each call means CI retries never hit the
 * "already covered → 200 approved, no pending card" dedup path.
 */
export function uniquePath(label = 'p'): string {
  pathCounter += 1;
  return `e2e-${label}-${pathCounter}`;
}
