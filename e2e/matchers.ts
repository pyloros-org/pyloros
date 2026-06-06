/**
 * Domain matchers for proxy behavior, so specs say what they mean
 * (`toBlock` / `toRouteThrough` / `toReachOrigin`) instead of polling raw HTTP
 * status codes. Each polls a request through the proxy until the condition
 * holds or the timeout elapses (covering async FilterEngine rebuilds).
 */
import { expect as baseExpect } from '@playwright/test';

import type { PylorosInstance } from './helpers/pyloros';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function pollStatus(
  pyloros: PylorosInstance,
  method: string,
  url: string,
  ok: (code: number) => boolean,
  timeoutMs: number,
): Promise<number> {
  let last = -1;
  const deadline = Date.now() + timeoutMs;
  do {
    last = await pyloros.sendRequest(method, url);
    if (ok(last)) return last;
    await sleep(150);
  } while (Date.now() < deadline);
  return last;
}

const TIMEOUT = 10_000;

export const expect = baseExpect.extend({
  /** The proxy blocks the request by policy (HTTP 451). */
  async toBlock(pyloros: PylorosInstance, url: string, method = 'GET') {
    const code = await pollStatus(pyloros, method, url, (c) => c === 451, TIMEOUT);
    return {
      pass: code === 451,
      message: () => `expected proxy to BLOCK ${method} ${url} (451); last status was ${code}`,
    };
  },

  /** A rule matched, so the request is not blocked (anything but 451). */
  async toRouteThrough(pyloros: PylorosInstance, url: string, method = 'GET') {
    const code = await pollStatus(pyloros, method, url, (c) => c !== 451, TIMEOUT);
    return {
      pass: code !== 451,
      message: () =>
        `expected proxy to ROUTE ${method} ${url} (not 451); last status was ${code}`,
    };
  },

  /** The request reached the real example.com origin (404 for an unknown path). */
  async toReachOrigin(pyloros: PylorosInstance, url: string, method = 'GET') {
    const code = await pollStatus(pyloros, method, url, (c) => c === 404, TIMEOUT);
    return {
      pass: code === 404,
      message: () =>
        `expected ${method} ${url} to reach the origin (404 from example.com); last status was ${code}`,
    };
  },
});

declare module '@playwright/test' {
  interface Matchers<R, T> {
    toBlock(url: string, method?: string): Promise<R>;
    toRouteThrough(url: string, method?: string): Promise<R>;
    toReachOrigin(url: string, method?: string): Promise<R>;
  }
}
