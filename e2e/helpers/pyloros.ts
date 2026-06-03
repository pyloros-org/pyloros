/**
 * Lifecycle + API helpers for driving a live `pyloros` binary from the
 * Playwright browser tests.
 *
 * Two ways to talk to the proxy are exposed:
 *
 *  - **Through the proxy** (`createApproval` / `waitForDecision` /
 *    `sendRequest`): curl with `--proxy` + `--cacert`, exercising the MITM
 *    agent API at `https://pyloros.internal/` and generating real audit
 *    entries. curl (not Node fetch) because it handles CONNECT-MITM with a
 *    custom CA cleanly, and the proxy — not the client — resolves DNS, so
 *    unique non-resolving test hosts work.
 *  - **Directly to the dashboard listener** (`setPermissive` / `addRule` /
 *    `revokeRule` / `parseRules` / `suggest`): plain Node `fetch` over HTTP,
 *    no proxy or CA needed.
 */
import { execFile, execFileSync, spawn, ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export interface Rule {
  method?: string;
  url: string;
  websocket?: boolean;
  git?: string;
  branches?: string[];
  allow_redirects?: string[];
  log_body?: boolean;
}

export type Lifetime = 'one_hour' | 'one_day' | 'permanent';

export interface CreateApprovalOpts {
  reason?: string;
  suggestedTtl?: Lifetime;
  triggeredBy?: { method: string; url: string };
}

/** Repo root (the worktree dir containing `e2e/` and `target/`). */
export function repoRoot(): string {
  return path.resolve(__dirname, '..', '..');
}

/** Path to the debug `pyloros` binary. */
export function pylorosBinaryPath(): string {
  return path.join(repoRoot(), 'target', 'debug', 'pyloros');
}

/** Grab a free TCP port on 127.0.0.1 by binding ephemerally and closing. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      if (addr && typeof addr === 'object') {
        const { port } = addr;
        srv.close(() => resolve(port));
      } else {
        srv.close(() => reject(new Error('could not determine free port')));
      }
    });
  });
}

function httpGetStatus(url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.once('error', reject);
    req.setTimeout(2000, () => req.destroy(new Error('timeout')));
  });
}

function tcpConnects(port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1');
    sock.once('connect', () => {
      sock.destroy();
      resolve(true);
    });
    sock.once('error', () => resolve(false));
    sock.setTimeout(2000, () => {
      sock.destroy();
      resolve(false);
    });
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

export class PylorosInstance {
  readonly dashboardUrl: string; // http://127.0.0.1:<dashPort> (no trailing slash)
  readonly proxyUrl: string; // http://127.0.0.1:<proxyPort>
  readonly caCertPath: string;
  readonly permanentRulesFile: string;
  readonly auditLogFile: string;
  readonly tmpDir: string;
  private readonly child: ChildProcess;
  private stderr = '';

  constructor(args: {
    dashPort: number;
    proxyPort: number;
    caCertPath: string;
    permanentRulesFile: string;
    auditLogFile: string;
    tmpDir: string;
    child: ChildProcess;
  }) {
    this.dashboardUrl = `http://127.0.0.1:${args.dashPort}`;
    this.proxyUrl = `http://127.0.0.1:${args.proxyPort}`;
    this.caCertPath = args.caCertPath;
    this.permanentRulesFile = args.permanentRulesFile;
    this.auditLogFile = args.auditLogFile;
    this.tmpDir = args.tmpDir;
    this.child = args.child;
    this.child.stderr?.on('data', (d) => {
      this.stderr += d.toString();
    });
  }

  // ---------- through the proxy (curl + MITM CA) ----------

  private curlBase(): string[] {
    return ['--proxy', this.proxyUrl, '--cacert', this.caCertPath];
  }

  /** Create a pending approval via the agent API. Returns the ApprovalRequest. */
  async createApproval(rules: Rule[], opts: CreateApprovalOpts = {}): Promise<any> {
    const body: Record<string, unknown> = { rules };
    if (opts.reason !== undefined) body.reason = opts.reason;
    if (opts.suggestedTtl !== undefined) body.suggested_ttl = opts.suggestedTtl;
    if (opts.triggeredBy !== undefined) body.context = { triggered_by: opts.triggeredBy };
    const { stdout } = await execFileAsync('curl', [
      '-sS',
      '--fail-with-body',
      ...this.curlBase(),
      '-X',
      'POST',
      '-H',
      'Content-Type: application/json',
      '--data',
      JSON.stringify(body),
      'https://pyloros.internal/approvals',
    ]);
    return JSON.parse(stdout);
  }

  /** Long-poll an approval's decision via the agent API. */
  async waitForDecision(id: string, dur = '60s'): Promise<any> {
    const { stdout } = await execFileAsync(
      'curl',
      [
        '-sS',
        '--fail-with-body',
        '--max-time',
        '65',
        ...this.curlBase(),
        `https://pyloros.internal/approvals/${encodeURIComponent(id)}?wait=${dur}`,
      ],
      { maxBuffer: 1024 * 1024 },
    );
    return JSON.parse(stdout);
  }

  /**
   * Issue a request through the proxy; return the HTTP status code.
   * 451 = blocked by policy; anything else = the filter let it through
   * (200 for a reachable host, ~502 for a non-resolving unique test host).
   */
  async sendRequest(method: string, url: string): Promise<number> {
    const { stdout } = await execFileAsync('curl', [
      '-sS',
      '-o',
      '/dev/null',
      '-w',
      '%{http_code}',
      '--max-time',
      '20',
      ...this.curlBase(),
      '-X',
      method,
      url,
    ]).catch((e: { stdout?: string }) => {
      // curl exits non-zero on e.g. upstream connection failure, but we
      // still want the HTTP code it printed (if any).
      if (e && typeof e.stdout === 'string' && /^\d{3}$/.test(e.stdout.trim())) {
        return { stdout: e.stdout };
      }
      throw e;
    });
    return parseInt(stdout.trim(), 10);
  }

  // ---------- directly to the dashboard listener (plain HTTP) ----------

  private async dashPost(path: string, body: unknown): Promise<Response> {
    return fetch(`${this.dashboardUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  }

  /** Enable timeboxed permissive mode for `durationSecs` (0 clears it). */
  async setPermissive(durationSecs: number): Promise<void> {
    const resp = await this.dashPost('/permissive', { duration_secs: durationSecs });
    if (!resp.ok) throw new Error(`POST /permissive failed: ${resp.status} ${await resp.text()}`);
  }

  /** Add an active rule group directly; returns the synthetic approval id. */
  async addRule(rules: Rule[], ttl: Lifetime): Promise<string> {
    const resp = await this.dashPost('/rules', { rules, ttl });
    if (!resp.ok) throw new Error(`POST /rules failed: ${resp.status} ${await resp.text()}`);
    const j = (await resp.json()) as { approval_id: string };
    return j.approval_id;
  }

  /** Revoke a previously-approved active rule group. */
  async revokeRule(id: string): Promise<void> {
    const resp = await fetch(`${this.dashboardUrl}/approvals/${encodeURIComponent(id)}/rules`, {
      method: 'DELETE',
    });
    if (!resp.ok) throw new Error(`DELETE rules failed: ${resp.status} ${await resp.text()}`);
  }

  /** Parse TOML rule text. Returns {status, body} so callers can assert errors. */
  async parseRules(toml: string): Promise<{ status: number; body: string }> {
    const resp = await this.dashPost('/rules/parse', { toml });
    return { status: resp.status, body: await resp.text() };
  }

  /** Server-built TOML suggestion for an audit entry or a re-format of rules. */
  async suggest(body: { audit: unknown } | { rules: Rule[] }): Promise<string> {
    const resp = await this.dashPost('/rules/suggest', body);
    if (!resp.ok) throw new Error(`POST /rules/suggest failed: ${resp.status}`);
    const j = (await resp.json()) as { toml: string };
    return j.toml;
  }

  // ---------- lifecycle ----------

  async stop(): Promise<void> {
    this.child.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      if (this.child.exitCode !== null || this.child.signalCode !== null) return resolve();
      this.child.once('exit', () => resolve());
      setTimeout(() => {
        this.child.kill('SIGKILL');
        resolve();
      }, 3000);
    });
    rmSync(this.tmpDir, { recursive: true, force: true });
  }

  diagnostics(): string {
    return this.stderr;
  }
}

/**
 * Generate a CA, write a config with approvals + audit logging enabled on
 * fresh ephemeral ports, spawn the binary, and wait until both listeners
 * are accepting connections.
 */
export async function startPyloros(): Promise<PylorosInstance> {
  const bin = pylorosBinaryPath();
  if (!existsSync(bin)) throw new Error(`pyloros binary not found at ${bin}`);

  const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'pyloros-e2e-'));
  const caCertPath = path.join(tmpDir, 'ca.crt');
  const caKeyPath = path.join(tmpDir, 'ca.key');
  const permanentRulesFile = path.join(tmpDir, 'permanent-rules.toml');
  const auditLogFile = path.join(tmpDir, 'audit.jsonl');
  const configPath = path.join(tmpDir, 'config.toml');

  execFileSync(bin, ['generate-ca', '--out', tmpDir], { stdio: 'pipe' });

  let lastErr: unknown;
  for (let attempt = 0; attempt < 2; attempt++) {
    const proxyPort = await freePort();
    const dashPort = await freePort();

    writeFileSync(
      configPath,
      [
        '[proxy]',
        `bind_address = "127.0.0.1:${proxyPort}"`,
        `ca_cert = "${caCertPath}"`,
        `ca_key  = "${caKeyPath}"`,
        '',
        '[logging]',
        `audit_log = "${auditLogFile}"`,
        '',
        '[approvals]',
        `permanent_rules_file = "${permanentRulesFile}"`,
        `dashboard_bind = "127.0.0.1:${dashPort}"`,
        '',
      ].join('\n'),
    );

    const child = spawn(bin, ['run', '--config', configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const inst = new PylorosInstance({
      dashPort,
      proxyPort,
      caCertPath,
      permanentRulesFile,
      auditLogFile,
      tmpDir,
      child,
    });

    const ready = await waitForReady(dashPort, proxyPort, child);
    if (ready) return inst;

    lastErr = new Error(
      `pyloros did not become ready (attempt ${attempt + 1}).\nstderr:\n${inst.diagnostics()}`,
    );
    child.kill('SIGKILL');
  }
  rmSync(tmpDir, { recursive: true, force: true });
  throw lastErr;
}

async function waitForReady(
  dashPort: number,
  proxyPort: number,
  child: ChildProcess,
): Promise<boolean> {
  for (let i = 0; i < 100; i++) {
    if (child.exitCode !== null) return false;
    try {
      const status = await httpGetStatus(`http://127.0.0.1:${dashPort}/`);
      if (status === 200 && (await tcpConnects(proxyPort))) return true;
    } catch {
      // not up yet
    }
    await sleep(100);
  }
  return false;
}
