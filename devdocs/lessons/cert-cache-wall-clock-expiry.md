# Cert cache expiry must use wall-clock time, not `Instant`

`Instant` on Linux is `CLOCK_MONOTONIC`, which **does not count time the system is suspended**
(`CLOCK_BOOTTIME` is the variant that does — `man 2 clock_gettime`). X.509 `notBefore`/`notAfter`
are wall-clock. Mixing the two in a cert cache breaks on any host that suspends.

The cache used to store `created_at: Instant` with a 12h TTL against 24h certs. On Docker Desktop
for macOS the VM is paused while the Mac sleeps, so guest monotonic time freezes while
`CLOCK_REALTIME` is stepped forward on resume: `elapsed()` reads minutes, the cache serves the
cert, the client rejects it as expired. Sticky, not transient — the entry survives until 12h of
*running* time passes, and a 1000-entry LRU never fills for a sandbox using a handful of hosts.
Restarting the proxy cleared it, so it looked like proxy flakiness. Threshold was any suspend
longer than `validity - TTL`.

Fix: store the cert's own `not_after` (returned by `generate_cert_for_host`) and evict at
`now + 1h > not_after`. No separate TTL, so the cache cannot disagree with the cert.

Related: `not_before = now` gives zero tolerance for a client clock behind the proxy's — a VM
resumed before timesync, or `generate-ca` run on an unsynced clock, which poisons the CA for its
full 10-year life. Both cert types are backdated 1h. A clock stepped backwards further than that
isn't recoverable here; it invalidates the CA chain too.
