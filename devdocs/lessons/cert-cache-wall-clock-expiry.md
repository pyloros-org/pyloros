# Cert cache expiry must use wall-clock time, not `Instant`

`std::time::Instant` on Linux is `CLOCK_MONOTONIC`, which **does not count time the system is
suspended** (`CLOCK_BOOTTIME` is the variant that does — see `man 2 clock_gettime`). X.509
`notBefore`/`notAfter` are wall-clock. Mixing the two in a certificate cache produces a failure
that only appears on hosts that suspend.

## The bug this replaced

The cert cache stored `created_at: Instant` and evicted after a 12h TTL, while certificates were
issued with 24h validity. On Docker Desktop for macOS the whole Linux VM is paused when the Mac
sleeps, so guest `CLOCK_MONOTONIC` freezes while `CLOCK_REALTIME` is stepped forward by the
timesync daemon on resume:

1. Friday: proxy issues a cert for `api.github.com`, `notAfter` = Saturday. Cached.
2. Mac sleeps until Monday. Guest monotonic clock does not advance.
3. Monday: `created_at.elapsed()` reads a few minutes, so the cache serves the cert. The client
   validates against wall-clock Monday and rejects it: `CERTIFICATE_EXPIRED`.

It is sticky, not transient. The entry only leaves the cache after 12h of *running* time or via
LRU eviction, and with a 1000-entry cache a sandbox touching a handful of hosts never triggers
eviction. Restarting the proxy clears it, which makes it look like proxy flakiness.

Trigger threshold was any suspend longer than `validity - TTL` = 12h. An overnight sleep is
borderline; a weekend is guaranteed.

## The fix

The cache stores the certificate's own `not_after` (returned by `generate_cert_for_host`) and
evicts once `now + RENEWAL_MARGIN > not_after`. There is no independent TTL, so the cache cannot
disagree with the certificate. The margin (1h) keeps a cert from being handed to a handshake with
moments of validity left.

## Related: backdate `notBefore`

`notBefore = now` gives zero tolerance for a client clock behind the proxy's — including the
window after a VM resume before timesync fires, and a `generate-ca` run on a VM that booted with
an unsynced clock (that one poisons the CA for its full 10-year life). Both CA and host certs are
backdated 1h.

A clock stepped *backwards* past the backdate is not recoverable at this layer: it invalidates
the CA chain and every other certificate on the system too.
