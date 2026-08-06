# Two dashboard JS bugs the Playwright e2e tests caught

The approvals dashboard's served JS (`src/approvals/dashboard.html`) had two bugs
that no Rust/HTTP-level test could catch (they only manifest in a real browser).
Both were found by the first run of the `e2e/` Playwright suite.

## 1. `resolved` SSE status shape mismatch (nested vs. flattened)

`ApprovalRequest` flattens its status, so the `snapshot` / `pending` frames carry a
**string** discriminant:

```json
{"id":"apr_…","rules":[…],"status":"pending"}
```

But `NotifierEvent::Resolved { id, status: ApprovalStatus }` does **not** flatten —
the `resolved` frame carries a **nested object**:

```json
{"event":"resolved","id":"apr_…","status":{"status":"approved","rules_applied":[…],"ttl":"one_hour"}}
```

The handler did `a.status = msg.status` (assigning the object), then
`renderPendingCard` compared `a.status === 'approved'`/`'denied'` (string) → never
matched, so the approved/denied tag never rendered, and `msg.rules_applied` /
`msg.message` (read at top level) were always `undefined`. Fix: read the nested
shape — `a.status = msg.status.status; a.rules_applied = msg.status.rules_applied; …`.

## 2. `style.display = ''` does not override a CSS `display: none`

`.parse-error` is `display: none` in the stylesheet. The error-reveal path set
`errEl.style.display = ''`, which *clears the inline property* and reverts to the
stylesheet value (`none`) — so the inline parse error was populated with text but
stayed invisible. Setting the text without showing the element is a silent no-op to
the user. Fix: set an explicit visible value, `errEl.style.display = 'block'`.
(The permissive-bar buttons use `style.display = ''` correctly because they have no
`display: none` CSS rule — there, reverting to the default is what you want.)

**Takeaway:** assert *visibility/rendered state* in the browser (`toBeVisible()`,
tag presence), not just that an element exists or that an endpoint returned the right
JSON. HTTP-level tests confirmed the server behaved; only a browser exercised the JS
that consumes it.
