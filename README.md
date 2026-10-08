# @sentinelsup/sdk

Official Node.js SDK for [Maskbreak](https://maskbreak.com) — network and device fraud signals for browser-SDK-backed visits, plus limited public IP intelligence.

[![npm](https://img.shields.io/npm/v/@sentinelsup/sdk.svg)](https://www.npmjs.com/package/@sentinelsup/sdk)
[![npm downloads](https://img.shields.io/npm/dm/@sentinelsup/sdk.svg)](https://www.npmjs.com/package/@sentinelsup/sdk)
[![types](https://img.shields.io/npm/types/@sentinelsup/sdk.svg)](./index.d.ts)
[![license](https://img.shields.io/npm/l/@sentinelsup/sdk.svg)](./LICENSE)

## Set up with AI (fastest)

Using Claude Code, Cursor, Copilot, or any AI coding assistant? Paste this
one prompt and it wires the whole integration — frontend script, backend
check, env var, and a test:

> Fetch https://maskbreak.com/integrate.md and follow it to add Maskbreak fraud
> protection to this app — protect signup, login, and checkout. Start in watch
> mode (MASKBREAK_MODE). Read the API key from the server-only
> MASKBREAK_API_KEY environment variable; I will configure the secret
> separately. Never put it in client-side code. Then show me how to test it.

Never paste the key itself into a prompt: set it in your hosting secrets.

[`integrate.md`](https://maskbreak.com/integrate.md) is the canonical
machine-readable integration guide, kept in sync with the live API.

## Install

```bash
npm install @sentinelsup/sdk
```

Zero dependencies. Requires Node.js 18+ with built-in `fetch`. Other runtimes and edge bundlers are not covered by this package's test matrix.

## Quick start

Three steps give you the first complete check, one that carries both the
network token and the browser check. The Maskbreak dashboard's setup uses the
same names.

**1. Add the script to the page with your form**, and `class="monocle-enriched"`
to the `<form>` element itself (never to an input):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<form class="monocle-enriched" method="post" action="/signup">
  <!-- your fields; the script adds monocle, sentinel_fp and sentinel_tz -->
</form>
```

Your site sends a Content-Security-Policy header? helmet's default policy does,
and it blocks the script until you add Maskbreak's hosts:
[the list](https://maskbreak.com/integrate.md#content-security-policy). The
hidden fields fill in a second or two after the page loads.

**2. Send the check from your server.** One field mapping, whichever way the
browser part sends it:

| Form field | `Sentinel.collect()` returns | Send to the API as |
|---|---|---|
| `monocle` (network token) | `token` | `token` |
| `sentinel_fp` (browser check) | `fingerprintEventId` | `fingerprintEventId` |
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; raw HTTP only, see below) |

Start in watch mode: every submission is checked and logged, a submission with
a missing field included (the dashboard then says which half did not arrive),
and nobody is blocked. `evaluate()` will not send a request without the network
token, so the quick start reports those submissions over plain HTTP:

```js
const Sentinel = require('@sentinelsup/sdk');

const sentinel = new Sentinel(); // reads MASKBREAK_API_KEY from the environment

// Start in watch mode: log Maskbreak's answer and let everyone through.
// When Events look right, set MASKBREAK_MODE=enforce and redeploy.
const MODE = process.env.MASKBREAK_MODE || 'watch';

// evaluate() refuses to send without the network token. In watch mode a
// submission without it is reported anyway, so the dashboard can say so.
async function reportWithoutToken(fields) {
  const response = await fetch('https://maskbreak.com/v1/evaluate', {
    method: 'POST',
    signal: AbortSignal.timeout(5000),
    headers: {
      Authorization: 'Bearer ' + process.env.MASKBREAK_API_KEY,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(fields)
  });
  return response.ok ? response.json() : null;
}

app.post('/signup', async (req, res, next) => {
  const body = req.body || {};
  // Form fields -> API names. Sentinel.collect() already uses the API names.
  const token = body.monocle || body.token;
  const fingerprintEventId = body.sentinel_fp || body.fingerprintEventId;
  let result = null, problem = null;
  try {
    if (token) {
      result = await sentinel.evaluate({ token, fingerprintEventId });
    } else if (MODE !== 'enforce') {
      result = await reportWithoutToken({ fingerprintEventId, tz: body.sentinel_tz || body.tz });
    }
  } catch (err) {
    problem = err.message; // an uncaught rejection would end an Express 4 process
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer', result ? result.reasons : problem);
  if (MODE === 'enforce' && (!result || result.decision !== 'allow')) {
    return res.status(result && result.decision === 'block' ? 403 : 409).json({ error: 'Verification required' });
  }
  next(); // watch mode, or an allow: your existing handler runs
});
```

**3. Submit your form once.** Deploy, open the page and submit the form. The
first check then appears in the dashboard (Integration tab and Events).

A form your JavaScript renders and submits (fetch, React, Next.js, Vue) sends
`await window.Sentinel.collect()` with its data instead: see
[Next.js App Router](#nextjs-app-router) below. The full enforce policy
(review, missing evidence, test and degraded answers) is in
[integrate.md](https://maskbreak.com/integrate.md).

Get a free API key (no credit card) at [maskbreak.com/signup](https://maskbreak.com/signup).

Since v0.3.3, `new Sentinel()` without a key reads `MASKBREAK_API_KEY` from the environment; the older `SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

## What you get back

Illustrative response. The VPN/proxy service name is returned only when known; otherwise it is `null`. Device fields require available device intelligence, not just a supplied event ID.

```ts
{
  decision: 'review',          // 'allow' | 'review' | 'block' — route on this
  risk_score: 65,              // 0–100
  isSuspicious: true,          // legacy flag; route on decision instead
  ip: '198.51.100.18',
  country: 'NL',
  network: {
    vpn: true, proxy: false, datacenter: true, anonymous: true,
    tor: false, residential: false, service: 'PROTON_VPN'
  },
  device: {                    // when fingerprintEventId resolves to device data
    antidetect: false,         // antidetect browser detected
    automation: false,         // bot / browser automation
    emulator: false, virtual_machine: false, incognito: false,
    ip_blocklisted: false, visitor_id: 'abc123', tampering_score: 0
  },
  reasons: ['vpn_detected', 'datacenter_asn']  // machine-readable codes
}
```

Try the live sample (same shape, no key needed):
`curl "https://maskbreak.com/v1/evaluate/sample?scenario=vpn"`

Legacy `details` / `deviceIntel` fields are still returned for backwards
compatibility with 0.1.0 integrations.

## Frontend setup

Add the Maskbreak SDK to the page with your form. One script loads **both**
layers — network (VPN/proxy/datacenter) and device (antidetect/bot/tampering):

```html
<script async src="https://maskbreak.com/assets/sentinel.js"></script>

<!-- class="monocle-enriched" on the form itself, never on an input -->
<form class="monocle-enriched" id="checkout-form">
  <!-- The SDK fills in:
       <input type="hidden" name="monocle"     value="eyJ...">  (network)
       <input type="hidden" name="sentinel_fp" value="a1b2..."> (device)
       <input type="hidden" name="sentinel_tz" value="Europe/Tallinn"> -->
</form>
```

If your site sends a Content-Security-Policy header (helmet's default policy
does), it must allow the SDK's hosts or the browser blocks the script:
[the list in the integration guide](https://maskbreak.com/integrate.md#content-security-policy).

A form your JavaScript submits collects the same evidence and sends it to your
backend. `collect()` waits at most 5 seconds for the device check
(`collect({ timeout: ms })` to change it); a value that is not there by then is
`null`. Check that the script is there, and never hold the form because of it:

```js
const evidence = window.Sentinel ? await window.Sentinel.collect() : {};
fetch('/checkout', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  // evidence = { token, fingerprintEventId, tz }, already the API's names
  body: JSON.stringify({ email: form.email.value, ...evidence })
});
```

## Examples

The examples below act on the decision, so they belong after the quick
start's watch mode, once Events look right. `evaluate()` throws when the
browser sent no token or the API cannot be reached, so every handler below
catches it. In Express 4 an async handler's uncaught error is an unhandled
rejection, which ends the whole Node process, not just the request. The
examples use this helper, which reads both namings (form fields and
`collect()`'s), and treat `null` as "no answer": decide what your endpoint does
then (here: continue).

```js
// Form fields (monocle, sentinel_fp) or collect()'s names (token, fingerprintEventId).
const evidence = body => ({
  token: body.token || body.monocle,
  fingerprintEventId: body.fingerprintEventId || body.sentinel_fp
});

async function check(input) {
  try {
    return await sentinel.evaluate(input);
  } catch (err) {
    console.log('[maskbreak] check unavailable:', err.message);
    return null;
  }
}
```

### Next.js App Router

Load the script once in `app/layout.js`
(`<Script src="https://maskbreak.com/assets/sentinel.js" strategy="afterInteractive" />`
from `next/script`), collect on submit in the client component that renders the
form, and check in a Route Handler. The key stays in a server-only environment
variable, never a `NEXT_PUBLIC_` one.

```jsx
// app/signup/signup-form.js
'use client';

export default function SignupForm() {
  async function onSubmit(event) {
    event.preventDefault();
    const email = new FormData(event.currentTarget).get('email');
    // No script (blocked or not loaded)? The form still goes through.
    const evidence = window.Sentinel ? await window.Sentinel.collect() : {};
    await fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, ...evidence })
    });
  }
  return (
    <form onSubmit={onSubmit}>
      <input type="email" name="email" required />
      <button type="submit">Sign up</button>
    </form>
  );
}
```

```js
// app/api/signup/route.js (server only)
import Sentinel from '@sentinelsup/sdk';

const MODE = process.env.MASKBREAK_MODE || 'watch';
// Created on the first request, not at import: `next build` imports route
// modules, and new Sentinel() throws when MASKBREAK_API_KEY is not set there.
let sentinel;

// evaluate() refuses to send without the network token; watch mode reports anyway.
async function reportWithoutToken(fields) {
  const response = await fetch('https://maskbreak.com/v1/evaluate', {
    method: 'POST',
    signal: AbortSignal.timeout(5000),
    headers: { Authorization: 'Bearer ' + process.env.MASKBREAK_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify(fields)
  });
  return response.ok ? response.json() : null;
}

export async function POST(request) {
  const body = (await request.json().catch(() => null)) || {};
  const { token, fingerprintEventId, tz, email } = body; // collect()'s names
  let result = null;
  try {
    if (token) result = await (sentinel ??= new Sentinel()).evaluate({ token, fingerprintEventId, email }); // reads MASKBREAK_API_KEY
    else if (MODE !== 'enforce') result = await reportWithoutToken({ fingerprintEventId, tz, email });
  } catch (err) {
    console.log('[maskbreak] check unavailable:', err.message);
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer');
  if (MODE === 'enforce' && (!result || result.decision !== 'allow')) {
    return Response.json({ error: 'Verification required' }, { status: result && result.decision === 'block' ? 403 : 409 });
  }
  return createAccount(body); // your existing signup logic
}
```

### Stripe Checkout — block card testing

```js
const Sentinel = require('@sentinelsup/sdk');
const stripe = require('stripe')(process.env.STRIPE_KEY);
const sentinel = new Sentinel({ apiKey: process.env.MASKBREAK_API_KEY });

app.post('/checkout', async (req, res) => {
  const result = await check(evidence(req.body));
  if (result && result.decision === 'block') return res.status(403).json({ error: 'declined' });

  const intent = await stripe.paymentIntents.create({ /* ... */ });
  res.json({ clientSecret: intent.client_secret });
});
```

### Signup — block fake Google sign-ins

```js
app.post('/auth/google', async (req, res) => {
  const ticket = await googleClient.verifyIdToken({ idToken: req.body.credential });

  const result = await check(evidence(req.body));
  if (result && result.decision === 'block') return res.status(403).json({ error: 'signup_blocked' });

  await createUser(ticket.getPayload().email, result?.device?.visitor_id);
});
```

### Custom policy with `shouldBlock`

```js
// Keep the API's own blocks, and also block a VPN visitor whose device is
// already behind another of your accounts. The API alone answers review for
// that visit (a VPN is review; a shared device adds the multi_account_device
// reason without changing the decision). device.multi_account needs the
// accountId you pass and a resolved device event. shouldBlock() throws like
// evaluate(): call it inside try/catch.
const blocked = await sentinel.shouldBlock(
  { token, fingerprintEventId, accountId: user.id },
  r => r.decision === 'block' || (r.network.vpn && r.device?.multi_account === true)
);
```

### Burner-email check at signup

```js
// Pass the signup email and Sentinel checks it against a continuously
// refreshed disposable-domain feed. A hit adds the disposable_email
// reason, raises risk_score, and escalates allow → review. The address
// is checked transiently — never stored or logged.
const result = await check({ token, email: req.body.email });
if (result?.email?.disposable) {
  // e.g. require a real address before granting the trial
}
```

### Look up an arbitrary IP — no browser token needed

```js
// Batch scoring, log enrichment, server-side screening. Same key,
// same hourly quota as evaluate().
const info = await sentinel.lookup('185.220.101.34');
// info.verdict     → 'allow' | 'review' | 'block'
// info.risk_score  → 0–100
// info.signals     → { vpn, proxied, tor, dch, anon } (null when known:false)
// info.network     → { asn, org, country, city }
```

## API

### `new Sentinel({ apiKey?, endpoint?, timeoutMs? })`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | `$MASKBREAK_API_KEY` (then `$SENTINEL_KEY`, `$SENTINEL_API_KEY`) | Your key starting with `sk_live_`; required unless one of those env vars is set |
| `endpoint` | string | `https://maskbreak.com` | Override base URL |
| `timeoutMs` | number | `5000` | Per-request timeout |

### `sentinel.evaluate({ token, fingerprintEventId?, accountId?, email? })`

Returns `EvaluateResult`. Throws `SentinelError` when `token` is missing or empty and on network/API failure — an API error carries `.status` and `.body`.

- `fingerprintEventId` — requests device signals (tampering, automation, emulator, …). When the device is identified, `device.times_seen`, `device.first_seen` and `device.returning` describe its retained sightings across Maskbreak, not just your account. These records are pruned after 90 days of inactivity; `first_seen` is not necessarily the device's lifetime first visit.
- `accountId` — your own user id for this session; with an identified device, enables customer-scoped account linking (`device.linked_accounts` / `device.multi_account`). Links are hash-only, never cross-customer, and pruned after 90 days of inactivity.
- New `device.customer_history` reports distinct verified events, first/latest visit and associated account counts **only for your customer account** over a rolling 90-day window. Fresh live-key events start this history; test keys and duplicate event submissions do not add to it. Derive `accountId` from your backend's authenticated session, never a browser-claimed account ID. Shared devices are not automatically fraud. Legacy fields above retain their meanings.
- An optional, default-off [GPU evidence beta](https://maskbreak.com/api#device-history) is available over raw HTTP with explicit browser collection. Published SDK versions may omit `gpuEvidence`; use the documented HTTP flow. It does not change fraud decisions or automatically link devices.
- `email` — adds `email.disposable` to the response; burner domains escalate `allow` to `review`.

### `sentinel.lookup(ip)`

Returns `LookupResponse` for a public IPv4/IPv6 address (wraps `GET /v1/lookup/{ip}`): a verdict, risk score and limited public-feed evidence from cloud-hosting ranges and Tor exit lists. Legacy VPN/proxy fields do not establish complete coverage. Use `evaluate()` with a browser SDK token for VPN/proxy evidence and service naming when known. `known: false`, false signals or an `allow` verdict are **not** a safety guarantee. Network metadata may be null. Shares the hourly quota with `evaluate()` (one per account for the live keys; the test key has its own) and has its own monthly allowance.

### `sentinel.shouldBlock({ token, fingerprintEventId? }, predicate?)`

Convenience: runs `evaluate()` and returns a boolean; it throws `SentinelError` in the same cases (no token, API failure), so call it inside `try`/`catch`. Default predicate is `r => r.decision === 'block'` (honors your dashboard rules and allow/block pins). Pass your own to build custom policies.

> `accountId`, `email`, and `lookup()` require **v0.2.1 or later** (`npm install @sentinelsup/sdk@latest`) — the older 0.1.2 silently ignores `accountId`/`email`.

## Testing

Deterministic test tokens exercise every decision path from a terminal — authenticated and rate-limited like real calls, but never billed, stored, or webhooked (responses carry `"test": true`):

```js
await sentinel.evaluate({ token: 'test_vpn' });   // → engine decision: 'review' (your rules/pins may override)
await sentinel.evaluate({ token: 'test_clean' }); // → decision: 'allow' path
// also: test_proxy, test_datacenter, test_tor
```

- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same `test_*` tokens with the same shapes — no signup, nothing stored.
- **CI / staging with real traffic:** every account also has a personal `sk_test_…` key (Settings → API keys) that runs the complete live pipeline — device intelligence, your rules and exception pins. Its events are marked test, kept out of your stats and never fire webhooks; its checks count toward the monthly allowance (the fixed `test_*` tokens and `sk_test_sandbox` do not). It is exempt from the account's IP allowlist.

## Rate limits

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with an hourly cap: **Free — 10,000 a month, up to 1,000 an hour, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges.

On `503` with `.body.code === 'storage_unavailable'`, the key could not be checked at that moment (not an invalid key; `401` is): retry later and apply your outage policy meanwhile.

On `429`, the thrown `SentinelError` has `.status === 429`. This SDK exposes status and body, not HTTP response headers. If your integration needs `Retry-After` or `X-RateLimit-*`, use raw HTTP and read those headers from the response. Use bounded backoff and an endpoint-specific fallback; an unavailable check is not an allow verdict. Approved public-interest accounts have no hourly or monthly cap and are exempt from the per-address request ceiling; `/v1/usage` and invalid-key protection keep their own limits.

The current `evaluate()` helper requires a non-empty token and does not serialize `tz`. Raw HTTP accepts missing or empty tokens as degraded evaluations and supports the timezone returned by `Sentinel.collect()`. Use the [HTTP reference](https://maskbreak.com/api#evaluate) for those paths; missing network evidence does not prove a visitor is safe.

## Development checks

```bash
npm ci --ignore-scripts
npm test
npm pack --dry-run --ignore-scripts
npm audit
```

Tests use local fixtures, not production keys. CI checks Node.js 18, 22 and 24. These commands do not publish a package.

## TypeScript

Full types ship with the package. Importing `Sentinel` gives you the class plus `EvaluateResult`, `DeviceIntel`, `EvaluateDetails`, and `SentinelError` types.

```ts
import Sentinel, { EvaluateResult } from '@sentinelsup/sdk';
```

## What Maskbreak detects

SDK-backed visits can supply VPN/proxy, cloud-hosting and Tor signals, with VPN/proxy service names when known. Available device intelligence adds browser tampering, automation, emulator and virtual-machine signals. Coverage depends on the evidence available; these are not guarantees of detecting every product or visitor. Bare-IP lookup is limited to public cloud-range and Tor evidence.

## Related

- **Python SDK** — [`sentinelsup`](https://github.com/sentinelsup/maskbreak-python) on PyPI
- **Free IP lookup tool** — [maskbreak.com/ip-lookup](https://maskbreak.com/ip-lookup)

## License

MIT © Sentinel Edge Networks LTD

## Links

- Website — [maskbreak.com](https://maskbreak.com)
- API docs — [maskbreak.com/api](https://maskbreak.com/api)
- Blog — [maskbreak.com/blog](https://maskbreak.com/blog)
