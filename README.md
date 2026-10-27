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
| `sentinel_tz` (time zone) | `tz` | `tz` (optional; `evaluate()` sends it since 0.5.0) |

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
  const tz = body.sentinel_tz || body.tz;
  let result = null, problem = null, monthUsedUp = false;
  try {
    if (token) {
      result = await sentinel.evaluate({ token, fingerprintEventId, tz });
    } else if (MODE !== 'enforce') {
      result = await reportWithoutToken({ fingerprintEventId, tz });
    }
  } catch (err) {
    problem = err.message; // an uncaught rejection would end an Express 4 process
    // The month's checks are used up: let the action through, logged, until the 1st.
    monthUsedUp = err.status === 429 && err.body?.code === 'monthly_quota_exceeded';
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer', result ? result.reasons : problem);
  // A test or sample answer is never a real visitor's verdict: anyone can send a test token.
  if (MODE === 'enforce' && !monthUsedUp && (!result || result.decision !== 'allow' || Sentinel.isFixtureAnswer(result))) {
    return res.status(result && result.decision === 'block' ? 403 : 409).json({ error: 'Verification required' });
  }
  next(); // watch mode, or an allow: your existing handler runs
});
```

**3. Submit your form once.** Run your app where you can open the page, on
your computer or on your site, and submit the form once. The first check then
appears in the dashboard (Integration tab and Events), and
[`sentinel.setupStatus()`](#check-your-setup) says whether it arrived complete
and what to fix.

A form your JavaScript renders and submits (fetch, React, Next.js, Vue) sends
`await window.Sentinel.collect()` with its data instead: see
[Next.js App Router](#nextjs-app-router) below. The full enforce policy
(review, missing evidence, test and degraded answers) is in
[integrate.md](https://maskbreak.com/integrate.md).

Get a free API key (no credit card) at [maskbreak.com/signup](https://maskbreak.com/signup).

Since v0.3.3, `new Sentinel()` without a key reads `MASKBREAK_API_KEY` from the environment; the older `SENTINEL_KEY` and `SENTINEL_API_KEY` names are still read as fallbacks.

## What's new

### 0.5.0 (2026-10-27)

- `evaluate()` sends the fields the API has read since 23 October 2026: `tz`,
  `phone`, and for login protection `event`, `loginSucceeded`, `succeeded`,
  `sessionId`, `userAgent`, `ip`, `reason`, `verificationType` and
  `verifiedEvent`. See [Logins, signups and account events](#logins-signups-and-account-events).
- The account events `password_change`, `verification`, `logout` and
  `account_change` can be sent without the browser's token. A login, a signup
  and a plain check still need it.
- A value the API would ignore or misread (an `event` such as `'signin'`, a
  `loginSucceeded` that is not `true` or `false`) throws a `SentinelError`
  before anything is sent, instead of a check that quietly runs without it.
- A check sent without `fingerprintEventId` prints one warning per process:
  such checks have no browser part. `new Sentinel({ warnMissingBrowserPart: false })`
  turns it off.
- New `sentinel.setupStatus()` (`GET /v1/setup`) says whether your checks
  arrive complete and what to fix.
- Types for the answer's `account_takeover`, `account_event`, `phone`,
  `timezone`, the scored `email` fields, `sandbox` and `sample`.

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
    vpn: true, proxy: false, privacy_relay: false, datacenter: true, anonymous: true,
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

With `event`, `email`, `phone` or `tz` in the request, the answer also carries
`account_takeover` or `account_event`, the scored `email` fields, `phone` and
`timezone`: see [Logins, signups and account events](#logins-signups-and-account-events).

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
browser sent no token (outside the [account events](#account-events)) or the
API cannot be reached, so every handler below catches it. In Express 4 an async handler's uncaught error is an unhandled
rejection, which ends the whole Node process, not just the request. The
examples use this helper, which reads both namings (form fields and
`collect()`'s), and treat `null` as "no answer": decide what your endpoint does
then (here: continue).

```js
// Form fields (monocle, sentinel_fp, sentinel_tz) or collect()'s names (token, fingerprintEventId, tz).
const evidence = body => ({
  token: body.token || body.monocle,
  fingerprintEventId: body.fingerprintEventId || body.sentinel_fp,
  tz: body.tz || body.sentinel_tz
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
  let result = null, monthUsedUp = false;
  try {
    if (token) result = await (sentinel ??= new Sentinel()).evaluate({ token, fingerprintEventId, tz, email }); // reads MASKBREAK_API_KEY
    else if (MODE !== 'enforce') result = await reportWithoutToken({ fingerprintEventId, tz, email });
  } catch (err) {
    console.log('[maskbreak] check unavailable:', err.message);
    // The month's checks are used up: let the action through, logged, until the 1st.
    monthUsedUp = err.status === 429 && err.body?.code === 'monthly_quota_exceeded';
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer');
  // A test or sample answer is never a real visitor's verdict: anyone can send a test token.
  if (MODE === 'enforce' && !monthUsedUp && (!result || result.decision !== 'allow' || Sentinel.isFixtureAnswer(result))) {
    return Response.json({ error: 'Verification required' }, { status: result && result.decision === 'block' ? 403 : 409 });
  }
  return createAccount(body); // your existing signup logic
}
```

### Stripe Checkout and login: check before the expensive step

Check before `stripe.paymentIntents.create()` and before the password hash
runs. Scripted card testing and credential stuffing often send no browser
token at all, so this gate does not wave such a request through: in enforce
mode only a real `allow` goes on.

```js
const stripe = require('stripe')(process.env.STRIPE_KEY);
const MODE = process.env.MASKBREAK_MODE || 'watch';

// Watch (the default) logs and always continues. Enforce holds everything but
// a real allow: no token, no answer, review, block or a test answer (anyone
// can send a test token). A used-up month continues, logged, until the 1st.
async function gate(body) {
  const input = evidence(body);
  let result = null, monthUsedUp = false;
  try {
    if (input.token) result = await sentinel.evaluate(input);
  } catch (err) {
    console.log('[maskbreak] check unavailable:', err.message);
    monthUsedUp = err.status === 429 && err.body?.code === 'monthly_quota_exceeded';
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer');
  if (MODE !== 'enforce' || monthUsedUp) return null;
  if (!result || result.decision !== 'allow' || Sentinel.isFixtureAnswer(result)) {
    return result && result.decision === 'block' ? 403 : 409; // 409: your verification flow
  }
  return null;
}

app.post('/api/checkout', async (req, res) => {
  const held = await gate(req.body);
  if (held) return res.status(held).json({ error: 'Verification required' });
  const intent = await stripe.paymentIntents.create({
    amount: calculateTotal(req.body.items), // from your own prices, never a submitted amount
    currency: 'usd',
    automatic_payment_methods: { enabled: true }
  });
  res.json({ clientSecret: intent.client_secret });
});

app.post('/api/login', async (req, res, next) => {
  const held = await gate(req.body); // before bcrypt or argon2 runs
  if (held) return res.status(held).json({ error: 'Verification required' });
  next(); // your existing credential check
}, existingLoginHandler);
```

A visitor who passes still confirms the payment with the client secret and
can try another card on the same intent: keep Stripe Radar and your own
attempt limits. To link devices to accounts, pass your own user id as
`accountId` (from your database, never the email or another form field).

### Signup — block fake Google sign-ins

```js
app.post('/auth/google', async (req, res) => {
  const ticket = await googleClient.verifyIdToken({ idToken: req.body.credential });

  const result = await check(evidence(req.body));
  if (result && (result.decision === 'block' || Sentinel.isFixtureAnswer(result))) return res.status(403).json({ error: 'signup_blocked' });

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
// reason, raises risk_score, and escalates allow → review. With email and
// phone intelligence on (the default for accounts created from
// 23 October 2026) the address is also scored by the email- and
// phone-intelligence provider (email.checked/score/risk/signals; 80 or
// more adds email_high_risk) and uses one of the plan's daily
// email-and-phone checks. Maskbreak never stores or logs the address.
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

## Logins, signups and account events

Since 0.5.0 `evaluate()` sends the fields the API reads for login protection
and for email and phone intelligence, so the call your login, signup and
account handlers already make carries them. The examples use the `evidence()`
and `check()` helpers above.

### A login

Make the check after your own password check, so it can say whether the
password was right. `accountId` is the account being signed in to, as your
database knows it (never a form field). Each call is a check: this one takes
the place of the [gate before the password hash](#stripe-checkout-and-login-check-before-the-expensive-step)
on your login route rather than adding to it.

```js
app.post('/login', async (req, res) => {
  const user = await findUserByEmail(req.body.email);               // your database
  const passwordOk = Boolean(user && await verifyPassword(user, req.body.password));

  let result = null, monthUsedUp = false;
  try {
    result = await sentinel.evaluate({
      ...evidence(req.body),                          // the browser's token, fingerprintEventId and tz
      event: 'login',
      accountId: user ? String(user.id) : undefined,  // your own id for the account
      loginSucceeded: passwordOk,                     // send failed attempts too
      sessionId: req.sessionID,                       // your session ID: only a keyed hash leaves Maskbreak
      userAgent: req.get('user-agent'),               // as your server received it
      ip: req.ip                                      // as your server saw it
    });
  } catch (err) {
    console.log('[maskbreak] check unavailable:', err.message);
    monthUsedUp = err.status === 429 && err.body?.code === 'monthly_quota_exceeded';
  }
  console.log('[maskbreak]', MODE, result ? result.decision : 'no answer', result?.account_takeover);

  if (!passwordOk) return res.status(401).json({ error: 'Wrong email or password.' });
  if (MODE === 'enforce' && !monthUsedUp) {
    if (result && result.decision === 'block') return res.status(403).json({ error: 'Sign-in unavailable.' });
    // Review, no answer or a test answer: a second factor, not a refusal.
    if (!result || result.decision !== 'allow' || Sentinel.isFixtureAnswer(result)) return sendSecondFactor(res, user);
  }
  return signIn(res, user); // your existing session code
});
```

- `ip` is used only when the network token gave no address, and never changes
  the network verdict. Behind a proxy, set Express's `trust proxy` for your
  setup so `req.ip` is the visitor's address; never take the first
  `X-Forwarded-For` value on trust.
- The answer gains `account_takeover`: `{ checked: true, score, risk, signals }`
  with a score from 0 to 100 (higher is riskier; `risk` is `low` below 50,
  `medium` from 50, `high` from 80). A score of 80 or more adds the reason
  `account_takeover_risk` and raises `allow` to `review`, never to `block`:
  answer it with a second factor or an emailed code.
- `checked: false` comes with `why`: `not_enabled` (switched off in Settings),
  `no_account_id`, `test`, `busy`, `unavailable` or `not_available`. Treat it
  as no opinion; the rest of the answer is unaffected.
- Login protection is on for every account until a workspace admin switches
  it off in Settings, and it acts only when you send `event` with
  `accountId`. Its score learns from the logins of every Maskbreak customer who
  uses login protection; say so in your own privacy notice. A login counts as
  a normal check.

### A signup with email and phone

Send `event: 'signup'` once your database has the new account's id, with the
address and the number the person gave:

```js
const result = await check({
  ...evidence(req.body),
  event: 'signup',               // the account was created
  accountId: String(user.id),    // the new account's id, from your database
  email: req.body.email,
  phone: req.body.phone          // international format, such as +44 20 7946 0958
});
console.log('[maskbreak]', result?.decision, result?.email, result?.phone, result?.account_event);
// A review: keep the new account waiting until it confirms its email or phone.
```

- With email and phone intelligence on, `email` gains `checked`, `score`,
  `risk`, `signals` and a few facts, and the answer gains a `phone` object of
  the same shape. A score of 80 or more adds `email_high_risk` or
  `phone_high_risk` and raises `allow` to `review`, never to `block`.
- Email and phone intelligence is on by default for accounts created from 23
  October 2026; an older account switches it on in Settings, and any account
  can switch it off there. Each address or number scored uses one of the
  plan's daily email-and-phone checks: Free 3, Starter 20, Growth 50, Scale
  150 a day.
- `checked: false` comes with `why`: `not_enabled`, `quota` (the day's checks
  are used up), `invalid`, `test`, `busy`, `unavailable` or `not_available`;
  `invalid`, `busy` and `unavailable` use no daily check. Treat it as no
  opinion. Maskbreak never stores or logs the address or the number.
- `account_event` says whether login protection took the signup:
  `{ event: 'signup', recorded: true }`.

### Account events

A password change, a second factor, a logout and an account change go to login
protection too: no score comes back, and they teach it what is normal for each
account, so its login scores get sharper. These four may go without the
browser's token (since 0.5.0), for handlers with no page in front of them:

```js
// After your password-change handler has saved the new password:
await check({
  event: 'password_change',
  accountId: String(req.session.userId),  // from your server-side session
  succeeded: true,
  reason: 'user',                         // 'forgot' after a reset link, 'forced' for a reset you required
  sessionId: req.sessionID,
  userAgent: req.get('user-agent'),
  ip: req.ip
});

// A second factor, with how it was checked and what it was for:
await check({ event: 'verification', accountId: String(user.id), succeeded: codeOk,
  verificationType: 'sms', verifiedEvent: 'login' });

await check({ event: 'logout', accountId: String(req.session.userId), sessionId: req.sessionID });
await check({ event: 'account_change', accountId: String(req.session.userId), email: newEmail }); // the new email
```

- The answer gains `account_event`: `{ event, recorded: true }`, or
  `recorded: false` with the same `why` values as a login.
- Sent with `...evidence(req.body)` from a form that carries the script, it is
  a full check. Without the token it is a degraded one (`degraded: true`): its
  `decision` says nothing about the visitor's network, so read
  `account_event`. A recorded event counts as a check.
- A login and a signup are visits, so they still need the token:
  `evaluate()` throws without it, as before.

### The visitor's time zone

`tz` comes with the browser's evidence (`Sentinel.collect()` returns it, a form
carries `sentinel_tz`), so `evidence()` above already sends it:

```js
const result = await check({ token, fingerprintEventId, tz });
// result.timezone → { reported: 'Europe/Tallinn', country: 'EE', matches_ip: true, checked: true }
```

A zone whose country disagrees with an ordinary-looking address adds
`timezone_mismatch` and raises `allow` to `review`; it never blocks. On a VPN,
proxy, Tor or datacenter exit, where a mismatch is expected, nothing is raised
(`checked: false`).

### Refused before sending

A value the API would ignore or misread throws a `SentinelError`, and nothing is
sent: an `event` other than `login`, `signup`, `password_change`,
`verification`, `logout` and `account_change` (read case-insensitively, so
`'signin'` is refused), a `reason`, `verificationType` or `verifiedEvent`
outside its list, a `loginSucceeded` or `succeeded` that is not `true` or
`false`, a `tz`, `phone`, `userAgent` or `ip` that is not a string, and a
`sessionId` that is not a string or a number or is longer than 256 characters.
A field that is `undefined`, `null` or `''` is left out of the request.

## Check your setup

After you submit your form once, `setupStatus()` (`GET /v1/setup`) tells you
whether the check arrived complete and what to fix:

```js
const setup = await sentinel.setupStatus();
console.log(setup.status, '-', setup.message);
if (setup.next_step) console.log('Next:', setup.next_step);
```

| Field | What it says |
|---|---|
| `status` | What the latest check showed: `waiting` (no check in the last 7 days, and none complete before), `complete` (both parts, live key), `missing_network` (no network token), `network_unavailable` (a token that could not be read), `missing_device` (no browser event id), `device_unavailable` (a browser event that could not be verified), `test_mode` (a test token, or the test key without both parts), `test_complete` (the test key with both parts: swap in the live key), `ip_restricted`, `rate_limited` or `request_failed` |
| `complete` | At least one complete live-key check has arrived |
| `message` / `next_step` | What the latest check showed, and what to do next (`null` when nothing is left) |
| `last_check_at`, `complete_checks`, `last_complete_at` | When the latest check arrived, how many complete ones did, and when the latest of those did |
| `website` | `{ confirmed, origin }`: the website the first complete check came from |
| `script_seen` | `{ origin, at }` where and when the page script last reported in, or `null` |
| `site_id`, `key_type`, `docs` | Your site ID, which key made the call (`live` or `test`), and a link to the guide |

It works with the live key and the test key, and returns the answer as the
API sends it.

## API

### `new Sentinel({ apiKey?, endpoint?, timeoutMs?, allowTestResults?, warnMissingBrowserPart? })`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `apiKey` | string | `$MASKBREAK_API_KEY` (then `$SENTINEL_KEY`, `$SENTINEL_API_KEY`) | Your key starting with `sk_live_`; required unless one of those env vars is set |
| `endpoint` | string | `https://maskbreak.com` | Override base URL |
| `timeoutMs` | number | `5000` | Per-request timeout |
| `allowTestResults` | boolean | `false` | Only for your own test runs: `shouldBlock()` treats test, sandbox and sample answers as a normal decision |
| `warnMissingBrowserPart` | boolean | `true` | `false` turns off the one-time warning for a check sent without `fingerprintEventId` (since 0.5.0) |

### `sentinel.evaluate(input)`

Returns `EvaluateResult`. Throws `SentinelError` when `token` is missing or empty (except for the four account events below), for a value the API would ignore or misread ([Refused before sending](#refused-before-sending)), and on network/API failure — an API error carries `.status` and `.body`.

| Field | Sent as | Notes |
|---|---|---|
| `token` | `token` | The browser's network token. Required, except for `event` `password_change`, `verification`, `logout` and `account_change` |
| `fingerprintEventId` | `fingerprintEventId` | The browser check; without it the SDK warns once (below) |
| `accountId` | `accountId` | Your own id for the account (string or number); login protection needs it with `event` |
| `email` | `email` | The address the person gave |
| `tz` | `tz` | The visitor's IANA time zone (since 0.5.0) |
| `phone` | `phone` | International format (since 0.5.0) |
| `event` | `event` | `login`, `signup`, `password_change`, `verification`, `logout` or `account_change` (since 0.5.0) |
| `loginSucceeded` | `loginSucceeded` | With `login`: `true` or `false` |
| `succeeded` | `succeeded` | With `password_change` or `verification`: `true` or `false` (absent means pending) |
| `sessionId` | `sessionId` | With an event: your session ID, at most 256 characters |
| `userAgent`, `ip` | `userAgent`, `ip` | With an event: as your server received them |
| `reason` | `reason` | With `password_change`: `user`, `forgot` or `forced` |
| `verificationType` | `verificationType` | With `verification`: `email`, `sms`, `phone_call`, `app`, `push`, `security_key` or `captcha` |
| `verifiedEvent` | `verifiedEvent` | With `verification`: `login`, `signup`, `password_change` or `account_change` |

- `fingerprintEventId` — requests device signals (tampering, automation, emulator, …). When the device is identified, `device.times_seen`, `device.first_seen` and `device.returning` describe its retained sightings across Maskbreak, not just your account. These records are pruned after 90 days of inactivity; `first_seen` is not necessarily the device's lifetime first visit.
- `accountId` — your own user id for this session (take it from your server-side session, never from a form field); with an identified device, enables customer-scoped account linking (`device.linked_accounts` / `device.multi_account`). With a live key the response also carries the `account` object (the account network, since 18 October 2026): devices this account used in 24 hours and 90 days, your accounts on this device and on this address in 24 hours, `new_device` for a returning account, and how many of your other accounts it shares a device or an address with. Its reasons `account_new_device`, `account_many_devices` and `ip_many_accounts` inform only; `device_many_accounts` (3+ of your accounts on one device within 24 hours) raises an allow to review. Links are keyed hashes and never cross customers; the account network also keeps your accountId encrypted so your console can show which accounts are linked. Both are pruned 90 days after last use.
- New `device.customer_history` reports distinct verified events, first/latest visit and associated account counts **only for your customer account** over a rolling 90-day window. Fresh live-key events start this history; test keys and duplicate event submissions do not add to it. Derive `accountId` from your backend's authenticated session, never a browser-claimed account ID. Shared devices are not automatically fraud. Legacy fields above retain their meanings.
- An optional, default-off [GPU evidence beta](https://maskbreak.com/api#device-history) is available over raw HTTP with explicit browser collection. Published SDK versions may omit `gpuEvidence`; use the documented HTTP flow. It does not change fraud decisions or automatically link devices.
- `email` — adds `email.disposable` to the response; burner domains escalate `allow` to `review`. With email and phone intelligence on (the default for accounts created from 23 October 2026), `email` also carries the provider's `checked`, `score`, `risk` and `signals`, and each address scored uses one of the plan's daily email-and-phone checks.

A check sent without `fingerprintEventId` has no browser part, so bots, fake
browsers and emulators go unchecked (the dashboard says the browser part is
missing). The first such call in a process prints one `console.warn` line
saying so and how to fix it; it never contains your key or anything about the
visitor. The fixed `test_*` tokens and the four account events never trigger
it. `new Sentinel({ warnMissingBrowserPart: false })` turns it off.

### `sentinel.lookup(ip)`

Returns `LookupResponse` for a public IPv4/IPv6 address (wraps `GET /v1/lookup/{ip}`): a verdict, risk score and limited public-feed evidence from cloud-hosting ranges and Tor exit lists. Legacy VPN/proxy fields do not establish complete coverage. Use `evaluate()` with a browser SDK token for VPN/proxy evidence and service naming when known. `known: false`, false signals or an `allow` verdict are **not** a safety guarantee. Network metadata may be null. Shares the hourly quota with `evaluate()` (one per account for the live keys; the test key has its own) and has its own monthly allowance.

### `sentinel.setupStatus()`

Wraps `GET /v1/setup` (since 0.5.0) and returns its answer as is: see [Check your setup](#check-your-setup). Throws `SentinelError` on network/API failure.

### `sentinel.shouldBlock(input, predicate?)`

Convenience: runs `evaluate()` and returns a boolean; it throws `SentinelError` in the same cases (no token, API failure), so call it inside `try`/`catch`. Default predicate is `r => r.decision === 'block'` (honors your dashboard rules and allow/block pins). Pass your own to build custom policies.

Since **0.4.0** a test, sandbox or sample answer (`test`, `sandbox` or `sample` is `true`) makes `shouldBlock()` return `true` whatever the predicate: the fixed test tokens are public, so a visitor whose real visit would be blocked could type `test_clean` into your form field. In your own test runs, create the client with `new Sentinel({ allowTestResults: true })`. `Sentinel.isFixtureAnswer(result)` tells you the same for a result you route yourself.

> `accountId`, `email`, and `lookup()` require **v0.2.1 or later** (`npm install @sentinelsup/sdk@latest`) — the older 0.1.2 silently ignores `accountId`/`email`. `tz`, `phone`, `event` and the other login-protection fields, and `setupStatus()`, require **v0.5.0 or later**: older versions leave them out of the request.

## Testing

Deterministic test tokens exercise every decision path from a terminal — authenticated and rate-limited like real calls, but never billed, stored, or webhooked (responses carry `"test": true`):

```js
await sentinel.evaluate({ token: 'test_vpn' });   // → engine decision: 'review' (your rules/pins may override)
await sentinel.evaluate({ token: 'test_clean' }); // → decision: 'allow' path
// also: test_proxy, test_datacenter, test_tor
```

- **No account yet?** The public sandbox key `sk_test_sandbox` answers the same `test_*` tokens with the same shapes — no signup, nothing stored.
- **Login protection, email and phone:** test keys, test tokens and the sandbox never reach those providers. `account_takeover`, `email` and `phone` answer `checked: false, why: 'test'`, and `account_event` answers `recorded: false, why: 'test'`, so you can test the shape without using the day's email-and-phone checks.
- **CI / staging with real traffic:** every account also has a personal `sk_test_…` key (Settings → API keys) that runs the live detection — device intelligence, your rules and exception pins (login protection, email and phone intelligence and the account network do not run for it, and it adds nothing to `times_seen` or `linked_accounts`, which its answers leave out). Its events are marked test, kept out of your stats and never fire webhooks; its checks count toward the monthly allowance (the fixed `test_*` tokens and `sk_test_sandbox` do not). It is exempt from the account's IP allowlist.

## Rate limits

Visitor checks (`evaluate()`) are counted per calendar month in UTC, with an hourly cap: **Free — 10,000 a month, up to 1,000 an hour, no credit card**; paid plans from €29 a month ([pricing](https://maskbreak.com/pricing)). IP lookups (`lookup()`) have their own monthly allowance, 10× the plan's checks (100,000 on Free). A used-up month answers `429` with `code: "monthly_quota_exceeded"` and `Retry-After` until the 1st; there are no overage charges. The quick start lets the action through on that answer and logs it, in enforce mode too, so running out never takes your form offline.

On `503` with `.body.code === 'storage_unavailable'`, the key could not be checked at that moment (not an invalid key; `401` is): retry later and apply your outage policy meanwhile.

On `429`, the thrown `SentinelError` has `.status === 429`. This SDK exposes status and body, not HTTP response headers. If your integration needs `Retry-After` or `X-RateLimit-*`, use raw HTTP and read those headers from the response. Use bounded backoff and an endpoint-specific fallback; an unavailable check is not an allow verdict. Approved public-interest accounts have no hourly or monthly cap and are exempt from the per-address request ceiling; `/v1/usage` and invalid-key protection keep their own limits.

`evaluate()` requires a non-empty token, except for the account events `password_change`, `verification`, `logout` and `account_change` (since 0.5.0). Raw HTTP accepts a missing or empty token for any check, as a degraded evaluation: use the [HTTP reference](https://maskbreak.com/api#evaluate) for that path, as the quick start's watch mode does. Missing network evidence does not prove a visitor is safe.

## Development checks

```bash
npm ci --ignore-scripts
npm test
npm pack --dry-run --ignore-scripts
npm audit
```

Tests use local fixtures, not production keys. CI checks Node.js 18, 22 and 24. These commands do not publish a package.

## TypeScript

Full types ship with the package. Importing `Sentinel` gives you the class plus `EvaluateResult`, `DeviceIntel`, `EvaluateDetails`, and `SentinelError` types, and since 0.5.0 `AccountTakeover`, `AccountEvent`, `PhoneIntelligence`, `TimezoneSignal`, `EmailSignals` and `SetupStatus`. `EvaluateInput` needs `token`; `AccountEventInput` is the token-less shape for the four account events.

```ts
import Sentinel, { EvaluateResult, SetupStatus } from '@sentinelsup/sdk';
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
