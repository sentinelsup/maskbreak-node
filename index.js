/**
 * Sentinel Node.js SDK — thin, zero-dependency wrapper around the
 * Sentinel fraud detection API at https://maskbreak.com/v1/evaluate.
 *
 * Usage:
 *   const Sentinel = require('@sentinelsup/sdk');
 *   const sentinel = new Sentinel();   // reads MASKBREAK_API_KEY from the env
 *   let result = null;   // evaluate() throws without a token or when the API fails
 *   try { result = await sentinel.evaluate({ token }); } catch (err) { console.log(err.message); }
 *   if (result && result.decision === 'block') return res.status(403).end();
 */

const DEFAULT_ENDPOINT = 'https://maskbreak.com';

// Sent on every request, as the Python and PHP SDKs send theirs
// (sentinel-python/…, sentinel-php/…), so this SDK's calls are not just Node's
// default "node". The version is read from package.json, which npm always
// ships, rather than written here: a hand-written one drifted in the MCP
// package. A runtime without require (a sandbox, an odd bundler) sends the
// name alone.
const USER_AGENT = (() => {
    try { return `sentinel-node/${require('./package.json').version}`; } catch (_) { return 'sentinel-node'; }
})();

class SentinelError extends Error {
    constructor(message, { status, body } = {}) {
        super(message);
        this.name = 'SentinelError';
        this.status = status;
        this.body = body;
    }
}

// MASKBREAK_API_KEY is the name every doc surface uses. SENTINEL_KEY and
// SENTINEL_API_KEY are older names, still read so existing installs keep
// working; the first non-empty one wins.
const API_KEY_ENV_NAMES = ['MASKBREAK_API_KEY', 'SENTINEL_KEY', 'SENTINEL_API_KEY'];

function apiKeyFromEnv() {
    const env = (typeof process !== 'undefined' && process && process.env) || {};
    for (const name of API_KEY_ENV_NAMES) {
        if (typeof env[name] === 'string' && env[name]) return env[name];
    }
    return '';
}

// evaluate() sends a field only when it is given: undefined, null and ''
// stay out of the request.
const given = value => value !== undefined && value !== null && value !== '';

// The values `event` takes (login protection, since 23 October 2026). The API
// reads the name case-insensitively and ignores any other value without a
// word, so a typo such as "signin" would run the check without login
// protection: evaluate() refuses it instead (0.5.0).
const EVENTS = ['login', 'signup', 'password_change', 'verification', 'logout', 'account_change'];
// Account events a server reports on its own, often with no page in front of
// it: the API records them without the visit's network token. A login and a
// signup are visits and still need the token.
const TOKENLESS_EVENTS = ['password_change', 'verification', 'logout', 'account_change'];
// Fields with a fixed list of values: the list, and what the API does with
// any other value (the reason evaluate() refuses it).
const CHOICES = {
    event: [EVENTS, 'the API ignores any other value, and the check would run without login protection'],
    reason: [['user', 'forgot', 'forced'], 'the API reads any other value as user'],
    verificationType: [['email', 'sms', 'phone_call', 'app', 'push', 'security_key', 'captcha'], 'the API ignores any other value'],
    verifiedEvent: [['login', 'signup', 'password_change', 'account_change'], 'the API ignores any other value']
};
// The API reads only a real boolean here (or the text "true"/"false" from a
// form body); anything else silently becomes "not known".
const BOOLEANS = ['loginSucceeded', 'succeeded'];
// The API reads these only when they are strings.
const STRINGS = ['tz', 'phone', 'userAgent', 'ip'];
// The API drops a longer session ID without a word (the device then stands in
// for the session).
const MAX_SESSION_ID = 256;

// The request body for POST /v1/evaluate, and whether this call is one of the
// account events that may go without the network token. Throws SentinelError
// for a value the API would ignore or misread; nothing is sent then.
function evaluateBody(input) {
    const picked = {};
    for (const [name, [allowed, otherwise]] of Object.entries(CHOICES)) {
        if (!given(input[name])) continue;
        const value = typeof input[name] === 'string' ? input[name].trim().toLowerCase() : null;
        if (!allowed.includes(value)) {
            throw new SentinelError(`Sentinel.evaluate: ${name} must be one of ${allowed.join(', ')}; ${otherwise}.`);
        }
        picked[name] = value;
    }
    const accountEvent = TOKENLESS_EVENTS.includes(picked.event);
    const { token } = input;
    if (!given(token) && !accountEvent) {
        throw new SentinelError('Sentinel.evaluate: token (client-side Sentinel token) is required (only the account events password_change, verification, logout and account_change can be sent without it)');
    }
    if (given(token) && typeof token !== 'string') {
        throw new SentinelError('Sentinel.evaluate: token (client-side Sentinel token) must be a string');
    }
    const body = {};
    if (given(token)) body.token = token;
    for (const name of ['fingerprintEventId', 'accountId', 'email']) {
        if (given(input[name])) body[name] = input[name];
    }
    for (const name of STRINGS) {
        if (!given(input[name])) continue;
        if (typeof input[name] !== 'string') throw new SentinelError(`Sentinel.evaluate: ${name} must be a string.`);
        body[name] = input[name];
    }
    if (picked.event) body.event = picked.event;
    for (const name of BOOLEANS) {
        if (!given(input[name])) continue;
        if (typeof input[name] !== 'boolean') throw new SentinelError(`Sentinel.evaluate: ${name} must be true or false.`);
        body[name] = input[name];
    }
    if (given(input.sessionId)) {
        const id = input.sessionId;
        if (!(typeof id === 'string' || (typeof id === 'number' && Number.isFinite(id))) || String(id).trim().length > MAX_SESSION_ID) {
            throw new SentinelError(`Sentinel.evaluate: sessionId must be a string or a number of at most ${MAX_SESSION_ID} characters; for a longer session value, send a shorter ID for the session (a hash of it, for example).`);
        }
        body.sessionId = id;
    }
    for (const name of ['reason', 'verificationType', 'verifiedEvent']) {
        if (picked[name]) body[name] = picked[name];
    }
    return { body, accountEvent };
}

// The fixed test tokens (test_clean, test_vpn, ...) describe a pretend visitor
// and never carry a browser part; a terminal test needs no warning about it.
const isTestToken = token => typeof token === 'string' && token.startsWith('test_');

// Checks that arrive without the browser part (the dashboard's
// missing_device) are a broken integration that is easy to miss. Said once
// per process, never with the key or anything about the visitor.
const MISSING_BROWSER_PART_WARNING = 'Sentinel: a check was sent without fingerprintEventId, so Maskbreak checks it without the browser part (bots, fake browsers and emulators go unchecked): keep the script on the page with your form and forward its sentinel_fp field (or the fingerprintEventId from Sentinel.collect()) as fingerprintEventId. Shown once per process; new Sentinel({ warnMissingBrowserPart: false }) turns it off.';
let warnedMissingBrowserPart = false;
function warnMissingBrowserPartOnce() {
    if (warnedMissingBrowserPart) return;
    warnedMissingBrowserPart = true;
    try {
        if (typeof console !== 'undefined' && console && typeof console.warn === 'function') console.warn(MISSING_BROWSER_PART_WARNING);
    } catch (_) { /* a warning never fails a check */ }
}

class Sentinel {
    /**
     * @param {object} [opts]
     * @param {string} [opts.apiKey] — your Sentinel API key (starts with sk_live_).
     *   Falls back to the MASKBREAK_API_KEY env var, then SENTINEL_KEY, then SENTINEL_API_KEY.
     * @param {string} [opts.endpoint] — override the default API base URL (for testing)
     * @param {number} [opts.timeoutMs=5000] — per-request timeout
     * @param {boolean} [opts.allowTestResults=false] — only for your own test runs: let shouldBlock()
     *   treat test, sandbox and sample answers as a normal decision
     * @param {boolean} [opts.warnMissingBrowserPart=true] — false turns off the one-time console
     *   warning for a check sent without fingerprintEventId (0.5.0)
     */
    constructor(opts = {}) {
        opts = opts || {};
        // Trimmed (a key read from a file or a secret store often ends in a
        // line break), and never echoed: a key with a space or control
        // character inside made fetch throw an error quoting the whole
        // Authorization header, which ended up in logs (0.4.0).
        const apiKey = ((typeof opts.apiKey === 'string' && opts.apiKey) || apiKeyFromEnv()).trim();
        if (!apiKey) {
            throw new SentinelError('Sentinel: apiKey is required. Pass it explicitly or set MASKBREAK_API_KEY (the older SENTINEL_KEY still works). Get one free at https://maskbreak.com/signup');
        }
        if (/[\s\u0000-\u001f\u007f]/.test(apiKey)) {
            throw new SentinelError('Sentinel: the API key contains a space, a line break or another control character. Copy it again from the dashboard (Settings, API keys).');
        }
        this.apiKey = apiKey;
        this.endpoint = (opts.endpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
        this.timeoutMs = opts.timeoutMs || 5000;
        // Fixture answers (the fixed test_* tokens, the sandbox key, samples)
        // describe a pretend visitor, not this one: shouldBlock() treats them
        // as a block unless the caller's own test run says otherwise (0.4.0).
        this.allowTestResults = opts.allowTestResults === true;
        // A check sent without fingerprintEventId gets one console warning per
        // process (0.5.0); false turns it off.
        this.warnMissingBrowserPart = opts.warnMissingBrowserPart !== false;
    }

    /**
     * True for an answer that is not a verdict on a real visitor: a fixed test
     * token, the public sandbox key or a sample. A visitor can type a test
     * token into your form field, so production code must never treat such an
     * answer as an allow.
     * @param {EvaluateResult} result
     * @returns {boolean}
     */
    static isFixtureAnswer(result) {
        return !!(result && (result.test === true || result.sample === true || result.sandbox === true));
    }

    // An error message with the key taken out, whatever produced it.
    _scrub(message) {
        const text = String(message == null ? '' : message);
        return this.apiKey ? text.split(this.apiKey).join('[api key]') : text;
    }

    /**
     * Shared transport: auth header, timeout, JSON parsing, error mapping.
     * @private
     */
    async _request(path, init) {
        const controller = new AbortController();
        const abortTimer = setTimeout(() => controller.abort(), this.timeoutMs);

        let res;
        try {
            res = await fetch(`${this.endpoint}${path}`, {
                ...init,
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'User-Agent': USER_AGENT,
                    ...(init && init.headers)
                },
                signal: controller.signal
            });
        } catch (err) {
            clearTimeout(abortTimer);
            if (err.name === 'AbortError') {
                throw new SentinelError(`Sentinel: request timed out after ${this.timeoutMs}ms`);
            }
            throw new SentinelError(`Sentinel: network error — ${this._scrub(err && err.message)}`);
        }

        // Body read stays under the abort timer too — otherwise a stalled
        // response body hangs the call far past timeoutMs.
        let json;
        try { json = await res.json(); } catch (err) {
            if (err && err.name === 'AbortError') {
                clearTimeout(abortTimer);
                throw new SentinelError(`Sentinel: request timed out after ${this.timeoutMs}ms`);
            }
            json = null;
        } finally {
            clearTimeout(abortTimer);
        }

        if (!res.ok) {
            throw new SentinelError(
                `Sentinel: API returned ${res.status}${json && json.error ? ` — ${json.error}` : ''}`,
                { status: res.status, body: json }
            );
        }

        if (!json || typeof json !== 'object' || Array.isArray(json)) {
            throw new SentinelError('Sentinel: invalid JSON response from API', { status: res.status, body: json });
        }

        return json;
    }

    /**
     * Evaluate a visitor session for fraud signals.
     *
     * Every field but `token` is optional and sent only when given (not
     * undefined, null or ''). A value the API would ignore or misread (an
     * unknown `event`, a non-boolean `loginSucceeded`, ...) throws a
     * SentinelError before anything is sent.
     *
     * @param {object} input
     * @param {string} [input.token] — Sentinel client-side token from the frontend SDK. Required, except
     *   for the account events password_change, verification, logout and account_change (0.5.0)
     * @param {string} [input.fingerprintEventId] — optional device event id for device signals
     * @param {string|number} [input.accountId] — optional account/user id (from your server-side session, never a form
     *   field): multi-accounting detection and, with a live key, the `account` object (account network).
     *   Login protection needs it with `event`.
     * @param {string} [input.email] — optional signup email; adds `email.disposable` to the
     *   response (burner domains escalate allow → review). With email and phone intelligence on,
     *   also `email.checked`, `score`, `risk` and `signals`. Never stored or logged.
     * @param {string} [input.tz] — the visitor's IANA time zone (`tz` from Sentinel.collect(), or the
     *   form's sentinel_tz field); adds `timezone` when recognised (0.5.0)
     * @param {string} [input.phone] — the visitor's phone number in international format; with email and
     *   phone intelligence on, adds the `phone` object with a score (0.5.0)
     * @param {'login'|'signup'|'password_change'|'verification'|'logout'|'account_change'} [input.event] —
     *   login protection (0.5.0): 'login' adds `account_takeover`, the others `account_event`
     * @param {boolean} [input.loginSucceeded] — with event 'login': whether the credential was right
     * @param {boolean} [input.succeeded] — with event 'password_change' or 'verification': whether it
     *   succeeded (absent = pending)
     * @param {string|number} [input.sessionId] — with an event: your own session ID (at most 256 characters;
     *   only a keyed hash of it leaves Maskbreak)
     * @param {string} [input.userAgent] — with an event: the visitor's User-Agent header as your server received it
     * @param {string} [input.ip] — with an event: the visitor's address as your server saw it (used only when the
     *   network token gave none)
     * @param {'user'|'forgot'|'forced'} [input.reason] — with event 'password_change'
     * @param {'email'|'sms'|'phone_call'|'app'|'push'|'security_key'|'captcha'} [input.verificationType] —
     *   with event 'verification'
     * @param {'login'|'signup'|'password_change'|'account_change'} [input.verifiedEvent] — with event
     *   'verification': which action it verified
     * @returns {Promise<EvaluateResult>}
     */
    async evaluate(input = {}) {
        input = input || {};
        const { body, accountEvent } = evaluateBody(input);
        // Account events may come from server code with no page in front of
        // them; anything else that lacks the browser part is a broken
        // integration, and says so once.
        if (this.warnMissingBrowserPart && !accountEvent && !given(input.fingerprintEventId) && !isTestToken(input.token)) {
            warnMissingBrowserPartOnce();
        }
        const result = await this._request('/v1/evaluate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        if (!['allow', 'review', 'block'].includes(result.decision)) {
            throw new SentinelError('Sentinel.evaluate: invalid decision in API response', { body: result });
        }
        return result;
    }

    /**
     * Look up an arbitrary public IP address — no browser token needed.
     * Wraps GET /v1/lookup/{ip}: allow/review/block verdict, 0–100 risk
     * score and limited public-feed evidence (cloud ranges and Tor).
     * VPN/proxy evidence needs evaluate() with a browser token; an unknown
     * IP or false signal is not proof that the visitor is safe.
     * Has its own monthly allowance, 10x the plan's checks (no plan has an
     * hourly limit since 2026-10-29).
     *
     * @param {string} ip — public IPv4 or IPv6 address, e.g. '185.220.101.34'
     * @returns {Promise<LookupResponse>}
     */
    async lookup(ip) {
        if (!ip || typeof ip !== 'string') {
            throw new SentinelError('Sentinel.lookup: ip (public IPv4 or IPv6 address) is required');
        }
        return this._request(`/v1/lookup/${encodeURIComponent(ip.trim())}`, { method: 'GET' });
    }

    /**
     * Whether your integration's checks arrive complete, and what to fix next
     * (GET /v1/setup, since 0.5.0). Submit your form once, then call it: it
     * says whether that check arrived with both parts and, when not, what to
     * change. Works with the live key and the test key. The answer is returned
     * as the API sends it.
     *
     * @returns {Promise<SetupStatus>}
     */
    async setupStatus() {
        return this._request('/v1/setup', { method: 'GET' });
    }

    /**
     * Convenience helper: returns true if the session should be blocked.
     * Defaults to the API's own decision === 'block' — this honors your
     * dashboard rules and allow/block pins, and matches the documented
     * routing contract. (Earlier versions gated on isSuspicious, which
     * blocked 'review' traffic and ignored customer allow-pins.)
     * Pass a custom predicate to build your own policy.
     *
     * A test, sandbox or sample answer always returns true (since 0.4.0):
     * the fixed test tokens are public, and a visitor whose real visit would
     * be blocked could type one into your form field. Construct the client
     * with { allowTestResults: true } in your own test runs.
     *
     * @param {object} input — same as evaluate()
     * @param {(r: EvaluateResult) => boolean} [predicate]
     * @returns {Promise<boolean>}
     */
    async shouldBlock(input, predicate) {
        const result = await this.evaluate(input);
        if (!this.allowTestResults && Sentinel.isFixtureAnswer(result)) return true;
        return predicate ? !!predicate(result) : result.decision === 'block';
    }
}

Sentinel.SentinelError = SentinelError;
module.exports = Sentinel;
module.exports.default = Sentinel;
module.exports.Sentinel = Sentinel;
module.exports.SentinelError = SentinelError;

/**
 * @typedef {object} EvaluateResult
 * @property {'allow'|'review'|'block'} decision — route on this
 * @property {number} risk_score — 0–100 weighted risk score
 * @property {boolean} isSuspicious — legacy flag: true when VPN, proxy, Tor, antidetect, automation, emulator or virtual machine fired (not a datacenter or anonymous network alone); route on `decision`
 * @property {string|null} ip
 * @property {string|null} country — 2-letter country code
 * @property {object} network — { vpn, proxy, privacy_relay, datacenter, anonymous, tor, residential, service }; privacy_relay (since 2026-10-10) is true for Apple's iCloud Private Relay, which is review on its own
 * @property {object} [device] — { antidetect, automation, emulator, virtual_machine, incognito, visitor_id, tampering_score, ... } when fingerprintEventId was supplied
 * @property {string[]} reasons — machine-readable reason codes (vpn_detected, proxy_detected, privacy_relay, ...)
 * @property {number} evaluated_in_ms
 * @property {EmailSignals} [email] — present when the optional email input was supplied
 * @property {object} [account] — the account network (since 2026-10-18): present when accountId was sent with a live key; { seen_before, first_seen, new_device, devices_24h, devices_90d, device_accounts_24h, ip_accounts_24h, connected_accounts, connected_by_device }
 * @property {AccountTakeover} [account_takeover] — login protection: present when event was 'login' (0.5.0)
 * @property {AccountEvent} [account_event] — login protection: present when event was another account event (0.5.0)
 * @property {PhoneIntelligence} [phone] — email and phone intelligence: present when phone was sent (0.5.0)
 * @property {TimezoneSignal} [timezone] — present when a recognised tz was sent and the address's country is known (0.5.0)
 * @property {boolean} [degraded] — true when the network part was unavailable (no or an unreadable token)
 * @property {boolean} [sandbox] — true when the public sk_test_sandbox key answered
 * @property {boolean} [sample] — true on GET /v1/evaluate/sample answers
 * @property {'allow'|'review'|'block'} [engine_decision] — present when your own rules/exceptions changed `decision`
 * @property {'rules'|'exception'} [decision_source] — who authored the final decision when it was not the engine
 * @property {string[]} [rule_matched] — signals that triggered a custom rule
 * @property {string[]} [exception_matched] — matched per-IP/visitor pins
 * @property {boolean} [test] — present on test-token / test-key responses (test-key checks count toward the monthly allowance; the fixed test_* tokens never count)
 * @property {'ok'|'unavailable'|'not_sent'} [device_evidence] — whether the device layer was usable; hold sensitive actions when not 'ok'
 * @property {{network_age_s?: number, device_age_s?: number, device_replayed?: boolean}} [evidence] — how fresh the evidence was (known fields only)
 * @property {EvaluateDetails} details — legacy network signals (backwards compatibility)
 * @property {DeviceIntel|null} [deviceIntel] — legacy device signals (backwards compatibility)
 */

/**
 * @typedef {object} EmailSignals
 * @property {boolean} disposable — the address uses a disposable/burner domain
 * @property {boolean} [checked] — email and phone intelligence: true when the address was scored
 * @property {number|null} [score] — 0–100, higher is riskier (when checked); null when no score came back
 * @property {'low'|'medium'|'high'|null} [risk] — low below 50, medium 50–79, high 80 and up
 * @property {string[]} [signals] — what the score noticed, by name (the list can grow)
 * @property {number|null} [online_accounts]
 * @property {number|null} [breaches]
 * @property {boolean|null} [deliverable]
 * @property {boolean|null} [free_provider]
 * @property {string|null} [domain_created] — a date, YYYY-MM-DD
 * @property {'not_enabled'|'not_available'|'quota'|'invalid'|'test'|'busy'|'unavailable'} [why] — when checked is false
 */

/**
 * @typedef {object} PhoneIntelligence
 * @property {boolean} checked — true when the number was scored
 * @property {number|null} [score] — 0–100, higher is riskier (when checked); null when no score came back
 * @property {'low'|'medium'|'high'|null} [risk] — low below 50, medium 50–79, high 80 and up
 * @property {string[]} [signals] — what the score noticed, by name (the list can grow)
 * @property {boolean|null} [valid]
 * @property {string|null} [line_type] — mobile, fixed_line, voip, ...
 * @property {string|null} [carrier]
 * @property {string|null} [country] — 2-letter country code of the number
 * @property {boolean|null} [disposable]
 * @property {number|null} [online_accounts]
 * @property {'not_enabled'|'not_available'|'quota'|'invalid'|'test'|'busy'|'unavailable'} [why] — when checked is false
 */

/**
 * @typedef {object} AccountTakeover
 * @property {boolean} checked — true when the login was scored
 * @property {number} [score] — 0–100, higher is riskier; 80 and up adds account_takeover_risk and raises allow to review, never to block
 * @property {'low'|'medium'|'high'} [risk]
 * @property {string[]} [signals] — what the score noticed, by name (the list can grow)
 * @property {'not_enabled'|'not_available'|'no_account_id'|'test'|'busy'|'unavailable'} [why] — when checked is false
 */

/**
 * @typedef {object} AccountEvent
 * @property {'signup'|'password_change'|'verification'|'logout'|'account_change'} event
 * @property {boolean} recorded — true when login protection took the event (no score comes back for these)
 * @property {'not_enabled'|'not_available'|'no_account_id'|'test'|'busy'|'unavailable'} [why] — when recorded is false
 */

/**
 * @typedef {object} TimezoneSignal
 * @property {string} reported — the IANA zone that was sent
 * @property {string} country — the country that zone belongs to
 * @property {boolean} matches_ip — the zone's country equals the address's country
 * @property {boolean} checked — false on a VPN, proxy, Tor or datacenter exit, where a mismatch is expected
 */

/**
 * @typedef {object} SetupStatus
 * @property {'waiting'|'complete'|'missing_network'|'network_unavailable'|'missing_device'|'device_unavailable'|'test_mode'|'test_complete'|'ip_restricted'|'rate_limited'|'request_failed'} status — what the latest check showed
 * @property {boolean} complete — at least one complete live-key check ever
 * @property {string} message — what the latest check showed, in words
 * @property {string|null} next_step — what to do next, or null
 * @property {string|null} last_check_at — ISO time of the latest check
 * @property {number} complete_checks
 * @property {string|null} last_complete_at — ISO time of the latest complete check
 * @property {{confirmed: boolean, origin: string|null}} website
 * @property {{origin: string, at: string}|null} script_seen — where and when the page script last reported in
 * @property {string|null} site_id
 * @property {'live'|'test'} key_type — which key made this call
 * @property {string} docs — a link to the setup guide
 */

/**
 * @typedef {object} LookupResponse
 * @property {string} ip
 * @property {boolean} known — whether our reputation feeds hold data for this IP (false ≠ clean)
 * @property {'allow'|'review'|'block'} verdict
 * @property {number} risk_score — 0–100
 * @property {{vpn: boolean, proxied: boolean, tor: boolean, dch: boolean, anon: boolean}|null} signals — null when known is false
 * @property {{asn: number|null, org: string|null, country: string|null, city: string|null, cloud?: string}|null} network
 * @property {number} latency_ms
 * @property {'allow'|'review'|'block'} [engine_verdict] — present when an exception pin changed `verdict`
 * @property {'exception'} [verdict_source]
 * @property {string[]} [exception_matched]
 * @property {boolean} [test] — present when the call used the per-account sk_test_ key
 */

/**
 * @typedef {object} EvaluateDetails
 * @property {string} ip
 * @property {string} cc — 2-letter country code
 * @property {boolean} vpn
 * @property {boolean} proxied
 * @property {boolean} dch — datacenter flag
 * @property {boolean} anon
 * @property {boolean} [crawler]
 * @property {string} [service]
 * @property {boolean} [tor] — present only when the Tor exit list matched; read network.tor
 */

/**
 * @typedef {object} DeviceIntel
 * @property {string|null} visitorId
 * @property {boolean} browserTampering
 * @property {boolean} botDetected
 * @property {boolean} vpnDetected
 * @property {boolean} proxyDetected
 * @property {boolean} torDetected
 * @property {boolean} ipBlocklisted
 * @property {boolean} incognito
 * @property {boolean} virtualMachine
 * @property {boolean} emulator
 * @property {number} [tamperingScore]
 * @property {boolean} [privacySettings]
 * @property {boolean} [highActivity]
 */
