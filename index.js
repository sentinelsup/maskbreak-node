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

class Sentinel {
    /**
     * @param {object} [opts]
     * @param {string} [opts.apiKey] — your Sentinel API key (starts with sk_live_).
     *   Falls back to the MASKBREAK_API_KEY env var, then SENTINEL_KEY, then SENTINEL_API_KEY.
     * @param {string} [opts.endpoint] — override the default API base URL (for testing)
     * @param {number} [opts.timeoutMs=5000] — per-request timeout
     */
    constructor(opts = {}) {
        opts = opts || {};
        const apiKey = (typeof opts.apiKey === 'string' && opts.apiKey) || apiKeyFromEnv();
        if (!apiKey) {
            throw new SentinelError('Sentinel: apiKey is required. Pass it explicitly or set MASKBREAK_API_KEY (the older SENTINEL_KEY still works). Get one free at https://maskbreak.com/signup');
        }
        this.apiKey = apiKey;
        this.endpoint = (opts.endpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
        this.timeoutMs = opts.timeoutMs || 5000;
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
                    ...(init && init.headers)
                },
                signal: controller.signal
            });
        } catch (err) {
            clearTimeout(abortTimer);
            if (err.name === 'AbortError') {
                throw new SentinelError(`Sentinel: request timed out after ${this.timeoutMs}ms`);
            }
            throw new SentinelError(`Sentinel: network error — ${err.message}`);
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
     * @param {object} input
     * @param {string} input.token — Sentinel client-side token from the frontend SDK
     * @param {string} [input.fingerprintEventId] — optional device event id for device signals
     * @param {string} [input.accountId] — optional account/user id for multi-accounting detection
     * @param {string} [input.email] — optional signup email; adds `email.disposable` to the
     *   response (burner domains escalate allow → review). Checked transiently, never stored.
     * @returns {Promise<EvaluateResult>}
     */
    async evaluate({ token, fingerprintEventId, accountId, email } = {}) {
        if (!token || typeof token !== 'string') {
            throw new SentinelError('Sentinel.evaluate: token (client-side Sentinel token) is required');
        }
        const result = await this._request('/v1/evaluate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token, fingerprintEventId, accountId, email })
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
     * Shares the hourly quota with evaluate() (one per account for the live keys;
     * the test key has its own) and has its own monthly allowance.
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
     * Convenience helper: returns true if the session should be blocked.
     * Defaults to the API's own decision === 'block' — this honors your
     * dashboard rules and allow/block pins, and matches the documented
     * routing contract. (Earlier versions gated on isSuspicious, which
     * blocked 'review' traffic and ignored customer allow-pins.)
     * Pass a custom predicate to build your own policy.
     *
     * @param {object} input — same as evaluate()
     * @param {(r: EvaluateResult) => boolean} [predicate]
     * @returns {Promise<boolean>}
     */
    async shouldBlock(input, predicate) {
        const result = await this.evaluate(input);
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
 * @property {object} network — { vpn, proxy, datacenter, anonymous, tor, residential, service }
 * @property {object} [device] — { antidetect, automation, emulator, virtual_machine, incognito, visitor_id, tampering_score, ... } when fingerprintEventId was supplied
 * @property {string[]} reasons — machine-readable reason codes (vpn_detected, proxy_detected, ...)
 * @property {number} evaluated_in_ms
 * @property {{disposable: boolean}} [email] — present when the optional email input was supplied
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
 */
