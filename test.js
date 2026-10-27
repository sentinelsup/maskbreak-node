/**
 * Minimal sanity tests. Run: `node --test test.js`
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const Sentinel = require('./index.js');

const KEY_ENV = ['MASKBREAK_API_KEY', 'SENTINEL_KEY', 'SENTINEL_API_KEY'];

// Run fn with exactly the given key env vars set; restore the real env after.
function withKeyEnv(vars, fn) {
    const saved = {};
    for (const name of KEY_ENV) { saved[name] = process.env[name]; delete process.env[name]; }
    Object.assign(process.env, vars);
    try { return fn(); } finally {
        for (const name of KEY_ENV) {
            if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
        }
    }
}

test('constructor throws without apiKey', () => {
    withKeyEnv({}, () => {
        assert.throws(() => new Sentinel({}), /apiKey is required/);
        assert.throws(() => new Sentinel(), /set MASKBREAK_API_KEY/);
    });
});

test('constructor reads MASKBREAK_API_KEY from the environment', () => {
    withKeyEnv({ MASKBREAK_API_KEY: 'sk_live_new' }, () => {
        assert.equal(new Sentinel().apiKey, 'sk_live_new');
        assert.equal(new Sentinel({ apiKey: undefined }).apiKey, 'sk_live_new');
    });
});

test('constructor still reads the older SENTINEL_KEY and SENTINEL_API_KEY names', () => {
    withKeyEnv({ SENTINEL_KEY: 'sk_live_old' }, () => {
        assert.equal(new Sentinel().apiKey, 'sk_live_old');
    });
    withKeyEnv({ SENTINEL_API_KEY: 'sk_live_legacy' }, () => {
        assert.equal(new Sentinel().apiKey, 'sk_live_legacy');
    });
});

test('MASKBREAK_API_KEY wins over the older names; an explicit apiKey wins over all', () => {
    withKeyEnv({ MASKBREAK_API_KEY: 'sk_live_new', SENTINEL_KEY: 'sk_live_old', SENTINEL_API_KEY: 'sk_live_legacy' }, () => {
        assert.equal(new Sentinel().apiKey, 'sk_live_new');
        assert.equal(new Sentinel({ apiKey: 'sk_live_explicit' }).apiKey, 'sk_live_explicit');
    });
    withKeyEnv({ MASKBREAK_API_KEY: '', SENTINEL_KEY: 'sk_live_old' }, () => {
        assert.equal(new Sentinel().apiKey, 'sk_live_old');
    });
});

test('constructor accepts apiKey', () => {
    const s = new Sentinel({ apiKey: 'sk_live_abc' });
    assert.equal(s.apiKey, 'sk_live_abc');
    assert.equal(s.endpoint, 'https://maskbreak.com');
});

test('constructor trims trailing slash from endpoint', () => {
    const s = new Sentinel({ apiKey: 'k', endpoint: 'https://example.com/' });
    assert.equal(s.endpoint, 'https://example.com');
});

test('evaluate throws without token', async () => {
    const s = new Sentinel({ apiKey: 'k' });
    await assert.rejects(() => s.evaluate({}), /token/);
});

test('lookup throws without ip', async () => {
    const s = new Sentinel({ apiKey: 'k' });
    await assert.rejects(() => s.lookup(), /ip/);
});

test('evaluate passes email through; lookup hits GET /v1/lookup/{ip}', async () => {
    const http = require('node:http');
    const seen = [];
    const srv = http.createServer((req, res) => {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
            seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, body });
            res.setHeader('Content-Type', 'application/json');
            res.end(req.url === '/v1/evaluate' ? '{"decision":"allow"}' : '{"verdict":"allow"}');
        });
    });
    await new Promise(resolve => srv.listen(0, resolve));
    try {
        const s = new Sentinel({ apiKey: 'sk_live_x', endpoint: `http://127.0.0.1:${srv.address().port}` });
        await s.evaluate({ token: 'test_clean', email: 'a@mailinator.com' });
        await s.lookup('185.220.101.34');
    } finally {
        srv.close();
    }
    assert.equal(seen.length, 2);
    assert.equal(seen[0].method, 'POST');
    assert.equal(seen[0].url, '/v1/evaluate');
    assert.equal(JSON.parse(seen[0].body).email, 'a@mailinator.com');
    assert.equal(seen[1].method, 'GET');
    assert.equal(seen[1].url, '/v1/lookup/185.220.101.34');
    assert.equal(seen[1].auth, 'Bearer sk_live_x');
});

test('every request names the SDK and its version in User-Agent, beside the key', async () => {
    const original = global.fetch;
    const seen = [];
    global.fetch = async (url, init) => {
        seen.push({ url, headers: init.headers });
        return new Response(JSON.stringify({ decision: 'allow', verdict: 'allow' }), { status: 200 });
    };
    try {
        const s = new Sentinel({ apiKey: 'k' });
        await s.lookup('185.220.101.34');
        await s.evaluate({ token: 'fixture' });
    } finally {
        global.fetch = original;
    }
    // Exactly the shipped version, so a stale or hand-written one fails.
    const expected = `sentinel-node/${require('./package.json').version}`;
    assert.equal(seen.length, 2);
    for (const { url, headers } of seen) {
        assert.equal(headers['User-Agent'], expected, url);
        assert.equal(headers.Authorization, 'Bearer k', url);
    }
    assert.equal(seen[1].headers['Content-Type'], 'application/json');
});

test('exports SentinelError as named + static', () => {
    assert.ok(Sentinel.SentinelError);
    const err = new Sentinel.SentinelError('boom', { status: 429 });
    assert.equal(err.status, 429);
});

test('network failures clear the request timer', async () => {
    const original = { fetch: global.fetch, setTimeout: global.setTimeout, clearTimeout: global.clearTimeout };
    const timer = {};
    let cleared;
    global.fetch = async () => { throw new Error('connection refused'); };
    global.setTimeout = () => timer;
    global.clearTimeout = value => { cleared = value; };
    try {
        const s = new Sentinel({ apiKey: 'k' });
        await assert.rejects(s.lookup('192.0.2.1'), /network error/);
        assert.equal(cleared, timer);
    } finally {
        Object.assign(global, original);
    }
});

test('invalid successful JSON never becomes an evaluation result', async () => {
    const original = global.fetch;
    try {
        const s = new Sentinel({ apiKey: 'k' });
        for (const body of ['<html>Unavailable</html>', 'null', '[]']) {
            global.fetch = async () => new Response(body, { status: 200 });
            await assert.rejects(s.evaluate({ token: 'fixture' }), err => {
                assert.ok(err instanceof Sentinel.SentinelError);
                assert.equal(err.status, 200);
                assert.match(err.message, /invalid JSON response/);
                return true;
            });
        }
    } finally {
        global.fetch = original;
    }
});

test('API failures retain the HTTP status and parsed body', async () => {
    const original = global.fetch;
    global.fetch = async () => new Response('{"error":"Quota reached"}', { status: 429 });
    try {
        await assert.rejects(new Sentinel({ apiKey: 'k' }).lookup('192.0.2.1'), err => {
            assert.equal(err.status, 429);
            assert.deepEqual(err.body, { error: 'Quota reached' });
            return true;
        });
    } finally {
        global.fetch = original;
    }
});

test('evaluate rejects missing or invalid decisions instead of silently allowing', async () => {
    const original = global.fetch;
    try {
        const s = new Sentinel({ apiKey: 'k' });
        for (const body of [{}, { decision: 'unexpected' }, { decision: null }]) {
            global.fetch = async () => new Response(JSON.stringify(body), { status: 200 });
            for (const run of [() => s.evaluate({ token: 'fixture' }), () => s.shouldBlock({ token: 'fixture' })]) {
                await assert.rejects(run, err => {
                    assert.ok(err instanceof Sentinel.SentinelError);
                    assert.match(err.message, /invalid decision/);
                    assert.deepEqual(err.body, body);
                    return true;
                });
            }
            // Lookup deliberately retains its limited object-response contract.
            assert.deepEqual(await s.lookup('192.0.2.1'), body);
        }
        for (const decision of ['allow', 'review', 'block']) {
            const body = { decision, isSuspicious: decision !== 'block', engine_decision: 'block' };
            global.fetch = async () => new Response(JSON.stringify(body), { status: 200 });
            assert.deepEqual(await s.evaluate({ token: 'fixture' }), body);
            assert.equal(await s.shouldBlock({ token: 'fixture' }), decision === 'block');
        }
    } finally {
        global.fetch = original;
    }
});

test('body stalls stay inside the request timeout', async () => {
    const original = global.fetch;
    global.fetch = async (_url, { signal }) => ({
        ok: true,
        status: 200,
        json: () => new Promise((_resolve, reject) => {
            signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), { name: 'AbortError' })), { once: true });
        })
    });
    try {
        await assert.rejects(new Sentinel({ apiKey: 'k', timeoutMs: 20 }).lookup('192.0.2.1'), /timed out after 20ms/);
    } finally {
        global.fetch = original;
    }
});

test('shouldBlock treats a test, sandbox or sample answer as a block unless the client allows test results', async () => {
    const s = new Sentinel({ apiKey: 'k' });
    for (const marker of ['test', 'sandbox', 'sample']) {
        s.evaluate = async () => ({ decision: 'allow', [marker]: true });
        assert.equal(await s.shouldBlock({ token: 'test_clean' }), true, marker + ': a public test token never lets a visitor through');
        assert.equal(await s.shouldBlock({ token: 'test_clean' }, () => false), true, marker + ': whatever the predicate');
    }
    assert.equal(Sentinel.isFixtureAnswer({ decision: 'allow', test: true }), true);
    assert.equal(Sentinel.isFixtureAnswer({ decision: 'allow' }), false);
    assert.equal(Sentinel.isFixtureAnswer(null), false);
    const ownTests = new Sentinel({ apiKey: 'k', allowTestResults: true });
    ownTests.evaluate = async () => ({ decision: 'allow', test: true });
    assert.equal(await ownTests.shouldBlock({ token: 'test_clean' }), false, 'opted in for its own test runs');
});

test('the API key is trimmed, a key with a line break or space inside is refused, and no error ever quotes it', async () => {
    assert.equal(new Sentinel({ apiKey: '  sk_live_abc\n' }).apiKey, 'sk_live_abc');
    withKeyEnv({ MASKBREAK_API_KEY: 'sk_live_fromfile\r\n' }, () => assert.equal(new Sentinel().apiKey, 'sk_live_fromfile'));
    for (const bad of ['sk_live_a\nb', 'sk_live_a b', 'sk_live_a\u0000b']) {
        assert.throws(() => new Sentinel({ apiKey: bad }), err => err instanceof Sentinel.SentinelError && !err.message.includes('sk_live_a'), JSON.stringify(bad));
    }
    const s = new Sentinel({ apiKey: 'sk_live_secret_value_123' });
    const realFetch = global.fetch;
    global.fetch = async () => { throw new TypeError('Headers.append: "Bearer sk_live_secret_value_123" is an invalid header value.'); };
    try {
        await assert.rejects(s.lookup('8.8.8.8'), err => !err.message.includes('sk_live_secret_value_123') && /\[api key\]/.test(err.message));
    } finally { global.fetch = realFetch; }
});

test('shouldBlock respects final decisions, including allow pins and review', async () => {
    const s = new Sentinel({ apiKey: 'k' });
    for (const decision of ['allow', 'review', 'block']) {
        s.evaluate = async () => ({ decision, isSuspicious: decision !== 'block' });
        assert.equal(await s.shouldBlock({ token: 'fixture' }), decision === 'block');
    }
    s.evaluate = async () => ({ decision: 'review' });
    assert.equal(await s.shouldBlock({ token: 'fixture' }, result => result.decision === 'review'), true);
});

function checkoutExample(result) {
    const vm = require('node:vm');
    const fs = require('node:fs');
    const seen = { payments: [] };
    const express = () => ({
        use() {}, listen() {},
        post(_path, handler) { seen.handler = handler; }
    });
    express.json = () => () => {};
    vm.runInNewContext(fs.readFileSync(`${__dirname}/examples/stripe-checkout.js`, 'utf8'), {
        require(name) {
            if (name === 'express') return express;
            if (name === 'stripe') return () => ({ paymentIntents: { create: async price => {
                seen.payments.push(JSON.parse(JSON.stringify(price)));
                return { client_secret: 'local-fixture' };
            } } });
            if (name === '@sentinelsup/sdk') return class {
                async evaluate(input) {
                    seen.input = JSON.parse(JSON.stringify(input));
                    if (result instanceof Error) throw result;
                    return result;
                }
            };
            throw new Error(`Unexpected dependency: ${name}`);
        },
        process: { env: {} }, console: { log() {}, error() {} }
    });
    return seen;
}

test('checkout example honors final decisions and never pays on unavailable/test data', async () => {
    const cases = [
        [{ decision: 'allow', details: { proxied: true } }, 200],
        [{ decision: 'block', details: {} }, 403],
        [{ decision: 'review', details: {} }, 503],
        [{ decision: 'allow', test: true }, 503],
        [{ decision: 'allow', sandbox: true }, 503],
        [{ decision: 'allow', sample: true }, 503],
        [{ decision: 'allow', degraded: true }, 503],
        [{}, 503],
        [new Error('unavailable'), 503]
    ];
    for (const [result, expectedStatus] of cases) {
        const seen = checkoutExample(result);
        let status = 200;
        const res = { status(code) { status = code; return this; }, json() {} };
        // The body Sentinel.collect() produces in the browser: { token, fingerprintEventId }.
        await seen.handler({ body: { productId: 'demo', amount: 1, currency: 'eur', token: 'fixture', fingerprintEventId: 'event' } }, res);
        assert.equal(status, expectedStatus);
        assert.deepEqual(seen.input, { token: 'fixture', fingerprintEventId: 'event' });
        assert.deepEqual(seen.payments, expectedStatus === 200 ? [{ amount: 2000, currency: 'usd' }] : []);
    }
});

test('signup example passes device evidence and does not count missing/shared IPs as devices', async () => {
    const vm = require('node:vm');
    const fs = require('node:fs');
    const inputs = [];
    const context = {
        require: () => class { async evaluate(input) { inputs.push(input); return { decision: 'allow', details: { ip: '192.0.2.1' } }; } },
        process: { env: {} }, console: { log() {}, error() {} }
    };
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(`${__dirname}/examples/signup-guard.js`, 'utf8'), context);
    await assert.rejects(context.handleSignup({ email: 'fixture@example.com', token: 'fixture', fingerprintEventId: 'event' }), /Device check unavailable/);
    assert.equal(inputs.at(-1).token, 'fixture');
    assert.equal(inputs.at(-1).fingerprintEventId, 'event');
    assert.equal(vm.runInContext('signupsByVisitor.size', context), 0);
});

// ── 0.5.0: the fields login protection, email and phone intelligence and the
// time zone read; account events without a token; the missing-browser-part
// warning; setupStatus(). ────────────────────────────────────────────────────

// Record what evaluate() would send, answering with `answer`.
async function sent(input, opts = {}, answer = { decision: 'allow' }) {
    const original = global.fetch;
    const calls = [];
    global.fetch = async (url, init) => {
        calls.push({ url, init, body: init.body === undefined ? undefined : JSON.parse(init.body) });
        return new Response(JSON.stringify(answer), { status: 200 });
    };
    try {
        const s = new Sentinel({ apiKey: 'sk_live_fields', warnMissingBrowserPart: false, ...opts });
        const result = await s.evaluate(input);
        return { calls, result };
    } finally {
        global.fetch = original;
    }
}

test('evaluate sends each new field under its API name, and only when given', async () => {
    const full = {
        token: 'tok', fingerprintEventId: 'evt', accountId: 'u_42', email: 'a@example.com',
        tz: 'Europe/Tallinn', phone: '+44 20 7946 0958', event: 'login', loginSucceeded: true,
        succeeded: false, sessionId: 'sess_1', userAgent: 'Mozilla/5.0 (X11)', ip: '81.20.33.4',
        reason: 'forgot', verificationType: 'sms', verifiedEvent: 'login'
    };
    const { calls } = await sent(full);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'https://maskbreak.com/v1/evaluate');
    assert.deepEqual(calls[0].body, full, 'every field under the API\'s own JSON name');
    // Nothing given: the token alone; undefined, null and '' stay out.
    const bare = await sent({ token: 'tok', fingerprintEventId: 'evt', tz: undefined, phone: null, event: '', sessionId: '', userAgent: undefined, loginSucceeded: '', succeeded: null });
    assert.deepEqual(bare.calls[0].body, { token: 'tok', fingerprintEventId: 'evt' });
    // A false boolean is an answer, so it is sent; a numeric session or account ID too.
    const failed = await sent({ token: 'tok', fingerprintEventId: 'evt', event: 'login', accountId: 0, loginSucceeded: false, sessionId: 7 });
    assert.deepEqual(failed.calls[0].body, { token: 'tok', fingerprintEventId: 'evt', accountId: 0, event: 'login', loginSucceeded: false, sessionId: 7 });
});

test('the fixed-list fields are read like the API reads them, and sent in its spelling', async () => {
    const { calls } = await sent({ token: 'tok', fingerprintEventId: 'evt', event: ' Password_Change ', reason: 'FORGOT', verificationType: 'Security_Key', verifiedEvent: 'SignUp' });
    assert.deepEqual(calls[0].body, { token: 'tok', fingerprintEventId: 'evt', event: 'password_change', reason: 'forgot', verificationType: 'security_key', verifiedEvent: 'signup' });
});

test('a value the API would ignore or misread is refused before anything is sent', async () => {
    const original = global.fetch;
    let calls = 0;
    global.fetch = async () => { calls++; return new Response('{"decision":"allow"}', { status: 200 }); };
    try {
        const s = new Sentinel({ apiKey: 'sk_live_refuse', warnMissingBrowserPart: false });
        const cases = [
            [{ event: 'signin' }, /event must be one of login, signup, password_change, verification, logout, account_change; the API ignores any other value/],
            [{ event: 42 }, /event must be one of/],
            [{ event: 'login', reason: 'expired' }, /reason must be one of user, forgot, forced; the API reads any other value as user/],
            [{ event: 'verification', verificationType: 'totp' }, /verificationType must be one of email, sms, phone_call, app, push, security_key, captcha/],
            [{ event: 'verification', verifiedEvent: 'checkout' }, /verifiedEvent must be one of login, signup, password_change, account_change/],
            [{ event: 'login', loginSucceeded: 'true' }, /loginSucceeded must be true or false/],
            [{ event: 'password_change', succeeded: 1 }, /succeeded must be true or false/],
            [{ tz: 3 }, /tz must be a string/],
            [{ phone: 4420794609 }, /phone must be a string/],
            [{ event: 'login', userAgent: ['Mozilla'] }, /userAgent must be a string/],
            [{ event: 'login', ip: { v4: '81.20.33.4' } }, /ip must be a string/],
            [{ event: 'login', sessionId: 'x'.repeat(257) }, /sessionId must be a string or a number of at most 256 characters/],
            [{ event: 'login', sessionId: { id: 1 } }, /sessionId must be/],
            [{ event: 'login', sessionId: Infinity }, /sessionId must be/]
        ];
        for (const [extra, message] of cases) {
            await assert.rejects(s.evaluate({ token: 'tok', fingerprintEventId: 'evt', ...extra }), err => {
                assert.ok(err instanceof Sentinel.SentinelError, JSON.stringify(extra));
                assert.match(err.message, message, JSON.stringify(extra));
                return true;
            });
        }
        // 256 characters is still fine.
        await s.evaluate({ token: 'tok', fingerprintEventId: 'evt', event: 'login', sessionId: 'x'.repeat(256) });
        assert.equal(calls, 1, 'only the valid call reached the API');
    } finally {
        global.fetch = original;
    }
});

test('the four account events go without a token; a login, a signup and a plain check still need one', async () => {
    for (const event of ['password_change', 'verification', 'logout', 'account_change']) {
        const { calls } = await sent({ event, accountId: 'u_42' });
        assert.deepEqual(calls[0].body, { accountId: 'u_42', event }, event + ': sent without token');
        // A token given anyway still goes along.
        assert.deepEqual((await sent({ event, accountId: 'u_42', token: 'tok' })).calls[0].body, { token: 'tok', accountId: 'u_42', event });
        // A token given but not a string is still refused.
        await assert.rejects(sent({ event, accountId: 'u_42', token: 12345 }), /token \(client-side Sentinel token\) must be a string/);
    }
    const original = global.fetch;
    let calls = 0;
    global.fetch = async () => { calls++; return new Response('{"decision":"allow"}', { status: 200 }); };
    try {
        const s = new Sentinel({ apiKey: 'sk_live_tokens', warnMissingBrowserPart: false });
        for (const input of [{ event: 'login', accountId: 'u' }, { event: 'signup', accountId: 'u' }, {}, { accountId: 'u' }, { event: 'login', token: '' }]) {
            await assert.rejects(s.evaluate(input), /token \(client-side Sentinel token\) is required \(only the account events password_change, verification, logout and account_change can be sent without it\)/, JSON.stringify(input));
        }
        await assert.rejects(s.shouldBlock({ event: 'signup' }), /token/);
        assert.equal(calls, 0);
    } finally {
        global.fetch = original;
    }
});

test('the new answer objects come back as the API sends them', async () => {
    const answer = {
        decision: 'review', reasons: ['account_takeover_risk', 'phone_high_risk'], degraded: true,
        account_takeover: { checked: true, score: 91, risk: 'high', signals: ['new_location'] },
        email: { disposable: false, checked: false, why: 'quota' },
        phone: { checked: true, score: 89, risk: 'high', signals: ['invalid'], carrier: null },
        timezone: { reported: 'Europe/Tallinn', country: 'EE', matches_ip: true, checked: true }
    };
    const { result } = await sent({ token: 'tok', fingerprintEventId: 'evt', event: 'login', accountId: 'u' }, {}, answer);
    assert.deepEqual(result, answer);
    const recorded = await sent({ event: 'logout', accountId: 'u' }, {}, { decision: 'allow', degraded: true, account_event: { event: 'logout', recorded: true } });
    assert.deepEqual(recorded.result.account_event, { event: 'logout', recorded: true });
});

// A fresh copy of the module: the warning is once per process, so each case
// starts from a module that has not warned yet.
function freshSentinel() {
    delete require.cache[require.resolve('./index.js')];
    try { return require('./index.js'); } finally { delete require.cache[require.resolve('./index.js')]; }
}

async function warningsFrom(run) {
    const original = { fetch: global.fetch, warn: console.warn };
    const warnings = [];
    global.fetch = async () => new Response('{"decision":"allow"}', { status: 200 });
    console.warn = (...args) => { warnings.push(args.join(' ')); };
    try {
        await run(freshSentinel());
    } finally {
        global.fetch = original.fetch;
        console.warn = original.warn;
    }
    return warnings;
}

test('a check without fingerprintEventId warns once per process, without the key, and the option turns it off', async () => {
    const key = 'sk_live_warning_secret_987';
    const once = await warningsFrom(async Fresh => {
        const s = new Fresh({ apiKey: key });
        await s.evaluate({ token: 'eyJ.live.token', email: 'visitor@example.com', ip: '81.20.33.4' });
        await s.evaluate({ token: 'eyJ.live.token' });
        await new Fresh({ apiKey: key }).evaluate({ token: 'eyJ.live.token', fingerprintEventId: '' });
    });
    assert.equal(once.length, 1, 'one warning, however many checks and clients');
    assert.match(once[0], /sent without fingerprintEventId/);
    assert.match(once[0], /keep the script on the page with your form and forward its sentinel_fp field \(or the fingerprintEventId from Sentinel\.collect\(\)\) as fingerprintEventId/);
    assert.match(once[0], /new Sentinel\(\{ warnMissingBrowserPart: false \}\) turns it off/);
    for (const secret of [key, 'eyJ.live.token', 'visitor@example.com', '81.20.33.4']) assert.ok(!once[0].includes(secret), 'the warning never carries ' + secret);

    const off = await warningsFrom(async Fresh => {
        await new Fresh({ apiKey: key, warnMissingBrowserPart: false }).evaluate({ token: 'eyJ.live.token' });
    });
    assert.deepEqual(off, [], 'warnMissingBrowserPart: false');

    const quiet = await warningsFrom(async Fresh => {
        const s = new Fresh({ apiKey: key });
        await s.evaluate({ token: 'eyJ.live.token', fingerprintEventId: 'evt' });            // the browser part is there
        await s.evaluate({ token: 'test_vpn' });                                             // a fixed test token
        for (const event of ['password_change', 'verification', 'logout', 'account_change']) {
            await s.evaluate({ event, accountId: 'u' });                                     // account events, no page
        }
        await assert.rejects(s.evaluate({ event: 'login' }), /token/);                       // refused before sending
    });
    assert.deepEqual(quiet, []);

    // Off for one client does not use up the warning for another.
    const mixed = await warningsFrom(async Fresh => {
        await new Fresh({ apiKey: key, warnMissingBrowserPart: false }).evaluate({ token: 'eyJ.live.token' });
        await new Fresh({ apiKey: key }).evaluate({ token: 'eyJ.live.token', event: 'login', accountId: 'u' });
    });
    assert.equal(mixed.length, 1);
});

test('a runtime without console still sends the check', async () => {
    const vm = require('node:vm');
    const fs = require('node:fs');
    const mod = { exports: {} };
    const bodies = [];
    vm.runInNewContext(fs.readFileSync(`${__dirname}/index.js`, 'utf8'), {
        module: mod, AbortController, setTimeout, clearTimeout,
        fetch: async (_url, init) => { bodies.push(JSON.parse(init.body)); return { ok: true, status: 200, json: async () => ({ decision: 'allow' }) }; }
    });
    await new mod.exports({ apiKey: 'k' }).evaluate({ token: 'tok' });
    assert.deepEqual(bodies, [{ token: 'tok' }]);
});

test('setupStatus GETs /v1/setup with the key and returns the answer as is', async () => {
    const http = require('node:http');
    const seen = [];
    const answer = {
        status: 'missing_device', complete: false, message: 'A check arrived, but the browser part is missing.',
        next_step: 'Send sentinel_fp as fingerprintEventId.', last_check_at: '2026-10-27T10:00:00.000Z',
        complete_checks: 0, last_complete_at: null, website: { confirmed: false, origin: null },
        script_seen: { origin: 'https://shop.example', at: '2026-10-27T09:59:00.000Z' }, site_id: 'site_0123456789abcdef',
        key_type: 'live', docs: 'https://maskbreak.com/integrate.md', future_field: 1
    };
    const srv = http.createServer((req, res) => {
        let body = '';
        req.on('data', c => { body += c; });
        req.on('end', () => {
            seen.push({ method: req.method, url: req.url, auth: req.headers.authorization, ua: req.headers['user-agent'], type: req.headers['content-type'], body });
            res.setHeader('Content-Type', 'application/json');
            if (req.headers.authorization !== 'Bearer sk_live_setup') { res.statusCode = 401; return res.end('{"error":"Invalid API Key."}'); }
            res.end(JSON.stringify(answer));
        });
    });
    await new Promise(resolve => srv.listen(0, '127.0.0.1', resolve));
    try {
        const endpoint = `http://127.0.0.1:${srv.address().port}`;
        assert.deepEqual(await new Sentinel({ apiKey: 'sk_live_setup', endpoint }).setupStatus(), answer);
        await assert.rejects(new Sentinel({ apiKey: 'sk_live_other', endpoint }).setupStatus(), err => {
            assert.equal(err.status, 401);
            assert.deepEqual(err.body, { error: 'Invalid API Key.' });
            return true;
        });
    } finally {
        srv.close();
    }
    assert.equal(seen[0].method, 'GET');
    assert.equal(seen[0].url, '/v1/setup');
    assert.equal(seen[0].auth, 'Bearer sk_live_setup');
    assert.equal(seen[0].ua, `sentinel-node/${require('./package.json').version}`);
    assert.equal(seen[0].type, undefined, 'a GET sends no body type');
    assert.equal(seen[0].body, '');
});

test('the package, its lockfile and its types agree on 0.5.0', () => {
    const fs = require('node:fs');
    assert.equal(require('./package.json').version, '0.5.0');
    const lock = require('./package-lock.json');
    assert.equal(lock.version, '0.5.0');
    assert.equal(lock.packages[''].version, '0.5.0');
    const types = fs.readFileSync(`${__dirname}/index.d.ts`, 'utf8');
    for (const name of ['setupStatus(): Promise<SetupStatus>', 'warnMissingBrowserPart?: boolean', 'account_takeover?: AccountTakeover',
        'account_event?: AccountEvent', 'phone?: PhoneIntelligence', 'timezone?: TimezoneSignal', 'interface AccountEventInput']) {
        assert.ok(types.includes(name), name);
    }
});
