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
