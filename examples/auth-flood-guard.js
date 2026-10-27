/**
 * Check a login before the password hash runs (credential stuffing, auth floods).
 *
 *   npm install express @sentinelsup/sdk
 *
 *   MASKBREAK_API_KEY=sk_live_xxx MASKBREAK_MODE=enforce node examples/auth-flood-guard.js
 */
const express = require('express');
const Sentinel = require('@sentinelsup/sdk');

const app = express();
app.use(express.json());

const sentinel = new Sentinel({ apiKey: process.env.MASKBREAK_API_KEY });
// 'watch' (default): log the decision, always continue. 'enforce': only a real allow goes on.
const MODE = process.env.MASKBREAK_MODE || 'watch';

// Demo-only, in-memory state. Production needs an atomic store with a TTL (e.g. Redis).
const attemptsByVisitor = new Map();

app.post('/api/login', async (req, res) => {
    const { email, password, token, fingerprintEventId } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials.' });

    // 1. Check before the expensive password verification (bcrypt/argon2).
    // Scripted logins often send no browser token: in enforce mode that is held,
    // never waved through. A used-up month continues, logged, until the 1st.
    let result = null, monthUsedUp = false;
    try {
        if (token) result = await sentinel.evaluate({ token, fingerprintEventId });
    } catch (err) {
        console.log('[maskbreak] check unavailable:', err.message);
        monthUsedUp = err.status === 429 && err.body?.code === 'monthly_quota_exceeded';
    }
    // Never log the email, password or tokens.
    console.log('[maskbreak]', MODE, result ? result.decision : 'no answer', result ? result.reasons : '');
    // A test or sample answer is never a real visitor's verdict: anyone can send a test token.
    if (MODE === 'enforce' && !monthUsedUp &&
        (!result || result.decision !== 'allow' || Sentinel.isFixtureAnswer(result))) {
        // 409: send the person to your verification step (an email code, a second factor).
        return res.status(result && result.decision === 'block' ? 403 : 409).json({ error: 'Verification required.' });
    }

    // 2. Slow down one browser that keeps trying, whatever address it rotates through.
    const visitorId = result?.device?.visitor_id;
    if (visitorId) {
        const attempts = (attemptsByVisitor.get(visitorId) || 0) + 1;
        attemptsByVisitor.set(visitorId, attempts);
        if (attempts > 10) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }

    // 3. Your existing password check runs here. To link devices to accounts,
    // pass your own user id as accountId (from your database, never the email).
    res.json({ message: 'Authentication proceeding.' });
});

app.listen(3001, () => console.log('Auth flood guard demo listening on :3001'));
