/**
 * Example customer policy: count signups per identified device (not email).
 * A shared device is not itself proof of fraud. Choose your own threshold.
 *
 *   MASKBREAK_API_KEY=sk_live_xxx node examples/signup-guard.js
 */
const Sentinel = require('@sentinelsup/sdk');
const sentinel = new Sentinel({ apiKey: process.env.MASKBREAK_API_KEY });

// Demo-only, in-memory state. Production needs an atomic, persistent counter.
const signupsByVisitor = new Map();

async function handleSignup({ email, token, fingerprintEventId }) {
    const result = await sentinel.evaluate({ token, fingerprintEventId });
    const visitorId = result.device && result.device.visitor_id;

    // Do not merge unrelated users behind a shared or missing IP into one device.
    if (!visitorId) throw new Error('Device check unavailable — retry or use a separate verification step');
    const identity = visitorId;
    const prior = signupsByVisitor.get(identity) || 0;

    if (prior >= 3) {
        throw new Error(`Signup blocked — device has already created ${prior} accounts`);
    }
    if (result.decision === 'block') {
        throw new Error('Signup blocked — high-risk session');
    }

    signupsByVisitor.set(identity, prior + 1);
    console.log(`✓ Accepted signup ${email} (visitor ${identity}, #${prior + 1})`);
}

// Demo
handleSignup({ email: 'test@example.com', token: 'YOUR_TOKEN_HERE', fingerprintEventId: 'YOUR_EVENT_ID_HERE' })
    .catch(err => console.error('✗', err.message));
