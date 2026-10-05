/**
 * Block card testing before it hits Stripe.
 *
 *   npm install express stripe @sentinelsup/sdk
 *
 *   MASKBREAK_API_KEY=sk_live_xxx STRIPE_KEY=sk_live_xxx node examples/stripe-checkout.js
 */
const express = require('express');
const Stripe = require('stripe');
const Sentinel = require('@sentinelsup/sdk');

const app = express();
app.use(express.json());

const stripe = Stripe(process.env.STRIPE_KEY);
const sentinel = new Sentinel({ apiKey: process.env.MASKBREAK_API_KEY });
// Demo catalog: prices come from the server, never the request body.
const catalog = new Map([['demo', { amount: 2000, currency: 'usd' }]]);

app.post('/checkout', async (req, res) => {
    // { token, fingerprintEventId } is what Sentinel.collect() returns in the browser.
    const { productId, token, fingerprintEventId } = req.body;
    const price = catalog.get(productId);
    if (!price) return res.status(400).json({ error: 'Unknown product.' });

    // 1. Screen the session BEFORE creating a Stripe payment intent.
    try {
        const result = await sentinel.evaluate({ token, fingerprintEventId });

        // Honor the final decision, including your configured rules and pins.
        if (result.decision === 'block') {
            return res.status(403).json({ error: 'Payment declined.' });
        }
        if (result.test || result.sandbox || result.sample || result.degraded || result.decision !== 'allow') {
            return res.status(503).json({ error: 'Payment requires additional verification.' });
        }
    } catch (err) {
        // This checkout example pauses on unavailable checks; choose and document
        // your own retry/review policy instead of treating failures as approval.
        console.error('[sentinel] evaluate failed', err.message);
        return res.status(503).json({ error: 'Payment verification unavailable. Try again.' });
    }

    // 2. The configured policy allows this request; this is not proof of safety.
    const intent = await stripe.paymentIntents.create(price);
    res.json({ clientSecret: intent.client_secret });
});

app.listen(3000, () => console.log('Stripe + Sentinel demo on :3000'));
