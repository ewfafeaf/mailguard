// Vercel Serverless Function – Stripe Checkout Session
// Stripe Secret Key je bezpečne na strane servera, nikdy sa nedostane do prehliadača.
// Odporúčanie: presunúť sk_test_... do Vercel Environment Variable STRIPE_SECRET_KEY

const stripe = require('stripe')(
  process.env.STRIPE_SECRET_KEY || 'sk_test_51TEErOC4tMEUwEDrAoq6Jg80vhg91FIAVvdsVMaF56muICV7YgXm7DbS33AwkrjHk1uLzGFtuD9iSJigqmCiEVOy00C2WuWQrr'
);

module.exports = async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', 'https://mailguard-eight.vercel.app');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { userId, email } = req.body || {};

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [
        {
          price: 'price_1TEF8NC4tMEUwEDrcQoSChC5',
          quantity: 1,
        },
      ],
      customer_email: email || undefined,
      client_reference_id: userId || undefined,
      success_url: 'https://mailguard-eight.vercel.app/dashboard.html?payment=success&session_id={CHECKOUT_SESSION_ID}',
      cancel_url:  'https://mailguard-eight.vercel.app/dashboard.html?payment=cancelled',
    });

    return res.status(200).json({ url: session.url });
  } catch (err) {
    console.error('Stripe error:', err.message);
    return res.status(500).json({ error: err.message });
  }
};
