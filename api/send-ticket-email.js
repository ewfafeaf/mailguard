const RESEND_API_KEY = process.env.RESEND_API_KEY;

const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

function getClientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress
    || 'unknown';
}

// Same checkRateLimit pattern as ssl-check.js/shodan-check.js, keyed by IP
// instead of userId since this endpoint has no auth.
async function checkRateLimit(ip) {
  const windowStart = new Date(Date.now() - 3600000).toISOString();
  const limit = 5;
  try {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(ip)}&endpoint=eq.ticket&select=count,window_start`,
      { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
    );
    const rows = await res.json();
    if (!rows || rows.length === 0) {
      await fetch(`${SUPABASE_URL}/rest/v1/rate_limits`, {
        method: 'POST',
        headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify({ user_id: ip, endpoint: 'ticket', count: 1, window_start: new Date().toISOString() })
      });
      return { allowed: true, remaining: limit - 1 };
    }
    const row = rows[0];
    if (new Date(row.window_start) < new Date(windowStart)) {
      await fetch(`${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(ip)}&endpoint=eq.ticket`, {
        method: 'PATCH',
        headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: 1, window_start: new Date().toISOString() })
      });
      return { allowed: true, remaining: limit - 1 };
    }
    if (row.count >= limit) {
      return { allowed: false, remaining: 0 };
    }
    await fetch(`${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(ip)}&endpoint=eq.ticket`, {
      method: 'PATCH',
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ count: row.count + 1 })
    });
    return { allowed: true, remaining: limit - row.count - 1 };
  } catch(e) { return { allowed: true, remaining: limit }; }
}

export default async function handler(req, res) {
  const ALLOWED = ['https://nondox.com', 'https://www.nondox.com'];
  const origin = req.headers['origin'];
  res.setHeader('Access-Control-Allow-Origin', ALLOWED.includes(origin) ? origin : 'https://nondox.com');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const _origin = req.headers['origin'];
  if (_origin && !['https://nondox.com', 'https://www.nondox.com'].includes(_origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const ip = getClientIp(req);
    const rl = await checkRateLimit(ip);
    if (!rl.allowed) {
      return res.status(429).json({ ok: false, error: 'Príliš veľa požiadaviek. Počkaj hodinu a skús znova.', retryAfter: 3600 });
    }

    const { type, priority, description, userEmail, name, school, phone, message } = req.body || {};

    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${RESEND_API_KEY}`
      },
      body: JSON.stringify({
        from: 'NonDox Support <noreply@nondox.com>',
        to: 'nondox.support@gmail.com',
        subject: `🏫 Nová škola má záujem — ${type}`,
        html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
  <div style="background:linear-gradient(135deg,#1a1d27,#0f1117);padding:24px 32px;border-radius:12px 12px 0 0">
    <div style="color:#4f8ef7;font-size:22px;font-weight:800">NonDox</div>
    <div style="color:#7a82a0;font-size:13px;margin-top:4px">Nová škola má záujem o spoluprácu</div>
  </div>
  <div style="background:white;padding:28px 32px;border:1px solid #e5e7eb;border-top:none">
    <table style="width:100%;border-collapse:collapse">
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280;width:140px">👤 Meno</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${name || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">🏫 Škola</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${school || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">📧 Email</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${userEmail || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">📞 Telefón</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${phone || '—'}</td>
      </tr>
      <tr>
        <td style="padding:12px 0;font-size:13px;color:#6b7280;vertical-align:top">💬 Správa</td>
        <td style="padding:12px 0;font-size:14px;color:#374151">${message || '—'}</td>
      </tr>
    </table>
  </div>
  <div style="background:#f9fafb;padding:16px 32px;border-radius:0 0 12px 12px;border:1px solid #e5e7eb;border-top:none;text-align:center">
    <div style="font-size:12px;color:#9ca3af">NonDox — Kybernetická ochrana škôl | nondox.com</div>
  </div>
</div>`
      }),
      signal: AbortSignal.timeout(10000)
    });

    const data = await response.json();
    return res.status(response.ok ? 200 : 400).json(data);
  } catch (err) {
    console.error('[send-ticket-email] error:', err.message);
    return res.status(500).json({ ok: false, error: 'Nepodarilo sa odoslať správu. Skús znova.' });
  }
}
