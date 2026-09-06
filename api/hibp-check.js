const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const HIBP_KEY = process.env.HIBP_KEY;

async function verifyToken(token) {
  if (!token) return null;
  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${token}` }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.id || null;
  } catch(e) { return null; }
}

// Same checkRateLimit pattern as ssl-check.js/shodan-check.js.
async function checkRateLimit(userId) {
  const windowStart = new Date(Date.now() - 3600000).toISOString();
  const limit = userId === 'anonymous' ? 5 : 20;
  try {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(userId)}&endpoint=eq.scan&select=count,window_start`,
      { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
    );
    const rows = await res.json();
    if (!rows || rows.length === 0) {
      await fetch(`${SUPABASE_URL}/rest/v1/rate_limits`, {
        method: 'POST',
        headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates' },
        body: JSON.stringify({ user_id: userId, endpoint: 'scan', count: 1, window_start: new Date().toISOString() })
      });
      return { allowed: true, remaining: limit - 1 };
    }
    const row = rows[0];
    if (new Date(row.window_start) < new Date(windowStart)) {
      await fetch(`${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(userId)}&endpoint=eq.scan`, {
        method: 'PATCH',
        headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: 1, window_start: new Date().toISOString() })
      });
      return { allowed: true, remaining: limit - 1 };
    }
    if (row.count >= limit) {
      return { allowed: false, remaining: 0 };
    }
    await fetch(`${SUPABASE_URL}/rest/v1/rate_limits?user_id=eq.${encodeURIComponent(userId)}&endpoint=eq.scan`, {
      method: 'PATCH',
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ count: row.count + 1 })
    });
    return { allowed: true, remaining: limit - row.count - 1 };
  } catch(e) { return { allowed: true, remaining: limit }; }
}

module.exports = async function handler(req, res) {
  const ALLOWED = ['https://nondox.com', 'https://www.nondox.com'];
  const origin = req.headers['origin'];
  res.setHeader('Access-Control-Allow-Origin', ALLOWED.includes(origin) ? origin : 'https://nondox.com');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const _origin = req.headers['origin'];
  if (_origin && !['https://nondox.com', 'https://www.nondox.com'].includes(_origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  const userId = token ? await verifyToken(token) : null;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  const rl = await checkRateLimit(userId);
  if (!rl.allowed) {
    return res.status(429).json({ error: 'Príliš veľa požiadaviek. Počkaj hodinu a skús znova.', retryAfter: 3600 });
  }

  const { domain } = req.query;
  if (!domain) return res.status(400).json({ error: 'Missing domain parameter' });

  const clean = domain.replace(/^https?:\/\//i, '').replace(/^www\./i, '').split('/')[0].toLowerCase();

  try {
    const r = await fetch(`https://haveibeenpwned.com/api/v3/breacheddomain/${encodeURIComponent(clean)}`, {
      headers: {
        'hibp-api-key': HIBP_KEY,
        'user-agent': 'NonDox-SecurityScanner'
      }
    });

    if (r.status === 404) {
      return res.status(200).json({ ok: true, domain: clean, breachCount: 0, breachedEmails: [] });
    }
    if (!r.ok) {
      return res.status(200).json({ ok: false, error: `HIBP HTTP ${r.status}` });
    }

    const data = await r.json();
    const emails = Object.keys(data);
    const breachCount = emails.length;

    const enriched = emails.slice(0, 20).map(email => ({
      email,
      breaches: data[email]
    }));

    return res.status(200).json({ ok: true, domain: clean, breachCount, breachedEmails: enriched });

  } catch(err) {
    return res.status(200).json({ ok: false, error: err.message });
  }
};
