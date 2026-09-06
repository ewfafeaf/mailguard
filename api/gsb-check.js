// Vercel Serverless Function – Google Safe Browsing check
// POST { url: string }

const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

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
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const _origin = req.headers['origin'];
  if (_origin && !['https://nondox.com', 'https://www.nondox.com'].includes(_origin)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  const userId = await verifyToken(token);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  const rl = await checkRateLimit(userId);
  if (!rl.allowed) {
    return res.status(429).json({ error: 'Príliš veľa požiadaviek. Počkaj hodinu a skús znova.', retryAfter: 3600 });
  }

  const { url } = req.body || {};
  if (!url) return res.status(400).json({ error: 'Missing url parameter' });

  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Neplatná URL adresa' });
    }
  } catch {
    return res.status(400).json({ error: 'Neplatná URL adresa' });
  }

  const gsbKey = process.env.GOOGLE_SAFE_BROWSING_KEY;
  if (!gsbKey) {
    return res.status(200).json({ ok: true, matches: [], skipped: true });
  }

  try {
    const body = {
      client: { clientId: 'nondox', clientVersion: '1.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    };

    const r = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(gsbKey)}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(6000),
      }
    );

    if (!r.ok) {
      console.warn('[gsb-check] GSB HTTP error:', r.status);
      return res.status(200).json({ ok: false, error: `GSB HTTP ${r.status}`, matches: [] });
    }

    const data = await r.json();
    return res.status(200).json({ ok: true, matches: data.matches || [] });

  } catch (err) {
    console.warn('[gsb-check] fetch error:', err.message);
    return res.status(200).json({ ok: false, error: err.message, matches: [] });
  }
};
