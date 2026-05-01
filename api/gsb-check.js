// Vercel Serverless Function – Google Safe Browsing check
// POST { url: string }

const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';

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

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
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
