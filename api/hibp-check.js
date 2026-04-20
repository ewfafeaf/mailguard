const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';
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

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  const userId = token ? await verifyToken(token) : null;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

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
