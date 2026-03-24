// Vercel Serverless Function – kontrola bezpečnostných HTTP hlavičiek
// Priamy fetch na doménu, čítame response headers zo servera (žiadne CORS problémy)

const SECURITY_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options',
  'referrer-policy',
  'permissions-policy',
];

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  console.log(`[headers-check] Checking ${clean}`);

  try {
    const result = await checkHeaders(clean);
    const present = Object.values(result.headers).filter(h => h.present).length;
    console.log(`[headers-check] ${present}/${SECURITY_HEADERS.length} headers present, httpStatus=${result.httpStatus}`);
    return res.status(200).json(result);
  } catch (err) {
    console.error('[headers-check] error:', err.message);
    return res.status(200).json({ ok: false, error: err.message });
  }
};

async function checkHeaders(hostname) {
  const url = `https://${hostname}`;

  const r = await fetch(url, {
    method:   'HEAD',
    redirect: 'follow',
    signal:   AbortSignal.timeout(7000),
    headers:  { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
  });

  // Niektoré servery neodpovedajú na HEAD – fallback na GET
  const response = r.ok || r.status < 500 ? r : await fetch(url, {
    method:   'GET',
    redirect: 'follow',
    signal:   AbortSignal.timeout(7000),
    headers:  { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
  });

  const found = {};
  response.headers.forEach((val, key) => {
    found[key.toLowerCase()] = val;
  });

  const headers = {};
  for (const h of SECURITY_HEADERS) {
    const present = h in found;
    headers[h] = {
      present,
      pass:  present,          // alias pre kompatibilitu s buildWebReport
      value: found[h] || null,
    };
  }

  return { ok: true, httpStatus: response.status, headers };
}
