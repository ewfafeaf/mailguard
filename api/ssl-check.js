// Vercel Serverless Function – vlastná SSL/TLS kontrola cez Node.js tls modul
// Nepotrebuje SSL Labs – výsledok do 3 sekúnd

const tls = require('tls');

const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';

async function verifyToken(token) {
  if (!token) return null;
  try {
    const res = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${token}`
      }
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data?.id || null;
  } catch(e) { return null; }
}

async function getCache(key) {
  try {
    const res = await fetch(
      `${SUPABASE_URL}/rest/v1/cache?cache_key=eq.${encodeURIComponent(key)}&expires_at=gt.${new Date().toISOString()}&select=data&limit=1`,
      { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
    );
    const rows = await res.json();
    return rows && rows[0] ? rows[0].data : null;
  } catch(e) { return null; }
}

async function setCache(key, value, hours = 24) {
  try {
    await fetch(`${SUPABASE_URL}/rest/v1/cache`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify({
        cache_key: key,
        data: value,
        expires_at: new Date(Date.now() + hours * 3600000).toISOString()
      })
    });
  } catch(e) {}
}

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
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  const userId = token ? await verifyToken(token) : null;
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });
  const rl = await checkRateLimit(userId);
  if (!rl.allowed) {
    return res.status(429).json({ error: 'Príliš veľa požiadaviek. Počkaj hodinu a skús znova.', retryAfter: 3600 });
  }

  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  const cacheKey = 'ssl:' + clean;
  const cached = await getCache(cacheKey);
  if (cached) return res.status(200).json(cached);

  console.log(`[ssl-check] Connecting to ${clean}:443`);

  try {
    const result = await checkSSL(clean);
    console.log(`[ssl-check] grade=${result.grade} protocol=${result.protocol} daysLeft=${result.cert?.daysLeft}`);
    await setCache(cacheKey, result, 12);
    return res.status(200).json(result);
  } catch (err) {
    console.error('[ssl-check] error:', err.message);
    return res.status(200).json({ ok: false, error: err.message });
  }
};

function checkSSL(hostname) {
  return new Promise((resolve, reject) => {
    let settled = false;

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(new Error('Spojenie vypršalo (timeout 8s)'));
    }, 8000);

    const socket = tls.connect(
      {
        host:               hostname,
        port:               443,
        servername:         hostname,
        rejectUnauthorized: false,   // chceme cert aj keď je self-signed
      },
      () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);

        try {
          const raw      = socket.getPeerCertificate(true);
          const protocol = socket.getProtocol();          // 'TLSv1.3', 'TLSv1.2', …
          const cipher   = socket.getCipher();
          socket.end();

          if (!raw || !raw.subject) {
            return resolve({ ok: false, error: 'Certifikát nebol získaný' });
          }

          const validTo   = raw.valid_to   ? new Date(raw.valid_to)   : null;
          const validFrom = raw.valid_from ? new Date(raw.valid_from) : null;
          const daysLeft  = validTo ? Math.round((validTo - Date.now()) / 86400000) : null;
          const expired   = daysLeft !== null && daysLeft < 0;

          const cert = {
            subject:   raw.subject?.CN || hostname,
            issuer:    raw.issuer?.O   || raw.issuer?.CN || 'Neznámy',
            validFrom: validFrom ? validFrom.toISOString().split('T')[0] : null,
            validTo:   validTo   ? validTo.toISOString().split('T')[0]   : null,
            daysLeft,
            expired,
            keyBits:   raw.bits        || null,
            sigAlg:    raw.asn1Curve   || null,
          };

          resolve({
            ok:       true,
            grade:    computeGrade(protocol, daysLeft, expired),
            cert,
            protocol: protocol || null,
            cipher:   cipher?.name || null,
          });
        } catch (e) {
          socket.destroy();
          reject(e);
        }
      }
    );

    socket.on('error', err => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    });
  });
}

function computeGrade(protocol, daysLeft, expired) {
  if (expired)                             return 'F';
  if (daysLeft !== null && daysLeft < 14)  return 'F';
  const p = (protocol || '').toUpperCase();
  if (p === 'SSLV2' || p === 'SSLV3')     return 'F';
  if (p === 'TLSV1' || p === 'TLSV1.0')   return 'F';
  if (p === 'TLSV1.1')                     return 'C';
  if (daysLeft !== null && daysLeft < 30)  return 'B';
  if (p === 'TLSV1.2')                     return 'A';
  if (p === 'TLSV1.3')                     return 'A+';
  return 'B';
}
