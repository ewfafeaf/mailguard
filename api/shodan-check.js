// Vercel Serverless Function – Shodan Network Intelligence
// 1. DNS A lookup → IP
// 2. Shodan /shodan/host/{IP} → porty, softvér, OS

const dns = require('dns').promises;

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

const DANGEROUS_PORTS = {
  21:    { label:'FTP',           risk:'high' },
  23:    { label:'Telnet',        risk:'high' },
  1433:  { label:'MSSQL',         risk:'high' },
  3306:  { label:'MySQL',         risk:'high' },
  5432:  { label:'PostgreSQL',    risk:'high' },
  5900:  { label:'VNC',           risk:'high' },
  6379:  { label:'Redis',         risk:'high' },
  9200:  { label:'Elasticsearch', risk:'high' },
  11211: { label:'Memcached',     risk:'high' },
  27017: { label:'MongoDB',       risk:'high' },
  22:    { label:'SSH',           risk:'medium' },
  8080:  { label:'HTTP-alt',      risk:'medium' },
  8443:  { label:'HTTPS-alt',     risk:'low' },
};

const SAFE_PORTS = new Set([80, 443]);

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET')     return res.status(405).json({ error: 'Method not allowed' });

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
  if (!/^[a-z0-9.-]+$/.test(clean)) return res.status(400).json({ error: 'Invalid hostname' });

  const cacheKey = 'shodan:' + clean;
  const cached = await getCache(cacheKey);
  if (cached) return res.status(200).json(cached);

  const apiKey = process.env.SHODAN_API_KEY;
  if (!apiKey) return res.status(200).json({ ok: false, error: 'SHODAN_API_KEY nie je nastavený' });

  // ── 1. DNS resolve ─────────────────────────────────────────
  let ip;
  try {
    const addrs = await dns.resolve4(clean);
    ip = addrs[0];
  } catch (e) {
    console.warn('[shodan] DNS failed for', clean, e.message);
    return res.status(200).json({ ok: false, error: 'DNS lookup zlyhal – doména neexistuje alebo nie je dostupná.' });
  }

  console.log(`[shodan] ${clean} → ${ip}`);

  // ── 2. Shodan host lookup ───────────────────────────────────
  let data;
  try {
    const r = await fetch(
      `https://api.shodan.io/shodan/host/${ip}?key=${apiKey}`,
      { signal: AbortSignal.timeout(8000) }
    );

    if (r.status === 404) {
      return res.status(200).json({ ok: true, ip, inShodan: false, ports: [], services: [], openDangerous: [] });
    }
    if (r.status === 401) {
      return res.status(200).json({ ok: false, error: 'Neplatný Shodan API kľúč' });
    }
    if (!r.ok) {
      return res.status(200).json({ ok: false, error: `Shodan HTTP ${r.status}` });
    }

    data = await r.json();
  } catch (e) {
    console.error('[shodan] fetch error:', e.message);
    return res.status(200).json({ ok: false, error: 'Shodan nedostupný – ' + e.message });
  }

  // ── 3. Parsovanie ───────────────────────────────────────────
  const ports = (data.ports || []).sort((a, b) => a - b);

  const services = (data.data || []).map(svc => ({
    port:      svc.port,
    transport: svc.transport || 'tcp',
    product:   svc.product   || null,
    version:   svc.version   || null,
  })).filter((s, i, arr) => arr.findIndex(x => x.port === s.port) === i); // deduplikácia

  // Nájdi webserver (port 80/443 alebo prvý s product)
  const webSvc = services.find(s => [80, 443, 8080, 8443].includes(s.port) && s.product);
  const webserver = webSvc ? `${webSvc.product}${webSvc.version ? ' ' + webSvc.version : ''}` : null;

  // Kategorizuj porty
  const portDetails = ports.map(p => {
    const d = DANGEROUS_PORTS[p];
    return {
      port:  p,
      label: d?.label || String(p),
      risk:  d ? d.risk : (SAFE_PORTS.has(p) ? 'safe' : 'unknown'),
    };
  });

  const openDangerous = portDetails.filter(p => p.risk === 'high' || p.risk === 'medium');

  console.log(`[shodan] ports=${ports.join(',')} dangerous=${openDangerous.map(p=>p.port).join(',')}`);

  const shodanResult = { ok: true, ip, inShodan: true, ports: portDetails, services, webserver, os: data.os || null, org: data.org || null, isp: data.isp || null, openDangerous, tags: data.tags || [], lastUpdate: data.last_update || null };
  await setCache(cacheKey, shodanResult, 6);
  return res.status(200).json(shodanResult);
};
