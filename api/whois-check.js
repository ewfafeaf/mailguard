// Vercel Serverless Function – RDAP/WHOIS kontrola domény
// Primárny:  https://rdap.org/domain/DOMAIN  (IANA RDAP bootstrap, JSON)
// Fallback:  https://who-dat.as93.net/DOMAIN.json (verejné API)

const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';

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

  // Použi len root doménu (bez subdomény)
  const parts = clean.split('.');
  const domain = parts.length > 2 ? parts.slice(-2).join('.') : clean;

  const cacheKey = 'whois:' + domain;
  const cached = await getCache(cacheKey);
  if (cached) return res.status(200).json(cached);

  console.log(`[whois-check] Looking up: ${domain}`);

  const result = await tryRDAP(domain) || await tryWhoDat(domain);

  if (!result) {
    console.warn(`[whois-check] All sources failed for ${domain}`);
    return res.status(200).json({ ok: false, error: 'RDAP/WHOIS nedostupné pre túto doménu' });
  }

  console.log(`[whois-check] ok – age_days=${result.age_days} registrar=${result.registrar}`);
  const whoisResult = { ok: true, domain, ...result };
  await setCache(cacheKey, whoisResult, 48);
  return res.status(200).json(whoisResult);
};

/* ═══════════════════════════════════════
   RDAP (rdap.org – IANA bootstrap)
═══════════════════════════════════════ */
async function tryRDAP(domain) {
  try {
    const r = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal:  AbortSignal.timeout(7000),
    });

    if (!r.ok) {
      console.warn(`[rdap] HTTP ${r.status} for ${domain}`);
      return null;
    }

    const data = await r.json();

    // Dátumy sú v events[]
    const events = Array.isArray(data.events) ? data.events : [];
    const getEvent = (action) => {
      const ev = events.find(e =>
        typeof e.eventAction === 'string' &&
        e.eventAction.toLowerCase().includes(action)
      );
      return ev?.eventDate || null;
    };

    const created = fmtDate(getEvent('registr'));   // "registration"
    const expires = fmtDate(getEvent('expir'));     // "expiration"
    const ageDays = calcAge(created);

    // Registrátor z entities
    let registrar = null;
    const entities = Array.isArray(data.entities) ? data.entities : [];
    const regEntity = entities.find(e => e.roles?.includes('registrar'));
    if (regEntity) {
      // vcardArray: [["vcard", [ ["fn",{},"text","Name"], ... ]]]
      const vcard = regEntity.vcardArray?.[1];
      if (Array.isArray(vcard)) {
        const fn = vcard.find(([name]) => name === 'fn');
        registrar = fn?.[3] || null;
      }
      // Fallback: publicIds
      if (!registrar && regEntity.publicIds?.[0]?.identifier) {
        registrar = regEntity.publicIds[0].identifier;
      }
    }

    // Krajina z registrant entity
    let country = null;
    const registrant = entities.find(e => e.roles?.includes('registrant'));
    if (registrant) {
      const vcard = registrant.vcardArray?.[1];
      if (Array.isArray(vcard)) {
        const adr = vcard.find(([name]) => name === 'adr');
        country = adr?.[1]?.cc || adr?.[3]?.[6] || null;
      }
    }

    return { creation_date: created, expiry_date: expires, registrar, country, age_days: ageDays, source: 'rdap' };

  } catch (err) {
    console.warn('[rdap] exception:', err.message);
    return null;
  }
}

/* ═══════════════════════════════════════
   Fallback: who-dat.as93.net
═══════════════════════════════════════ */
async function tryWhoDat(domain) {
  try {
    const r = await fetch(`https://who-dat.as93.net/${encodeURIComponent(domain)}.json`, {
      signal: AbortSignal.timeout(7000),
    });

    if (!r.ok) {
      console.warn(`[who-dat] HTTP ${r.status} for ${domain}`);
      return null;
    }

    const data = await r.json();
    if (data.error || (!data.domain && !data.created_date)) return null;

    const d = data.domain || data;
    const created = fmtDate(d.created_date || d.creation_date || data.created_date);
    const expires = fmtDate(d.expiration_date || d.expiry_date || data.expiration_date);
    const registrar = data.registrar?.name || d.registrar || null;
    const country   = data.registrant?.country || data.administrative?.country || null;
    const ageDays   = calcAge(created);

    return { creation_date: created, expiry_date: expires, registrar, country, age_days: ageDays, source: 'who-dat' };

  } catch (err) {
    console.warn('[who-dat] exception:', err.message);
    return null;
  }
}

/* ── Helpers ── */
function fmtDate(s) {
  if (!s) return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d.toISOString().split('T')[0];
}

function calcAge(isoDate) {
  if (!isoDate) return null;
  return Math.floor((Date.now() - new Date(isoDate).getTime()) / 86400000);
}
