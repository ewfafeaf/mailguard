// Vercel Serverless Function – WHOIS kontrola domény
// Vracia: creation_date, expiry_date, registrar, country, age_days

const whois = require('whois');

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

  console.log(`[whois-check] Looking up: ${domain}`);

  try {
    const result = await lookupWhois(domain);
    console.log(`[whois-check] age_days=${result.age_days} registrar=${result.registrar} country=${result.country}`);
    return res.status(200).json(result);
  } catch (err) {
    console.error('[whois-check] error:', err.message);
    return res.status(200).json({ ok: false, error: err.message });
  }
};

function lookupWhois(domain) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      resolve({ ok: false, error: 'WHOIS timeout (8s)' });
    }, 8000);

    whois.lookup(domain, { timeout: 7000 }, (err, raw) => {
      clearTimeout(timer);

      if (err) {
        return resolve({ ok: false, error: err.message });
      }
      if (!raw) {
        return resolve({ ok: false, error: 'Prázdna WHOIS odpoveď' });
      }

      const parsed = parseWhois(raw);
      resolve({ ok: true, domain, ...parsed });
    });
  });
}

function parseWhois(raw) {
  // Pomocná funkcia – vyskúša viac regex vzorov, vráti prvý match
  const get = (...patterns) => {
    for (const p of patterns) {
      const m = raw.match(p);
      if (m?.[1]?.trim()) return m[1].trim();
    }
    return null;
  };

  const creationRaw = get(
    /Creation Date:\s*(.+)/i,
    /Created(?:\s+On)?:\s*(.+)/i,
    /Domain Create Date:\s*(.+)/i,
    /Registered(?:\s+On)?:\s*(.+)/i,
    /created:\s*(.+)/i,
    /Registration Time:\s*(.+)/i,
  );

  const expiryRaw = get(
    /Registry Expiry Date:\s*(.+)/i,
    /Expir(?:ation|y|es)(?:\s+Date|\s+On)?:\s*(.+)/i,
    /Domain Expiration Date:\s*(.+)/i,
    /paid-till:\s*(.+)/i,
    /Renewal Date:\s*(.+)/i,
  );

  const registrar = get(
    /Registrar:\s*(.+)/i,
    /Registrar Name:\s*(.+)/i,
    /Sponsoring Registrar:\s*(.+)/i,
  );

  const country = get(
    /Registrant Country:\s*(.+)/i,
    /Country:\s*(.+)/i,
    /Registrant State\/Province:\s*(.+)/i,
  );

  // Parsuj dátumy – orezaj timestamp ak je ISO formát
  const parseDate = (s) => {
    if (!s) return null;
    // Orezaj čas, timezone a URL poznámky
    const clean = s.replace(/T[\d:.Z+\-]+.*/i, '').replace(/\s+.*/, '').trim();
    const d = new Date(clean);
    return isNaN(d.getTime()) ? null : d;
  };

  const created = parseDate(creationRaw);
  const expires = parseDate(expiryRaw);
  const ageDays = created ? Math.floor((Date.now() - created.getTime()) / 86400000) : null;

  return {
    creation_date: created ? created.toISOString().split('T')[0] : null,
    expiry_date:   expires ? expires.toISOString().split('T')[0] : null,
    registrar:     registrar ? registrar.replace(/\s+/g, ' ').slice(0, 60) : null,
    country:       country ? country.slice(0, 50) : null,
    age_days:      ageDays,
  };
}
