// Vercel Serverless Function – VirusTotal domain reputation check
// Endpoint: GET /api/virustotal-check?host=DOMAIN

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

  const apiKey = process.env.VIRUSTOTAL_API_KEY || 'ed512194cf801fda89aef7e2e39ba4b8ca5bd79d54bb7fdeacd21a1389605d04';

  // Použi root doménu
  const parts = clean.split('.');
  const domain = parts.length > 2 ? parts.slice(-2).join('.') : clean;

  console.log(`[virustotal] Checking domain: ${domain}`);

  try {
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers: {
        'x-apikey': apiKey,
        'Accept':   'application/json',
      },
      signal: AbortSignal.timeout(8000),
    });

    console.log(`[virustotal] HTTP ${r.status}`);

    if (r.status === 404) {
      return res.status(200).json({ ok: true, domain, unknown: true, malicious: 0, suspicious: 0, harmless: 0, total: 0 });
    }
    if (r.status === 401) {
      return res.status(200).json({ ok: false, error: 'Neplatný VirusTotal API kľúč' });
    }
    if (!r.ok) {
      return res.status(200).json({ ok: false, error: `VirusTotal HTTP ${r.status}` });
    }

    const data = await r.json();
    const attrs = data?.data?.attributes;
    if (!attrs) {
      return res.status(200).json({ ok: false, error: 'Neočakávaný formát odpovede' });
    }

    const stats      = attrs.last_analysis_stats || {};
    const malicious  = stats.malicious  || 0;
    const suspicious = stats.suspicious || 0;
    const harmless   = stats.harmless   || 0;
    const undetected = stats.undetected || 0;
    const total      = malicious + suspicious + harmless + undetected;
    const reputation = attrs.reputation ?? null;

    console.log(`[virustotal] malicious=${malicious} suspicious=${suspicious} harmless=${harmless} total=${total}`);

    return res.status(200).json({
      ok: true,
      domain,
      malicious,
      suspicious,
      harmless,
      undetected,
      total,
      reputation,
    });

  } catch (err) {
    console.error('[virustotal] exception:', err.message);
    return res.status(200).json({ ok: false, error: err.message });
  }
};
