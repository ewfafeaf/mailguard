// Vercel Serverless Function – SSL Labs API proxy
// SSL Labs API docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host, startNew } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  // Sanitize – only allow valid hostnames
  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  try {
    const params = new URLSearchParams({
      host: clean,
      publish: 'off',
      all: 'done',
      ignoreMismatch: 'on',
    });

    // startNew=true pre čerstvý sken, inak vráti cache
    if (startNew === 'true') params.set('startNew', 'on');

    const apiUrl = `https://api.ssllabs.com/api/v3/analyze?${params}`;
    const apiRes = await fetch(apiUrl, {
      headers: { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      return res.status(apiRes.status).json({ error: `SSL Labs API error: ${errText}` });
    }

    const data = await apiRes.json();

    // Ak je hotový, spracuj výsledok do prehľadnej formy
    if (data.status === 'READY') {
      const parsed = parseSSLResult(data);
      return res.status(200).json({ status: 'READY', raw: data, parsed });
    }

    // Inak vráť surový status (IN_PROGRESS, DNS, ERROR)
    return res.status(200).json({
      status: data.status,
      statusMessage: data.statusMessage || null,
      engineVersion: data.engineVersion || null,
    });

  } catch (err) {
    console.error('ssl-check error:', err.message);
    return res.status(500).json({ error: err.message });
  }
};

function parseSSLResult(data) {
  const endpoint = data.endpoints?.[0] || null;
  const details  = endpoint?.details || null;

  // Grade
  const grade = endpoint?.grade || endpoint?.gradeTrust || 'N/A';

  // Certifikát
  let cert = null;
  if (details?.cert) {
    const c = details.cert;
    cert = {
      issuer:    c.issuerLabel  || c.issuerSubject || 'Neznámy',
      subject:   c.commonNames?.[0] || data.host,
      notBefore: c.notBefore ? new Date(c.notBefore).toISOString().split('T')[0] : null,
      notAfter:  c.notAfter  ? new Date(c.notAfter).toISOString().split('T')[0]  : null,
      daysLeft:  c.notAfter  ? Math.round((c.notAfter - Date.now()) / 86400000) : null,
      keyAlg:    c.keyAlg    || null,
      keySize:   c.keySize   || null,
      sigAlg:    c.sigAlg    || null,
    };
  }

  // Protokoly
  const protocols = (details?.protocols || []).map(p => ({
    name:    p.name,
    version: p.version,
    id:      p.id,
  }));

  // Slabiny / vulns
  const vulns = [];
  if (details) {
    if (details.poodle)          vulns.push({ id: 'POODLE',      desc: 'Zraniteľnosť POODLE (SSLv3)' });
    if (details.poodleTls === 2) vulns.push({ id: 'POODLE_TLS',  desc: 'Zraniteľnosť POODLE-TLS' });
    if (details.heartbleed)      vulns.push({ id: 'HEARTBLEED',  desc: 'Zraniteľnosť Heartbleed' });
    if (details.freak)           vulns.push({ id: 'FREAK',       desc: 'Zraniteľnosť FREAK' });
    if (details.logjam)          vulns.push({ id: 'LOGJAM',      desc: 'Zraniteľnosť Logjam' });
    if (details.drown)           vulns.push({ id: 'DROWN',       desc: 'Zraniteľnosť DROWN' });
    if (details.ticketbleed)     vulns.push({ id: 'TICKETBLEED', desc: 'Zraniteľnosť Ticketbleed' });
    if (details.bleichenbacher)  vulns.push({ id: 'ROBOT',       desc: 'Zraniteľnosť ROBOT (Bleichenbacher)' });
    if (details.zombiePoodle)    vulns.push({ id: 'ZOMBIE',      desc: 'Zraniteľnosť Zombie POODLE' });
    if (details.goldenDoodle)    vulns.push({ id: 'GOLDENDOODLE',desc: 'Zraniteľnosť GoldenDoodle' });
    if (details.zeroLengthPaddingOracle) vulns.push({ id: 'ZLPOODLE', desc: 'Zraniteľnosť 0-Length Padding Oracle' });
    if (details.sleepingPoodle)  vulns.push({ id: 'SLEEPING',    desc: 'Zraniteľnosť Sleeping POODLE' });
  }

  // HSTS / forward secrecy
  const hsts = details?.hstsPolicy?.status === 'present';
  const forwardSecrecy = details?.forwardSecrecy >= 2; // 2=most, 4=all

  return { grade, cert, protocols, vulns, hsts, forwardSecrecy };
}
