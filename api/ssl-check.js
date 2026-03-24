// Vercel Serverless Function – SSL Labs API proxy
// SSL Labs v3 API docs: https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host, startNew } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  // Sanitize
  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  console.log(`[ssl-check] host=${clean} startNew=${startNew}`);

  try {
    const params = new URLSearchParams({
      host: clean,
      publish: 'off',
      all: 'done',
      ignoreMismatch: 'on',
    });
    if (startNew === 'true') params.set('startNew', 'on');

    const apiUrl = `https://api.ssllabs.com/api/v3/analyze?${params}`;
    console.log(`[ssl-check] calling: ${apiUrl}`);

    const apiRes = await fetch(apiUrl, {
      headers: { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      console.error(`[ssl-check] SSL Labs HTTP ${apiRes.status}: ${errText}`);
      return res.status(apiRes.status).json({ error: `SSL Labs API error ${apiRes.status}: ${errText}` });
    }

    const data = await apiRes.json();
    console.log(`[ssl-check] status=${data.status} endpoints=${data.endpoints?.length ?? 0}`);

    if (data.status === 'READY') {
      const parsed = parseSSLResult(data);
      console.log(`[ssl-check] parsed grade=${parsed.grade} cert=${parsed.cert?.issuer}`);
      return res.status(200).json({ status: 'READY', parsed });
    }

    // IN_PROGRESS / DNS / ERROR – klient bude pollovať
    return res.status(200).json({
      status: data.status,
      statusMessage: data.statusMessage || data.endpoints?.[0]?.statusMessage || null,
    });

  } catch (err) {
    console.error('[ssl-check] exception:', err.message);
    return res.status(500).json({ error: err.message });
  }
};

function parseSSLResult(data) {
  const endpoint = data.endpoints?.[0] || null;
  const details  = endpoint?.details  || null;

  const grade = endpoint?.grade || 'N/A';

  // ── Certifikát (v3: data.certs[] + certChains na prepojenie) ──
  let cert = null;
  try {
    // Najdi certId z prvého chainu prvého endpointu
    const certId = details?.certChains?.[0]?.certIds?.[0];
    // data.certs je pole certov – hľadaj podľa id
    const raw = certId
      ? (data.certs || []).find(c => c.id === certId)
      : (data.certs || [])[0];             // fallback: prvý cert

    if (raw) {
      cert = {
        issuer:   raw.issuerLabel || raw.issuerSubject || 'Neznámy',
        subject:  raw.commonNames?.[0] || raw.subject || data.host,
        notBefore: raw.notBefore ? new Date(raw.notBefore).toISOString().split('T')[0] : null,
        notAfter:  raw.notAfter  ? new Date(raw.notAfter).toISOString().split('T')[0]  : null,
        daysLeft:  raw.notAfter  ? Math.round((raw.notAfter - Date.now()) / 86400000)  : null,
        keyAlg:   raw.keyAlg  || null,
        keySize:  raw.keySize || null,
        sigAlg:   raw.sigAlg  || null,
      };
    }
  } catch (e) {
    console.warn('[ssl-check] cert parse error:', e.message);
  }

  // ── Protokoly ──
  const protocols = (details?.protocols || []).map(p => ({
    name:    p.name,
    version: p.version,
    id:      p.id,
  }));

  // ── Zraniteľnosti ──
  const vulns = [];
  if (details) {
    if (details.poodle)                    vulns.push({ id: 'POODLE',       desc: 'POODLE (SSLv3)' });
    if (details.poodleTls === 2)           vulns.push({ id: 'POODLE_TLS',   desc: 'POODLE-TLS' });
    if (details.heartbleed)                vulns.push({ id: 'HEARTBLEED',   desc: 'Heartbleed' });
    if (details.freak)                     vulns.push({ id: 'FREAK',        desc: 'FREAK' });
    if (details.logjam)                    vulns.push({ id: 'LOGJAM',       desc: 'Logjam' });
    if (details.drownVulnerable)           vulns.push({ id: 'DROWN',        desc: 'DROWN' });
    if (details.ticketbleed === 2)         vulns.push({ id: 'TICKETBLEED',  desc: 'Ticketbleed' });
    if (details.bleichenbacher === 2 || details.bleichenbacher === 3)
                                           vulns.push({ id: 'ROBOT',        desc: 'ROBOT (Bleichenbacher)' });
    if (details.zombiePoodle === 2)        vulns.push({ id: 'ZOMBIE',       desc: 'Zombie POODLE' });
    if (details.goldenDoodle === 2)        vulns.push({ id: 'GOLDENDOODLE', desc: 'GoldenDoodle' });
    if (details.zeroLengthPaddingOracle === 2) vulns.push({ id: 'ZLPOODLE', desc: '0-Length Padding Oracle' });
    if (details.sleepingPoodle === 2)      vulns.push({ id: 'SLEEPING',     desc: 'Sleeping POODLE' });
  }

  // ── HSTS / Forward Secrecy ──
  const hsts           = details?.hstsPolicy?.status === 'present';
  const forwardSecrecy = (details?.forwardSecrecy ?? 0) >= 2;

  return { grade, cert, protocols, vulns, hsts, forwardSecrecy };
}
