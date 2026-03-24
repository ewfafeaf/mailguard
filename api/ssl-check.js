// Vercel Serverless Function – SSL Labs API proxy
// Non-blocking: makes exactly ONE request to SSL Labs and returns immediately.
// All polling is done by the client (dashboard.html).
//
// ?host=DOMAIN&startNew=true  → triggers a new scan
// ?host=DOMAIN                → fetches current scan state (for polling)

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { host, startNew } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  const params = new URLSearchParams({
    host: clean,
    publish: 'off',
    all: 'done',
    ignoreMismatch: 'on',
  });
  if (startNew === 'true') params.set('startNew', 'on');

  const apiUrl = `https://api.ssllabs.com/api/v3/analyze?${params}`;
  console.log(`[ssl-check] ${startNew === 'true' ? 'START' : 'POLL'} host=${clean} → ${apiUrl}`);

  try {
    const apiRes = await fetch(apiUrl, {
      headers: { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
      signal: AbortSignal.timeout(8000),
    });

    console.log(`[ssl-check] SSL Labs HTTP ${apiRes.status}`);

    if (apiRes.status === 529) {
      return res.status(200).json({
        status: 'DNS',
        statusMessage: 'SSL Labs preťažený, čakám…',
      });
    }

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      console.error(`[ssl-check] HTTP ${apiRes.status}: ${errText.slice(0, 200)}`);
      return res.status(200).json({ status: 'ERROR', error: `SSL Labs HTTP ${apiRes.status}` });
    }

    const data = await apiRes.json();
    const ep = data.endpoints?.[0];
    console.log(`[ssl-check] status=${data.status} grade=${ep?.grade || '-'} epStatus=${ep?.statusMessage || '-'}`);

    // Ready if main status says so, OR if endpoint already has a grade
    const isReady = data.status === 'READY' || (ep?.grade && ep.grade !== '');

    if (isReady) {
      const parsed = parseSSLResult(data);
      console.log(`[ssl-check] READY – grade=${parsed.grade} cert=${parsed.cert?.issuer}`);
      return res.status(200).json({ status: 'READY', parsed });
    }

    // Still scanning – client will poll again in 5 s
    return res.status(200).json({
      status: data.status || 'IN_PROGRESS',
      statusMessage: data.statusMessage || ep?.statusMessage || null,
    });

  } catch (err) {
    console.error('[ssl-check] exception:', err.message);
    // Treat timeout as transient – client will retry
    return res.status(200).json({ status: 'IN_PROGRESS', statusMessage: 'Čakám na SSL Labs…' });
  }
};

function parseSSLResult(data) {
  const endpoint = data.endpoints?.[0] || null;
  const details  = endpoint?.details  || null;

  const grade = endpoint?.grade || 'N/A';

  // ── Certifikát ──
  let cert = null;
  try {
    let raw = null;

    // 1. v3 certChains → data.certs[]
    const certId = details?.certChains?.[0]?.certIds?.[0];
    if (certId) {
      raw = (data.certs || []).find(c => c.id === certId);
    }
    // 2. Fallback: prvý cert v data.certs[]
    if (!raw && data.certs?.length) {
      raw = data.certs[0];
    }
    // 3. Fallback: details.cert (starší formát)
    if (!raw && details?.cert) {
      raw = details.cert;
    }

    if (raw) {
      cert = {
        issuer:    raw.issuerLabel || raw.issuerSubject || 'Neznámy',
        subject:   raw.commonNames?.[0] || raw.subject || data.host,
        notBefore: raw.notBefore ? new Date(raw.notBefore).toISOString().split('T')[0] : null,
        notAfter:  raw.notAfter  ? new Date(raw.notAfter).toISOString().split('T')[0]  : null,
        daysLeft:  raw.notAfter  ? Math.round((raw.notAfter - Date.now()) / 86400000)  : null,
        keyAlg:    raw.keyAlg  || null,
        keySize:   raw.keySize || null,
        sigAlg:    raw.sigAlg  || null,
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
    if (details.poodle)                        vulns.push({ id: 'POODLE',       desc: 'POODLE (SSLv3)' });
    if (details.poodleTls === 2)               vulns.push({ id: 'POODLE_TLS',   desc: 'POODLE-TLS' });
    if (details.heartbleed)                    vulns.push({ id: 'HEARTBLEED',   desc: 'Heartbleed' });
    if (details.freak)                         vulns.push({ id: 'FREAK',        desc: 'FREAK' });
    if (details.logjam)                        vulns.push({ id: 'LOGJAM',       desc: 'Logjam' });
    if (details.drownVulnerable)               vulns.push({ id: 'DROWN',        desc: 'DROWN' });
    if (details.ticketbleed === 2)             vulns.push({ id: 'TICKETBLEED',  desc: 'Ticketbleed' });
    if (details.bleichenbacher === 2 || details.bleichenbacher === 3)
                                               vulns.push({ id: 'ROBOT',        desc: 'ROBOT (Bleichenbacher)' });
    if (details.zombiePoodle === 2)            vulns.push({ id: 'ZOMBIE',       desc: 'Zombie POODLE' });
    if (details.goldenDoodle === 2)            vulns.push({ id: 'GOLDENDOODLE', desc: 'GoldenDoodle' });
    if (details.zeroLengthPaddingOracle === 2) vulns.push({ id: 'ZLPOODLE',     desc: '0-Length Padding Oracle' });
    if (details.sleepingPoodle === 2)          vulns.push({ id: 'SLEEPING',     desc: 'Sleeping POODLE' });
  }

  // ── HSTS / Forward Secrecy ──
  const hsts           = details?.hstsPolicy?.status === 'present';
  const forwardSecrecy = (details?.forwardSecrecy ?? 0) >= 2;

  return { grade, cert, protocols, vulns, hsts, forwardSecrecy };
}
