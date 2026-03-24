// Vercel Serverless Function – HTTP security headers checker
// Primárne: Mozilla HTTP Observatory API
// Fallback:  Priamy fetch cieľovej URL + kontrola response headers (server-side, bez CORS)

const OBS_BASE = 'https://http-observatory.security.mozilla.org/api/v1';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET')    return res.status(405).json({ error: 'Method not allowed' });

  const { host } = req.query;
  if (!host) return res.status(400).json({ error: 'Missing host parameter' });

  const clean = host.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(clean)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }

  console.log(`[observatory] === START host=${clean} ===`);

  // ── 1. Pokús sa cez Mozilla Observatory ──
  const obsResult = await tryObservatory(clean);

  if (obsResult) {
    console.log(`[observatory] Observatory OK: grade=${obsResult.scan?.grade}`);
    return res.status(200).json(obsResult);
  }

  // ── 2. Fallback: priamy fetch a kontrola response headers ──
  console.log(`[observatory] Observatory nedostupné, spúšťam priamy header check`);
  const directResult = await tryDirectHeaders(clean);
  return res.status(200).json(directResult);
};

/* ════════════════════════════════════════
   MOZILLA OBSERVATORY
════════════════════════════════════════ */
async function tryObservatory(clean) {
  try {
    // POST – spusti sken
    console.log(`[observatory] POST trigger → ${OBS_BASE}/analyze?host=${clean}`);
    const triggerRes = await fetch(`${OBS_BASE}/analyze?host=${encodeURIComponent(clean)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'hidden=true&rescan=false',
    });

    console.log(`[observatory] trigger HTTP ${triggerRes.status} ${triggerRes.statusText}`);
    if (!triggerRes.ok) return null;

    let scan = await triggerRes.json();
    console.log(`[observatory] trigger body:`, JSON.stringify(scan).slice(0, 300));

    // Poll max 12× × 3s = 36s
    for (let i = 0; i < 12; i++) {
      if (scan.state === 'FINISHED' || scan.state === 'ABORTED' || scan.state === 'FAILED') break;
      console.log(`[observatory] poll ${i + 1}: state=${scan.state}`);
      await sleep(3000);
      const pollRes = await fetch(`${OBS_BASE}/analyze?host=${encodeURIComponent(clean)}`);
      scan = await pollRes.json();
    }

    console.log(`[observatory] final state=${scan.state} grade=${scan.grade}`);
    if (scan.state !== 'FINISHED') return null;

    // Načítaj výsledky testov
    const testRes = await fetch(`${OBS_BASE}/getScanResults?scan=${scan.scan_id}`);
    const tests   = await testRes.json();
    console.log(`[observatory] tests keys:`, Object.keys(tests || {}).join(', '));

    const headers = parseObsHeaders(tests);
    console.log(`[observatory] parsed headers:`, JSON.stringify(headers));

    return { state: 'FINISHED', source: 'observatory', grade: scan.grade, scan, headers };

  } catch (err) {
    console.error('[observatory] tryObservatory exception:', err.message);
    return null;
  }
}

function parseObsHeaders(tests) {
  if (!tests || typeof tests !== 'object') return {};
  const pick = (key) => {
    const t = tests[key];
    if (!t) return null;
    return { pass: t.pass === true, desc: t.score_description || '' };
  };
  return {
    'strict-transport-security': pick('strict-transport-security'),
    'content-security-policy':   pick('content-security-policy'),
    'x-frame-options':           pick('x-frame-options'),
    'x-content-type-options':    pick('x-content-type-options'),
    'referrer-policy':           pick('referrer-policy'),
    'permissions-policy':        pick('permissions-policy'),
  };
}

/* ════════════════════════════════════════
   PRIAMY HEADER FETCH (fallback)
   Fetchujeme cieľovú URL zo servera a
   čítame HTTP response headers priamo.
════════════════════════════════════════ */
async function tryDirectHeaders(clean) {
  const targetUrl = `https://${clean}`;
  console.log(`[direct] fetching ${targetUrl}`);

  let responseHeaders = {};
  let fetchOk = false;

  try {
    const r = await fetch(targetUrl, {
      method: 'HEAD',
      redirect: 'follow',
      signal: AbortSignal.timeout(8000),
      headers: { 'User-Agent': 'MailGuard-SecurityScanner/1.0' },
    });

    console.log(`[direct] HTTP ${r.status}`);
    fetchOk = r.ok || r.status < 500;

    // Skopíruj všetky hlavičky
    r.headers.forEach((val, key) => {
      responseHeaders[key.toLowerCase()] = val;
    });
    console.log(`[direct] headers:`, JSON.stringify(responseHeaders));

  } catch (err) {
    console.warn(`[direct] fetch failed: ${err.message}`);
  }

  const SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
  ];

  const headers = {};
  for (const h of SECURITY_HEADERS) {
    const present = h in responseHeaders;
    headers[h] = {
      pass: present,
      value: responseHeaders[h] || null,
      desc: present
        ? `Hlavička je prítomná: ${responseHeaders[h] || '(prázdna hodnota)'}`
        : 'Hlavička chýba',
    };
  }

  console.log(`[direct] parsed headers:`, JSON.stringify(headers));

  return {
    state: fetchOk ? 'FINISHED' : 'ERROR',
    source: 'direct',
    grade: null,       // priamy fetch nehodnotí celkový grade
    scan:  null,
    headers,
  };
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
