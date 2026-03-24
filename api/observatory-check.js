// Vercel Serverless Function – Mozilla HTTP Observatory proxy
// Rieši CORS problém pri volaní Observatory priamo z prehliadača.

const BASE = 'https://http-observatory.security.mozilla.org/api/v1';

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

  console.log(`[observatory] host=${clean}`);

  try {
    // 1. Spusti / načítaj cached sken (POST)
    const triggerRes = await fetch(`${BASE}/analyze?host=${encodeURIComponent(clean)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'hidden=true&rescan=false',
    });

    if (!triggerRes.ok) {
      console.error(`[observatory] trigger HTTP ${triggerRes.status}`);
      return res.status(200).json({ state: 'ERROR', error: `Observatory HTTP ${triggerRes.status}` });
    }

    let scan = await triggerRes.json();
    console.log(`[observatory] initial state=${scan.state}`);

    // 2. Polluj kým nie je FINISHED (max 18× × 3s = 54s)
    for (let i = 0; i < 18; i++) {
      if (scan.state === 'FINISHED' || scan.state === 'ABORTED' || scan.state === 'FAILED') break;
      await sleep(3000);
      const pollRes = await fetch(`${BASE}/analyze?host=${encodeURIComponent(clean)}`);
      scan = await pollRes.json();
      console.log(`[observatory] poll ${i + 1}: state=${scan.state}`);
    }

    if (scan.state !== 'FINISHED') {
      return res.status(200).json({ state: scan.state, scan, tests: null });
    }

    // 3. Načítaj detaily testov
    const testRes = await fetch(`${BASE}/getScanResults?scan=${scan.scan_id}`);
    const tests   = await testRes.json();

    // 4. Vytiahni len potrebné hlavičky
    const headers = parseHeaders(tests);
    console.log(`[observatory] grade=${scan.grade} headers=${JSON.stringify(headers)}`);

    return res.status(200).json({ state: 'FINISHED', scan, headers });

  } catch (err) {
    console.error('[observatory] exception:', err.message);
    return res.status(200).json({ state: 'ERROR', error: err.message });
  }
};

function parseHeaders(tests) {
  if (!tests || typeof tests !== 'object') return {};
  const pick = (key) => {
    const t = tests[key];
    if (!t) return null;
    return { pass: t.pass === true, score: t.score_modifier, desc: t.score_description };
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

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
