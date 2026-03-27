// Vercel Serverless Function – QR Code Scanner + URL Safety Check
// POST { image: base64, mimetype: string, gsbKey?: string }

const jsQR = require('jsqr');
const Jimp = require('jimp');

const MAX_SIZE = 10 * 1024 * 1024; // 10 MB

export const config = {
  api: {
    bodyParser: {
      sizeLimit: '10mb',
    },
  },
};

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const { image: b64, gsbKey } = req.body || {};
  if (!b64) return res.status(400).json({ error: 'Chýba parameter image (base64)' });

  const buf = Buffer.from(b64, 'base64');
  if (buf.length > MAX_SIZE) {
    return res.status(400).json({ error: 'Obrázok je príliš veľký (max 4 MB)' });
  }

  try {
    // ── 1. Dekóduj obrázok → RGBA pixel data ─────────────────────────
    let image;
    try {
      image = await Jimp.read(buf);
    } catch (e) {
      return res.status(200).json({ ok: false, error: 'Nepodarilo sa načítať obrázok: ' + e.message });
    }

    const { width, height, data } = image.bitmap;
    const rgba = new Uint8ClampedArray(data);

    // ── 2. Skenuj QR kód ──────────────────────────────────────────────
    const code = jsQR(rgba, width, height, { inversionAttempts: 'attemptBoth' });

    if (!code) {
      return res.status(200).json({
        ok: false,
        error: 'QR kód sa nenašiel v obrázku. Skontroluj kvalitu a osvetlenie.',
      });
    }

    const decoded = code.data.trim();
    console.log(`[qr-scan] decoded: ${decoded.slice(0, 100)}`);

    // ── 3. Zisti typ obsahu ───────────────────────────────────────────
    const isUrl  = /^https?:\/\//i.test(decoded);
    const isWifi = /^WIFI:/i.test(decoded);
    const isVcard= /^BEGIN:VCARD/i.test(decoded);

    let contentType = 'text';
    if (isUrl)   contentType = 'url';
    if (isWifi)  contentType = 'wifi';
    if (isVcard) contentType = 'vcard';

    // ── 4. GSB kontrola (len pre URL) ─────────────────────────────────
    let gsbResult = null;
    if (isUrl && gsbKey) {
      try {
        gsbResult = await checkGSB(decoded, gsbKey);
      } catch (e) {
        console.warn('[qr-scan] GSB failed:', e.message);
      }
    }

    // ── 5. Základná URL analýza ───────────────────────────────────────
    let urlRisk = null;
    if (isUrl) {
      urlRisk = analyzeUrl(decoded);
    }

    return res.status(200).json({
      ok:          true,
      decoded,
      contentType,
      isUrl,
      urlRisk,
      gsbThreats:  gsbResult,
      gsbChecked:  !!gsbKey && isUrl,
    });

  } catch (err) {
    console.error('[qr-scan] error:', err.message);
    return res.status(200).json({ ok: false, error: 'Interná chyba: ' + err.message });
  }
};

/* ═══════════════════════════════════════
   Základná URL analýza (bez externých API)
═══════════════════════════════════════ */
function analyzeUrl(url) {
  const findings = [];
  let score = 0; // 0 = clean, higher = more suspicious

  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();

    // IP adresa namiesto domény
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      findings.push({ sev: 'high', text: 'URL používa IP adresu namiesto domény' });
      score += 40;
    }

    // Skrátené URL
    const shorteners = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','rebrand.ly'];
    if (shorteners.some(s => host === s || host.endsWith('.'+s))) {
      findings.push({ sev: 'medium', text: 'Skrátená URL – skutočný cieľ je skrytý' });
      score += 25;
    }

    // Podozrivé kľúčové slová v URL
    const phishKeywords = ['paypal','apple','amazon','microsoft','google','facebook','instagram',
      'login','signin','verify','secure','account','update','confirm','banking'];
    const hostWords = host.replace(/[.-]/g, ' ');
    for (const kw of phishKeywords) {
      if (hostWords.includes(kw) && !host.endsWith(kw+'.com') && !host.endsWith(kw+'.'+kw)) {
        findings.push({ sev: 'high', text: `Doména imituje "${kw}" (možný phishing)` });
        score += 35;
        break;
      }
    }

    // Príliš dlhá URL
    if (url.length > 200) {
      findings.push({ sev: 'low', text: 'Neobvykle dlhá URL' });
      score += 10;
    }

    // Viacero subdomén
    const parts = host.split('.');
    if (parts.length > 4) {
      findings.push({ sev: 'medium', text: `Veľa subdomén (${parts.length - 2})` });
      score += 20;
    }

    // Riziková TLD
    const tld = '.'+parts[parts.length-1];
    if (['.ru','.cn','.tk','.ga','.ml','.cf','.gq'].includes(tld)) {
      findings.push({ sev: 'medium', text: `Riziková TLD "${tld}"` });
      score += 20;
    }

  } catch {
    findings.push({ sev: 'high', text: 'Neplatná URL štruktúra' });
    score += 30;
  }

  return { score: Math.min(100, score), findings };
}

/* ═══════════════════════════════════════
   Google Safe Browsing
═══════════════════════════════════════ */
async function checkGSB(url, apiKey) {
  const body = {
    client:    { clientId: 'mailguard', clientVersion: '1.0' },
    threatInfo: {
      threatTypes:      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes:    ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries:    [{ url }],
    },
  };
  const r = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
    { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body),
      signal: AbortSignal.timeout(5000) }
  );
  if (!r.ok) return null;
  const data = await r.json();
  return (data.matches || []).map(m => ({ url: m.threat.url, threat: m.threatType }));
}
