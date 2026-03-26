// Vercel Serverless Function – PDF/Document Security Analysis
// POST { filename, mimetype, data (base64), gsbKey? }

const pdfParse = require('pdf-parse');

const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const { filename = 'file', mimetype = '', data: b64, gsbKey } = req.body || {};
  if (!b64) return res.status(400).json({ error: 'Chýba parameter data (base64)' });

  const buf = Buffer.from(b64, 'base64');
  if (buf.length > MAX_SIZE_BYTES) {
    return res.status(400).json({ error: 'Súbor je príliš veľký (max 10 MB)' });
  }

  const ext = filename.split('.').pop().toLowerCase();
  const isPDF = mimetype === 'application/pdf' || ext === 'pdf';

  if (!isPDF) {
    return res.status(400).json({ error: 'Momentálne je podporovaný iba formát PDF.' });
  }

  try {
    const result = await analyzePDF(buf, gsbKey);
    result.filename = filename;
    return res.status(200).json(result);
  } catch (err) {
    console.error('[analyze-file] PDF parse error:', err.message);
    return res.status(200).json({ ok: false, error: 'Nepodarilo sa spracovať PDF: ' + err.message });
  }
};

/* ═══════════════════════════════════════
   PDF Analysis
═══════════════════════════════════════ */
async function analyzePDF(buf, gsbKey) {
  // ── 1. Parse PDF ──────────────────────────────────────────────
  let pdfData;
  try {
    pdfData = await pdfParse(buf, { max: 0 }); // max:0 = all pages
  } catch (e) {
    throw new Error('PDF parsing failed: ' + e.message);
  }

  const text = pdfData.text || '';
  const rawStr = buf.toString('latin1'); // raw bytes as string for pattern matching

  // ── 2. Extrahuj URL z textu ────────────────────────────────────
  const rawUrls = [...new Set((text.match(URL_REGEX) || []).map(u => u.replace(/[.,;)]+$/, '')))];

  // Extrahuj aj URL z raw PDF (URI actions, annotations)
  const rawPdfUrls = [...(rawStr.match(/\/URI\s*\(([^)]+)\)/g) || [])]
    .map(m => m.replace(/^\/URI\s*\(/, '').replace(/\)$/, '').trim())
    .filter(u => /^https?:\/\//i.test(u));

  const allUrls = [...new Set([...rawUrls, ...rawPdfUrls])].slice(0, 100); // max 100

  // ── 3. Detekuj JavaScript ──────────────────────────────────────
  const hasJS = /\/JavaScript\s*[\[(]|\/JS\s*[\[(]/.test(rawStr);

  // ── 4. Detekuj embedded súbory ─────────────────────────────────
  const hasEmbedded = /\/EmbeddedFile/.test(rawStr);

  // ── 5. Detekuj formuláre (AcroForm) ───────────────────────────
  const hasForms = /\/AcroForm/.test(rawStr);

  // ── 6. Detekuj auto-open akcie ─────────────────────────────────
  const hasAutoOpen = /\/OpenAction|\/AA\s*<</.test(rawStr);

  // ── 7. Skontroluj URL cez Google Safe Browsing ─────────────────
  let suspiciousUrls = [];
  if (gsbKey && allUrls.length > 0) {
    try {
      suspiciousUrls = await checkGSB(allUrls, gsbKey);
    } catch (e) {
      console.warn('[analyze-file] GSB check failed:', e.message);
    }
  }

  // ── 8. Výpočet skóre ───────────────────────────────────────────
  let score = 100;
  const recs = [];

  if (hasJS) {
    score -= 40;
    recs.push('⚠️ PDF obsahuje JavaScript – môže spustiť škodlivý kód pri otvorení.');
  }
  if (hasAutoOpen) {
    score -= 30;
    recs.push('⚠️ PDF obsahuje auto-open akcie – spustí sa kód automaticky po otvorení.');
  }
  if (hasEmbedded) {
    score -= 20;
    recs.push('PDF obsahuje vložené súbory – môžu obsahovať malvér.');
  }
  if (hasForms && allUrls.some(u => /paypal|bank|login|secure|verify/i.test(u))) {
    score -= 15;
    recs.push('PDF obsahuje formulár s podozrivými odkazmi – môže ísť o phishing.');
  }
  if (suspiciousUrls.length > 0) {
    score -= suspiciousUrls.length * 20;
    recs.push(`Google Safe Browsing označil ${suspiciousUrls.length} URL ako nebezpečné.`);
  }
  if (allUrls.length > 30) {
    score -= 5;
    recs.push('Neobvyklý počet URL – môže ísť o spam alebo tracking PDF.');
  }

  score = Math.max(0, Math.min(100, score));

  console.log(`[analyze-file] pages=${pdfData.numpages} urls=${allUrls.length} hasJS=${hasJS} hasEmbed=${hasEmbedded} suspicious=${suspiciousUrls.length} score=${score}`);

  return {
    ok: true,
    pages:        pdfData.numpages,
    urlCount:     allUrls.length,
    urls:         allUrls.slice(0, 50), // max 50 v odpovedi
    suspiciousUrls,
    hasJS,
    hasEmbedded,
    hasForms,
    hasAutoOpen,
    score,
    recs,
  };
}

/* ═══════════════════════════════════════
   Google Safe Browsing (batch)
═══════════════════════════════════════ */
async function checkGSB(urls, apiKey) {
  const body = {
    client:    { clientId: 'mailguard', clientVersion: '1.0' },
    threatInfo: {
      threatTypes:      ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
      platformTypes:    ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries:    urls.map(u => ({ url: u })),
    },
  };

  const r = await fetch(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
      signal: AbortSignal.timeout(6000) }
  );

  if (!r.ok) return [];
  const data = await r.json();
  return (data.matches || []).map(m => ({ url: m.threat.url, threat: m.threatType }));
}
