// Vercel Serverless Function – PDF/DOCX/XLSX Security Analysis
// POST { filename, mimetype, data (base64), gsbKey? }

const pdfParse = require('pdf-parse');
const mammoth  = require('mammoth');
const XLSX     = require('xlsx');

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

  const isPDF  = mimetype === 'application/pdf' || ext === 'pdf';
  const isDOCX = ['docx','doc'].includes(ext) ||
    mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
    mimetype === 'application/msword';
  const isXLSX = ['xlsx','xls'].includes(ext) ||
    mimetype === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' ||
    mimetype === 'application/vnd.ms-excel';

  try {
    let result;
    if (isPDF)       result = await analyzePDF(buf, gsbKey);
    else if (isDOCX) result = await analyzeDOCX(buf, gsbKey);
    else if (isXLSX) result = await analyzeXLSX(buf, gsbKey);
    else return res.status(400).json({ error: 'Nepodporovaný formát. Použi PDF, DOCX, DOC, XLSX alebo XLS.' });

    result.filename = filename;
    return res.status(200).json(result);
  } catch (err) {
    console.error('[analyze-file] error:', err.message);
    return res.status(200).json({ ok: false, error: 'Nepodarilo sa spracovať súbor: ' + err.message });
  }
};

/* ═══════════════════════════════════════
   PDF Analysis
═══════════════════════════════════════ */
async function analyzePDF(buf, gsbKey) {
  const pdfData = await pdfParse(buf, { max: 0 });
  const text    = pdfData.text || '';
  const rawStr  = buf.toString('latin1');

  // URL z textu + z raw PDF URI anotácií
  const textUrls = extractUrls(text);
  const pdfUriUrls = [...(rawStr.match(/\/URI\s*\(([^)]+)\)/g) || [])]
    .map(m => m.replace(/^\/URI\s*\(/, '').replace(/\)$/, '').trim())
    .filter(u => /^https?:\/\//i.test(u));
  const allUrls = dedup([...textUrls, ...pdfUriUrls]).slice(0, 100);

  const hasJS       = /\/JavaScript\s*[\[(]|\/JS\s*[\[(]/.test(rawStr);
  const hasEmbedded = /\/EmbeddedFile/.test(rawStr);
  const hasForms    = /\/AcroForm/.test(rawStr);
  const hasAutoOpen = /\/OpenAction|\/AA\s*<</.test(rawStr);

  const suspiciousUrls = await safeGSB(allUrls, gsbKey);
  const { score, recs } = calcScore({
    hasJS, hasAutoOpen, hasEmbedded, hasForms, allUrls, suspiciousUrls, docType: 'PDF',
  });

  console.log(`[PDF] pages=${pdfData.numpages} urls=${allUrls.length} js=${hasJS} score=${score}`);
  return { ok:true, docType:'PDF', pages:pdfData.numpages, urlCount:allUrls.length,
    urls:allUrls.slice(0,50), suspiciousUrls, hasJS, hasEmbedded, hasForms, hasAutoOpen, score, recs };
}

/* ═══════════════════════════════════════
   DOCX/DOC Analysis  (mammoth)
═══════════════════════════════════════ */
async function analyzeDOCX(buf, gsbKey) {
  // Extrahuj plain text
  const { value: text } = await mammoth.extractRawText({ buffer: buf });

  // Extrahuj HTML pre hyperlinky (<a href="...">)
  const { value: html } = await mammoth.convertToHtml({ buffer: buf });
  const hrefUrls = [...(html.matchAll(/href="([^"]+)"/g) || [])].map(m => m[1])
    .filter(u => /^https?:\/\//i.test(u));

  const textUrls = extractUrls(text);
  const allUrls  = dedup([...hrefUrls, ...textUrls]).slice(0, 100);

  // DOCX môže obsahovať makrá (detekcia cez raw bytes – OOXML balík)
  // .doc (legacy binary) - kontrola OLE header
  const rawStr  = buf.toString('latin1');
  const hasMacros = /vbaProject\.bin/i.test(rawStr) || // DOCX s VBA
    (buf[0] === 0xD0 && buf[1] === 0xCF); // legacy .doc OLE compound

  const suspiciousUrls = await safeGSB(allUrls, gsbKey);
  const { score, recs } = calcScore({
    hasJS: false, hasAutoOpen: false, hasEmbedded: hasMacros,
    hasForms: false, allUrls, suspiciousUrls, docType: 'DOCX',
    hasMacros,
  });

  console.log(`[DOCX] urls=${allUrls.length} macros=${hasMacros} score=${score}`);
  return { ok:true, docType:'DOCX', pages: null, urlCount:allUrls.length,
    urls:allUrls.slice(0,50), suspiciousUrls, hasJS:false, hasEmbedded:hasMacros,
    hasForms:false, hasAutoOpen:false, hasMacros, score, recs };
}

/* ═══════════════════════════════════════
   XLSX/XLS Analysis  (xlsx)
═══════════════════════════════════════ */
async function analyzeXLSX(buf, gsbKey) {
  const wb = XLSX.read(buf, { type: 'buffer', cellFormula: false, cellNF: false });

  const allUrls = [];

  for (const sheetName of wb.SheetNames) {
    const ws = wb.Sheets[sheetName];
    if (!ws) continue;

    for (const cellAddr of Object.keys(ws)) {
      if (cellAddr.startsWith('!')) continue;
      const cell = ws[cellAddr];

      // Hyperlink na bunke
      if (cell.l?.Target && /^https?:\/\//i.test(cell.l.Target)) {
        allUrls.push(cell.l.Target);
      }
      // URL v textovej hodnote bunky
      if (typeof cell.v === 'string') {
        const found = cell.v.match(URL_REGEX);
        if (found) allUrls.push(...found.map(u => u.replace(/[.,;)]+$/, '')));
      }
    }
  }

  const uniqueUrls = dedup(allUrls).slice(0, 100);

  // Kontrola makier (XLSM/XLS legacy)
  const rawStr    = buf.toString('latin1');
  const hasMacros = /xl\/vbaProject\.bin/i.test(rawStr) ||
    (buf[0] === 0xD0 && buf[1] === 0xCF);

  const suspiciousUrls = await safeGSB(uniqueUrls, gsbKey);
  const { score, recs } = calcScore({
    hasJS: false, hasAutoOpen: false, hasEmbedded: hasMacros,
    hasForms: false, allUrls: uniqueUrls, suspiciousUrls, docType: 'XLSX',
    hasMacros,
  });

  const sheetCount = wb.SheetNames.length;
  console.log(`[XLSX] sheets=${sheetCount} urls=${uniqueUrls.length} macros=${hasMacros} score=${score}`);
  return { ok:true, docType:'XLSX', pages: sheetCount, urlCount:uniqueUrls.length,
    urls:uniqueUrls.slice(0,50), suspiciousUrls, hasJS:false, hasEmbedded:hasMacros,
    hasForms:false, hasAutoOpen:false, hasMacros, score, recs };
}

/* ═══════════════════════════════════════
   Spoločné pomocné funkcie
═══════════════════════════════════════ */
function extractUrls(text) {
  return [...new Set((text.match(URL_REGEX) || []).map(u => u.replace(/[.,;)]+$/, '')))];
}

function dedup(arr) {
  return [...new Set(arr)];
}

function calcScore({ hasJS, hasAutoOpen, hasEmbedded, hasForms, allUrls, suspiciousUrls, docType, hasMacros }) {
  let score = 100;
  const recs = [];

  if (hasJS) {
    score -= 40;
    recs.push(`⚠️ ${docType} obsahuje JavaScript – môže spustiť škodlivý kód.`);
  }
  if (hasAutoOpen) {
    score -= 30;
    recs.push(`⚠️ ${docType} obsahuje auto-open akcie.`);
  }
  if (hasMacros) {
    score -= 35;
    recs.push(`⚠️ Dokument obsahuje makrá (VBA) – nespúšťaj ich z neznámych zdrojov.`);
  } else if (hasEmbedded) {
    score -= 20;
    recs.push(`${docType} obsahuje vložené súbory.`);
  }
  if (hasForms && allUrls.some(u => /paypal|bank|login|secure|verify/i.test(u))) {
    score -= 15;
    recs.push('Dokument obsahuje formulár s podozrivými odkazmi – môže ísť o phishing.');
  }
  if (suspiciousUrls.length > 0) {
    score -= suspiciousUrls.length * 20;
    recs.push(`Google Safe Browsing označil ${suspiciousUrls.length} URL ako nebezpečné.`);
  }
  if (allUrls.length > 30) {
    score -= 5;
    recs.push('Neobvyklý počet URL – môže ísť o spam alebo tracking dokument.');
  }

  return { score: Math.max(0, Math.min(100, score)), recs };
}

async function safeGSB(urls, gsbKey) {
  if (!gsbKey || urls.length === 0) return [];
  try { return await checkGSB(urls, gsbKey); }
  catch (e) { console.warn('[analyze-file] GSB failed:', e.message); return []; }
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
    { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body),
      signal: AbortSignal.timeout(6000) }
  );
  if (!r.ok) return [];
  const data = await r.json();
  return (data.matches || []).map(m => ({ url: m.threat.url, threat: m.threatType }));
}
