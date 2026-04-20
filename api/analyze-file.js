// Vercel Serverless Function – PDF/DOCX/XLSX Security Analysis
// POST { filename, mimetype, data (base64), gsbKey? }

const pdfParse = require('pdf-parse');
const AdmZip   = require('adm-zip');
const XLSX     = require('xlsx');

const MAX_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB
const URL_REGEX = /https?:\/\/[^\s<>"')\]]+/gi;

const DANGEROUS_PATTERNS = [
  // Python
  { pattern: 'shutil.rmtree',              severity: 'critical', desc: 'Mazanie priečinkov' },
  { pattern: 'os.remove',                  severity: 'high',     desc: 'Mazanie súborov' },
  { pattern: 'os.system',                  severity: 'high',     desc: 'Spustenie systémových príkazov' },
  { pattern: 'subprocess',                 severity: 'high',     desc: 'Spustenie externých procesov' },
  // Windows/Native
  { pattern: 'NtRaiseHardError',           severity: 'critical', desc: 'Kritická systémová chyba – BSoD' },
  { pattern: 'RtlAdjustPrivilege',         severity: 'critical', desc: 'Eskalácia systémových privilégií' },
  { pattern: 'dllload',                    severity: 'critical', desc: 'Načítanie systémovej knižnice' },
  // Office macros
  { pattern: 'AutoOpen',                   severity: 'critical', desc: 'Automatické spustenie po otvorení' },
  { pattern: 'Workbook_Open',              severity: 'critical', desc: 'Automatické spustenie v Exceli' },
  { pattern: 'CreateObject("WScript.Shell")', severity: 'critical', desc: 'Prístup k Windows Shell' },
  { pattern: "CreateObject('WScript.Shell')", severity: 'critical', desc: 'Prístup k Windows Shell' },
  { pattern: 'Shell(',                     severity: 'high',     desc: 'Spustenie shell príkazu' },
  // System paths
  { pattern: 'System32',                   severity: 'critical', desc: 'Prístup k systémovým súborom Windows' },
  { pattern: 'C:\\Windows',               severity: 'high',     desc: 'Prístup k Windows priečinku' },
  { pattern: '/etc/passwd',               severity: 'critical', desc: 'Prístup k systémovým heslám Linux' },
  // Fork bomb
  { pattern: 'fork()',                     severity: 'critical', desc: 'Fork bomb – zahltenie systému' },
  { pattern: ':(){ :|:& };:',             severity: 'critical', desc: 'Fork bomb príkaz' },
];

function scanDangerousPatterns(text) {
  if (!text) return [];
  const lines = text.split('\n');
  const found = [];
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    for (const dp of DANGEROUS_PATTERNS) {
      const key = dp.pattern + ':' + i;
      if (seen.has(key)) continue;
      if (line.toLowerCase().includes(dp.pattern.toLowerCase())) {
        seen.add(key);
        found.push({
          pattern:  dp.pattern,
          severity: dp.severity,
          desc:     dp.desc,
          line:     i + 1,
          snippet:  line.trim().slice(0, 120),
        });
      }
    }
  }
  return found;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST')   return res.status(405).json({ error: 'Method not allowed' });

  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const authRes = await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/auth/v1/user', {
    headers: { 'apikey': 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06', 'Authorization': `Bearer ${token}` }
  });
  if (!authRes.ok) return res.status(401).json({ error: 'Unauthorized' });

  const { filename = 'file', mimetype = '', data: b64, gsbKey } = req.body || {};
  if (!b64) return res.status(400).json({ error: 'Chýba parameter data (base64)' });

  const buf = Buffer.from(b64, 'base64');
  if (buf.length > MAX_SIZE_BYTES) {
    return res.status(400).json({ error: 'Súbor je príliš veľký (max 10 MB)' });
  }

  const ext = filename.split('.').pop().toLowerCase();

  const isPDF  = mimetype === 'application/pdf' || ext === 'pdf';
  const isDOCX = ['docx'].includes(ext) ||
    mimetype === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
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
   DOCX Analysis  (ZIP + XML parsing)
═══════════════════════════════════════ */
async function analyzeDOCX(buf, gsbKey) {
  let zip;
  try {
    zip = new AdmZip(buf);
  } catch (e) {
    throw new Error('Nepodarilo sa otvoriť DOCX súbor (neplatný ZIP): ' + e.message);
  }

  // ── 1. Hyperlinky z relationships súboru ─────────────────────────
  // word/_rels/document.xml.rels obsahuje <Relationship Target="https://..." TargetMode="External"/>
  const relsXml = zip.getEntry('word/_rels/document.xml.rels')?.getData()?.toString('utf8') || '';
  const hyperlinkUrls = [...relsXml.matchAll(/Target="([^"]+)"/g)]
    .map(m => m[1])
    .filter(u => /^https?:\/\//i.test(u));

  // ── 2. Text z document.xml (URL vzory v texte) ────────────────────
  const docXml = zip.getEntry('word/document.xml')?.getData()?.toString('utf8') || '';
  // Odstráň XML tagy, nechaj len text
  const plainText = docXml.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  const textUrls  = extractUrls(plainText);

  // ── 3. Počet strán z docProps/app.xml ─────────────────────────────
  const appXml    = zip.getEntry('docProps/app.xml')?.getData()?.toString('utf8') || '';
  const pagesMatch = appXml.match(/<Pages>(\d+)<\/Pages>/i);
  const pages     = pagesMatch ? parseInt(pagesMatch[1], 10) : null;

  // ── 4. Makrá (VBA project) ────────────────────────────────────────
  const hasMacros = !!zip.getEntry('word/vbaProject.bin');

  const allUrls = dedup([...hyperlinkUrls, ...textUrls]).slice(0, 100);

  const suspiciousUrls = await safeGSB(allUrls, gsbKey);
  const { score, recs } = calcScore({
    hasJS: false, hasAutoOpen: false, hasEmbedded: hasMacros,
    hasForms: false, allUrls, suspiciousUrls, docType: 'DOCX', hasMacros,
  });

  console.log(`[DOCX] pages=${pages} hyperlinks=${hyperlinkUrls.length} textUrls=${textUrls.length} macros=${hasMacros} score=${score}`);
  return { ok:true, docType:'DOCX', pages, urlCount:allUrls.length,
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
