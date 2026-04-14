// Vercel Serverless Function – Email Header Analysis
// POST { headers: string (raw email headers) }

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

  const { headers: raw } = req.body || {};
  if (!raw || typeof raw !== 'string' || raw.trim().length < 10) {
    return res.status(400).json({ error: 'Chýbajú alebo sú prázdne email hlavičky.' });
  }

  try {
    const result = analyzeHeaders(raw);
    return res.status(200).json(result);
  } catch (err) {
    console.error('[analyze-headers]', err.message);
    return res.status(200).json({ ok: false, error: err.message });
  }
};

/* ═══════════════════════════════════════
   Parser
═══════════════════════════════════════ */
function analyzeHeaders(raw) {
  // Unfold multi-line headers (RFC 5322: lines starting with whitespace are continuation)
  const unfolded = raw.replace(/\r?\n([ \t])/g, ' ');
  const lines    = unfolded.split(/\r?\n/);

  // Build header map (lowercase key → last value, keep array for multi-value)
  const hmap = {};
  for (const line of lines) {
    const colon = line.indexOf(':');
    if (colon < 1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const val = line.slice(colon + 1).trim();
    if (!hmap[key]) hmap[key] = [];
    hmap[key].push(val);
  }

  const get  = (k)  => hmap[k]?.[0] || null;
  const getAll = (k) => hmap[k] || [];

  // ── Raw header values ──────────────────────────────────────────
  const fromRaw       = get('from')        || '';
  const replyToRaw    = get('reply-to')    || '';
  const returnPathRaw = get('return-path') || '';
  const subject       = get('subject')     || '';
  const date          = get('date')        || '';
  const messageId     = get('message-id')  || '';

  // Authentication-Results (may contain spf/dkim/dmarc verdicts)
  const authResults   = getAll('authentication-results').join(' ');
  const receivedSpf   = getAll('received-spf').join(' ');
  const dkimSig       = getAll('dkim-signature').join(' ');

  // ── Extract domains ─────────────────────────────────────────────
  const emailDomain = (s) => {
    const m = s.match(/@([\w.-]+)/);
    return m ? m[1].toLowerCase() : null;
  };
  const addrEmail = (s) => {
    const m = s.match(/<([^>]+)>/) || s.match(/\S+@\S+/);
    return m ? m[1].toLowerCase().trim() : s.toLowerCase().trim();
  };

  const fromEmail     = addrEmail(fromRaw);
  const fromDomain    = emailDomain(fromRaw);
  const replyToDomain = emailDomain(replyToRaw);
  const returnDomain  = emailDomain(returnPathRaw);

  // ── SPF ─────────────────────────────────────────────────────────
  // Hľadaj v Received-SPF alebo Authentication-Results
  let spfResult = null;
  const spfSource = (receivedSpf + ' ' + authResults).toLowerCase();
  if      (/spf=pass/.test(spfSource))      spfResult = 'pass';
  else if (/spf=fail/.test(spfSource))      spfResult = 'fail';
  else if (/spf=softfail/.test(spfSource))  spfResult = 'softfail';
  else if (/spf=neutral/.test(spfSource))   spfResult = 'neutral';
  else if (/spf=none/.test(spfSource))      spfResult = 'none';

  // ── DKIM ────────────────────────────────────────────────────────
  let dkimResult = null;
  const dkimSource = authResults.toLowerCase();
  if      (/dkim=pass/.test(dkimSource))    dkimResult = 'pass';
  else if (/dkim=fail/.test(dkimSource))    dkimResult = 'fail';
  else if (/dkim=none/.test(dkimSource))    dkimResult = 'none';
  else if (dkimSig)                         dkimResult = 'present'; // podpis existuje ale výsledok neznámy

  // ── DMARC ───────────────────────────────────────────────────────
  let dmarcResult = null;
  if      (/dmarc=pass/.test(dkimSource))   dmarcResult = 'pass';
  else if (/dmarc=fail/.test(dkimSource))   dmarcResult = 'fail';
  else if (/dmarc=none/.test(dkimSource))   dmarcResult = 'none';

  // ── Zhody ───────────────────────────────────────────────────────
  const fromReplyMatch = !replyToRaw || replyToDomain === fromDomain;
  const fromReturnMatch = !returnPathRaw || returnDomain === fromDomain;

  // ── Spoofing indikátory ─────────────────────────────────────────
  const spoofingFlags = [];
  if (replyToRaw && replyToDomain && replyToDomain !== fromDomain) {
    spoofingFlags.push(`Reply-To doména (${replyToDomain}) ≠ From doména (${fromDomain})`);
  }
  if (returnPathRaw && returnDomain && returnDomain !== fromDomain) {
    spoofingFlags.push(`Return-Path doména (${returnDomain}) ≠ From doména (${fromDomain})`);
  }
  if (spfResult === 'fail') {
    spoofingFlags.push('SPF kontrola zlyhala – odosielateľ nie je autorizovaný');
  }
  if (spfResult === 'softfail') {
    spoofingFlags.push('SPF softfail – odosielateľ pravdepodobne nie je autorizovaný');
  }
  if (dkimResult === 'fail') {
    spoofingFlags.push('DKIM podpis je neplatný – email mohol byť modifikovaný');
  }

  // ── Received chain (hop count) ──────────────────────────────────
  const receivedHops = getAll('received').length;

  // ── Skóre ───────────────────────────────────────────────────────
  let score = 50;
  if (spfResult === 'pass')     score += 20;
  else if (spfResult === 'fail') score -= 25;
  else if (spfResult === 'softfail') score -= 10;

  if (dkimResult === 'pass')    score += 20;
  else if (dkimResult === 'fail') score -= 20;

  if (dmarcResult === 'pass')   score += 10;
  else if (dmarcResult === 'fail') score -= 15;

  if (fromReplyMatch)           score += 5;
  else                          score -= 15;

  if (fromReturnMatch)          score += 5;
  else                          score -= 10;

  score = Math.max(0, Math.min(100, score));

  console.log(`[analyze-headers] from=${fromDomain} spf=${spfResult} dkim=${dkimResult} dmarc=${dmarcResult} spoof=${spoofingFlags.length} score=${score}`);

  return {
    ok: true,
    score,
    // Hlavné polia
    from:        fromRaw,
    fromEmail,
    fromDomain,
    replyTo:     replyToRaw   || null,
    returnPath:  returnPathRaw || null,
    subject,
    date,
    messageId,
    // Auth výsledky
    spf:    spfResult,
    dkim:   dkimResult,
    dmarc:  dmarcResult,
    // Zhody
    fromReplyMatch,
    fromReturnMatch,
    // Spoofing
    spoofingDetected: spoofingFlags.length > 0,
    spoofingFlags,
    // Meta
    receivedHops,
    hasAuthResults: !!authResults,
    hasDkimSignature: !!dkimSig,
  };
}
