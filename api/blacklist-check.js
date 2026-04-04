export const config = {
  runtime: 'edge',
};

export default async function handler(req) {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers });
  }

  try {
    const { input } = await req.json();

    if (!input) {
      return new Response(JSON.stringify({ error: 'IP address or domain required' }), {
        status: 400, headers
      });
    }

    const clean = input.trim().toLowerCase()
      .replace(/^https?:\/\//, '')
      .replace(/^www\./, '')
      .replace(/\/.*$/, '');

    const cacheKey = 'blacklist:' + clean;
    const sbRes = await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/rest/v1/cache?cache_key=eq.' + encodeURIComponent(cacheKey) + '&expires_at=gt.' + new Date().toISOString() + '&select=data', {
      headers: {
        'apikey': 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06',
        'Authorization': 'Bearer sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06'
      }
    });
    const sbData = await sbRes.json();
    if (sbData && sbData[0]) return new Response(JSON.stringify(sbData[0].data), { status: 200, headers });

    // Resolve to IP if domain
    let ip = clean;
    let resolvedFrom = null;

    if (!isValidIP(clean)) {
      const resolved = await resolveToIP(clean);
      if (!resolved) {
        return new Response(JSON.stringify({ error: `Could not resolve domain: ${clean}` }), {
          status: 400, headers
        });
      }
      ip = resolved;
      resolvedFrom = clean;
    }

    if (!isValidIP(ip)) {
      return new Response(JSON.stringify({ error: `Invalid IP address: ${ip}` }), {
        status: 400, headers
      });
    }

    // Skip private/reserved IPs
    if (isPrivateIP(ip)) {
      return new Response(JSON.stringify({
        input: clean, ip, resolvedFrom,
        blacklisted: false,
        lists: [],
        count: 0,
        checked: RBL_LISTS.length,
        note: 'Private/reserved IP address — not checked against blacklists'
      }), { status: 200, headers });
    }

    const reversed = reverseIP(ip);

    // Check all RBLs in parallel
    const results = await Promise.all(
      RBL_LISTS.map(rbl => checkRBL(reversed, rbl))
    );

    const listed = results.filter(r => r.listed);
    const clean_count = results.filter(r => !r.listed && !r.error).length;
    const errors = results.filter(r => r.error).length;

    const blResult = {
      input: clean,
      ip,
      resolvedFrom,
      blacklisted: listed.length > 0,
      count: listed.length,
      checked: RBL_LISTS.length,
      clean: clean_count,
      errors,
      lists: results,
      score: calculateScore(listed.length, RBL_LISTS.length),
    };

    await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/rest/v1/cache', {
      method: 'POST',
      headers: {
        'apikey': 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06',
        'Authorization': 'Bearer sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06',
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify({ cache_key: cacheKey, data: blResult, expires_at: new Date(Date.now() + 24*3600000).toISOString() })
    });

    return new Response(JSON.stringify(blResult), { status: 200, headers });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500, headers
    });
  }
}

// ── RBL list definitions ──
const RBL_LISTS = [
  {
    id: 'spamhaus-zen',
    name: 'Spamhaus ZEN',
    host: 'zen.spamhaus.org',
    description: 'Combined Spamhaus IP blocklist — most trusted RBL',
    severity: 'high',
  },
  {
    id: 'spamhaus-xbl',
    name: 'Spamhaus XBL',
    host: 'xbl.spamhaus.org',
    description: 'Exploits Block List — hijacked/infected systems',
    severity: 'high',
  },
  {
    id: 'sorbs-dnsbl',
    name: 'SORBS DNSBL',
    host: 'dnsbl.sorbs.net',
    description: 'Spam and Open Relay Blocking System',
    severity: 'medium',
  },
  {
    id: 'barracuda',
    name: 'Barracuda BRBL',
    host: 'b.barracudacentral.org',
    description: 'Barracuda Reputation Block List',
    severity: 'medium',
  },
  {
    id: 'spamcop',
    name: 'SpamCop BL',
    host: 'bl.spamcop.net',
    description: 'SpamCop Blocking List — user-reported spam sources',
    severity: 'medium',
  },
  {
    id: 'uceprotect-1',
    name: 'UCEPROTECT L1',
    host: 'dnsbl-1.uceprotect.net',
    description: 'UCEPROTECT Level 1 — individual IP listings',
    severity: 'medium',
  },
  {
    id: 'uceprotect-2',
    name: 'UCEPROTECT L2',
    host: 'dnsbl-2.uceprotect.net',
    description: 'UCEPROTECT Level 2 — network range listings',
    severity: 'low',
  },
  {
    id: 'nordspam',
    name: 'NordSpam BL',
    host: 'bl.nordspam.com',
    description: 'NordSpam IP blocklist',
    severity: 'low',
  },
];

// ── DNS RBL lookup via Google DoH ──
async function checkRBL(reversedIP, rbl) {
  const query = `${reversedIP}.${rbl.host}`;
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(query)}&type=A`,
      { signal: AbortSignal.timeout(4000) }
    );
    const data = await res.json();

    // NXDOMAIN (status 3) or no Answer → clean
    if (data.Status === 3 || !data.Answer || data.Answer.length === 0) {
      return { ...rbl, listed: false };
    }

    // Has A record → listed
    const returnCode = data.Answer[0]?.data || '';
    return {
      ...rbl,
      listed: true,
      returnCode,
      detail: interpretReturnCode(rbl.id, returnCode),
    };
  } catch (e) {
    return { ...rbl, listed: false, error: e.message };
  }
}

// ── Resolve domain to IPv4 ──
async function resolveToIP(domain) {
  try {
    const res = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`,
      { signal: AbortSignal.timeout(4000) }
    );
    const data = await res.json();
    const record = data.Answer?.find(r => r.type === 1); // type 1 = A record
    return record?.data || null;
  } catch {
    return null;
  }
}

// ── Helpers ──
function reverseIP(ip) {
  return ip.split('.').reverse().join('.');
}

function isValidIP(str) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(str) &&
    str.split('.').every(n => parseInt(n) <= 255);
}

function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);
  return (
    parts[0] === 10 ||
    parts[0] === 127 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    (parts[0] === 169 && parts[1] === 254)
  );
}

function calculateScore(listedCount, totalChecked) {
  // 100 = clean, 0 = listed on all
  if (listedCount === 0) return 100;
  if (listedCount >= totalChecked) return 0;
  return Math.max(0, Math.round(100 - (listedCount / totalChecked) * 100));
}

// Spamhaus return codes: 127.0.0.2 = SBL, 127.0.0.4 = XBL, etc.
function interpretReturnCode(rblId, code) {
  if (rblId === 'spamhaus-zen' || rblId === 'spamhaus-xbl') {
    const map = {
      '127.0.0.2': 'SBL — spam source',
      '127.0.0.3': 'SBL CSS — snowshoe spam',
      '127.0.0.4': 'XBL — exploited/infected system',
      '127.0.0.9': 'SBL DROP — hijacked netblock',
      '127.0.0.10': 'PBL ISP — dynamic IP',
      '127.0.0.11': 'PBL Spamhaus — policy listing',
    };
    return map[code] || `Listed (${code})`;
  }
  return `Listed (${code})`;
}
