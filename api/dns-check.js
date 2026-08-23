export const config = {
  runtime: 'edge',
};

const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

export default async function handler(req) {
  // CORS headers
  const ALLOWED = ['https://nondox.com', 'https://www.nondox.com'];
  const origin = req.headers.get('origin');
  const headers = {
    'Access-Control-Allow-Origin': ALLOWED.includes(origin) ? origin : 'https://nondox.com',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };

  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 200, headers });
  }

  const _origin = req.headers.get('origin');
  if (_origin && !['https://nondox.com', 'https://www.nondox.com'].includes(_origin)) {
    return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
  }

  try {
    const { domain } = await req.json();

    if (!domain) {
      return new Response(JSON.stringify({ error: 'Domain required' }), {
        status: 400,
        headers
      });
    }

    // Clean domain (remove http://, www., trailing slash)
    const cleanDomain = domain.replace(/^https?:\/\//, '')
                              .replace(/^www\./, '')
                              .replace(/\/$/, '');

    const authHeader = req.headers.get('authorization') || '';
    const token = authHeader.replace('Bearer ', '');
    if (!token) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
    const authRes = await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/auth/v1/user', {
      headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${token}` }
    });
    if (!authRes.ok) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });

    const cacheKey = 'dns:' + cleanDomain;
    const sbRes = await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/rest/v1/cache?cache_key=eq.' + encodeURIComponent(cacheKey) + '&expires_at=gt.' + new Date().toISOString() + '&select=data', {
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`
      }
    });
    const sbData = await sbRes.json();
    if (sbData && sbData[0]) return new Response(JSON.stringify(sbData[0].data), { status: 200, headers });

    const results = {
      domain: cleanDomain,
      spf: await checkSPF(cleanDomain),
      dkim: await checkDKIM(cleanDomain),
      dmarc: await checkDMARC(cleanDomain),
      mx: await checkMX(cleanDomain),
      score: 0,
      recommendations: []
    };

    // Calculate score
    results.score = calculateScore(results);
    results.recommendations = generateRecommendations(results);

    await fetch('https://qalcsmnvyuujsmnreglt.supabase.co/rest/v1/cache', {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'resolution=merge-duplicates'
      },
      body: JSON.stringify({ cache_key: cacheKey, data: results, expires_at: new Date(Date.now() + 24*3600000).toISOString() })
    });

    return new Response(JSON.stringify(results), {
      status: 200,
      headers
    });

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers
    });
  }
}

// Check SPF record
async function checkSPF(domain) {
  try {
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=TXT`);
    const data = await response.json();

    if (data.Answer) {
      const spfRecord = data.Answer.find(record =>
        record.data.includes('v=spf1')
      );

      if (spfRecord) {
        return {
          exists: true,
          record: spfRecord.data,
          valid: spfRecord.data.includes('v=spf1'),
          status: 'PASS'
        };
      }
    }

    return {
      exists: false,
      record: null,
      valid: false,
      status: 'FAIL'
    };
  } catch (error) {
    return {
      exists: false,
      record: null,
      valid: false,
      status: 'ERROR',
      error: error.message
    };
  }
}

// Check DKIM — tries multiple common selectors in order
async function checkDKIM(domain) {
  const SELECTORS = ['resend', 'google', 'default', 'mail', 'smtp', 'k1'];
  try {
    for (const selector of SELECTORS) {
      const response = await fetch(`https://dns.google/resolve?name=${selector}._domainkey.${domain}&type=TXT`);
      const data = await response.json();
      if (data.Answer && data.Answer.length > 0) {
        return {
          exists: true,
          selector: selector,
          record: data.Answer[0]?.data || null,
          status: 'PASS'
        };
      }
    }
    return {
      exists: false,
      selector: null,
      status: 'NOT_FOUND'
    };
  } catch (error) {
    return {
      exists: false,
      selector: null,
      status: 'ERROR',
      error: error.message
    };
  }
}

// Check DMARC record
async function checkDMARC(domain) {
  try {
    const response = await fetch(`https://dns.google/resolve?name=_dmarc.${domain}&type=TXT`);
    const data = await response.json();

    if (data.Answer && data.Answer.length > 0) {
      const dmarcRecord = data.Answer[0].data;

      // Parse policy
      const policyMatch = dmarcRecord.match(/p=([^;]+)/);
      const policy = policyMatch ? policyMatch[1] : 'none';

      return {
        exists: true,
        record: dmarcRecord,
        policy: policy,
        status: policy === 'reject' || policy === 'quarantine' ? 'PASS' : 'WEAK'
      };
    }

    return {
      exists: false,
      record: null,
      policy: null,
      status: 'FAIL'
    };
  } catch (error) {
    return {
      exists: false,
      record: null,
      policy: null,
      status: 'ERROR',
      error: error.message
    };
  }
}

// Check MX records
async function checkMX(domain) {
  try {
    const response = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
    const data = await response.json();

    if (data.Answer && data.Answer.length > 0) {
      const mxRecords = data.Answer.map(record => ({
        priority: parseInt(record.data.split(' ')[0]),
        server: record.data.split(' ')[1]
      }));

      return {
        exists: true,
        records: mxRecords,
        count: mxRecords.length,
        status: 'PASS'
      };
    }

    return {
      exists: false,
      records: [],
      count: 0,
      status: 'FAIL'
    };
  } catch (error) {
    return {
      exists: false,
      records: [],
      count: 0,
      status: 'ERROR',
      error: error.message
    };
  }
}

// Calculate overall security score
function calculateScore(results) {
  let score = 0;

  // SPF: 35 points
  if (results.spf.status === 'PASS') score += 35;

  // DKIM: 10 points (NOT_FOUND penalizes at most 10 — selector may just be unknown)
  if (results.dkim.status === 'PASS') score += 10;

  // DMARC: 45 points
  if (results.dmarc.status === 'PASS') score += 45;
  else if (results.dmarc.status === 'WEAK') score += 22;

  // MX: 10 points
  if (results.mx.status === 'PASS') score += 10;

  // Bonus: if SPF + DMARC + MX are all OK, guarantee minimum 90
  const coreOk = results.spf.status === 'PASS' &&
    (results.dmarc.status === 'PASS' || results.dmarc.status === 'WEAK') &&
    results.mx.status === 'PASS';
  if (coreOk && results.dmarc.status === 'PASS') score = Math.max(score, 90);

  return Math.min(score, 100);
}

// Generate recommendations
function generateRecommendations(results) {
  const recommendations = [];

  if (!results.spf.exists) {
    recommendations.push({
      type: 'critical',
      title: 'Chýba SPF záznam',
      description: 'Bez SPF záznamu môže ktokoľvek na svete odoslať email ktorý sa tvári že pochádza z vašej domény.',
      fix: 'Pridajte TXT záznam: v=spf1 include:_spf.google.com ~all'
    });
  }

  if (!results.dkim.exists) {
    recommendations.push({
      type: 'warning',
      title: 'Chýba DKIM podpis',
      description: 'Bez DKIM podpisu nemôže príjemca overiť že email naozaj odoslali vy. Útočník môže obsah emailu zmeniť počas prenosu bez toho aby to niekto zistil.',
      fix: 'Nastavte DKIM v administrácii vášho email providera.'
    });
  }

  if (!results.dmarc.exists) {
    recommendations.push({
      type: 'critical',
      title: 'Chýba DMARC politika',
      description: 'Bez DMARC politiky môže ktokoľvek posielať emaily v mene vašej domény. Rodičia, žiaci aj úrady dostanú falošný email ktorý vyzerá ako od vás.',
      fix: 'Pridajte TXT záznam na _dmarc.' + results.domain + ': v=DMARC1; p=quarantine; rua=mailto:admin@' + results.domain
    });
  } else if (results.dmarc.policy === 'none') {
    recommendations.push({
      type: 'warning',
      title: 'DMARC politika je príliš slabá',
      description: 'Vaša DMARC politika je nastavená na "none" čo neposkytuje ochranu.',
      fix: 'Zmeňte p=none na p=quarantine alebo p=reject'
    });
  }

  if (!results.mx.exists) {
    recommendations.push({
      type: 'critical',
      title: 'Chýbajú MX záznamy',
      description: 'Bez MX záznamov nemôžete prijímať emaily.',
      fix: 'Pridajte MX záznamy pre váš mail server.'
    });
  }

  return recommendations;
}
