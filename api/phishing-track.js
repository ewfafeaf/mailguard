const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';

module.exports = async function handler(req, res) {
  const { token } = req.query;

  if (!token) {
    return res.redirect('https://nondox.com');
  }

  try {
    // Najdi target podla tokenu
    const findRes = await fetch(
      `${SUPABASE_URL}/rest/v1/phishing_targets?token=eq.${encodeURIComponent(token)}&select=id,clicked,campaign_id&limit=1`,
      { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
    );
    const rows = await findRes.json();

    if (rows && rows[0] && !rows[0].clicked) {
      const userAgent = req.headers['user-agent'] || '';
      const isBot = /bot|crawler|spider|headless|phantom|selenium/i.test(userAgent);

      const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';

      let geo = {};
      try {
        const geoRes = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
          signal: AbortSignal.timeout(3000)
        });
        if (geoRes.ok) geo = await geoRes.json();
      } catch(geoErr) {
        console.warn('[phishing-track] geo lookup failed:', geoErr.message);
      }

      const CLOUD_RANGES = [
        '13.', '52.', '54.', '18.', '3.',           // Amazon AWS
        '34.', '35.', '104.196.', '130.211.',        // Google Cloud
        '40.', '20.', '51.', '13.64.',               // Microsoft Azure
        '199.232.', '185.199.',                       // GitHub/Fastly CDN
      ];
      const isCloudIP = CLOUD_RANGES.some(prefix => ip.startsWith(prefix));

      const isSlovak = geo.country_code === 'SK';
      const isSuspicious = !isSlovak && !isBot && !isCloudIP && !!geo.country_code;

      let behavior;
      if (isCloudIP)   behavior = 'sandboxed';
      else if (isBot)  behavior = 'bot';
      else             behavior = 'clicked';

      // Oznac ako kliknuty
      await fetch(
        `${SUPABASE_URL}/rest/v1/phishing_targets?id=eq.${rows[0].id}`,
        {
          method: 'PATCH',
          headers: {
            'apikey': SUPABASE_KEY,
            'Authorization': `Bearer ${SUPABASE_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            clicked: true,
            clicked_at: new Date().toISOString(),
            behavior,
            user_agent: userAgent.slice(0, 200),
            ip_address: ip.slice(0, 45),
            country: geo.country || null,
            country_code: geo.country_code || null,
            is_suspicious: isSuspicious,
            notes: isCloudIP ? 'Automatický skener (cloud IP) — nie reálny používateľ' : null,
          })
        }
      );

      // Inkrementuj click_count na kampani
      const campRes = await fetch(
        `${SUPABASE_URL}/rest/v1/phishing_campaigns?id=eq.${rows[0].campaign_id}&select=click_count&limit=1`,
        { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
      );
      const camps = await campRes.json();
      if (camps && camps[0]) {
        await fetch(
          `${SUPABASE_URL}/rest/v1/phishing_campaigns?id=eq.${rows[0].campaign_id}`,
          {
            method: 'PATCH',
            headers: {
              'apikey': SUPABASE_KEY,
              'Authorization': `Bearer ${SUPABASE_KEY}`,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({ click_count: camps[0].click_count + 1 })
          }
        );
      }
    }
  } catch(e) {
    console.error('[phishing-track]', e.message);
  }

  // Presmeruj na výsledkovú stránku
  return res.redirect('https://nondox.com/phishing-result.html');
};
