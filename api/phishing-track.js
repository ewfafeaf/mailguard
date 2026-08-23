const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;

module.exports = async function handler(req, res) {
  const { token } = req.query;

  if (!token) {
    return res.redirect('https://nondox.com');
  }

  try {
    // Zápis kliku ide výhradne cez SECURITY DEFINER RPC funkciu
    // track_phishing_click — tá interne overí token a zapíše
    // clicked/clicked_at na správny target a inkrementuje
    // click_count na kampani. Anon kľúč už nemá priamy UPDATE
    // prístup k phishing_targets/phishing_campaigns.
    await fetch(`${SUPABASE_URL}/rest/v1/rpc/track_phishing_click`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ p_token: token })
    });
  } catch(e) {
    console.error('[phishing-track]', e.message);
  }

  // Presmeruj na výsledkovú stránku
  return res.redirect('https://nondox.com/phishing-result.html');
};
