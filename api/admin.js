const SUPABASE_URL = 'https://qalcsmnvyuujsmnreglt.supabase.co';
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY || 'sb_publishable_gSuxNEKiTmU0puO9G8vrPQ_GcjOoK06';

export default async function handler(req, res) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || '';
  const userAgent = req.headers['user-agent'] || '';
  const path = req.url || '';
  const method = req.method || 'GET';
  const referer = req.headers['referer'] || '';

  // Fire-and-forget — never block the 404 response
  fetch(`${SUPABASE_URL}/rest/v1/audit_log`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Prefer': 'return=minimal',
    },
    body: JSON.stringify({
      event: 'honeypot_hit',
      ip_address: ip.slice(0, 45),
      user_agent: userAgent.slice(0, 200),
      path: path.slice(0, 200),
      method,
      referer: referer.slice(0, 200),
      created_at: new Date().toISOString(),
    }),
  }).catch(() => {});

  console.warn(`[honeypot] ${method} ${path} from ${ip} ua="${userAgent.slice(0, 80)}"`);

  res.status(404).end();
}
