const RESEND_API_KEY = 're_ATz3hTR1_QJ8kSBxfDFnGCpPU2iadNtvm';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { type, priority, description, userEmail } = req.body;

  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${RESEND_API_KEY}`
    },
    body: JSON.stringify({
      from: 'NonDox Support <noreply@nondox.com>',
      to: 'nondox.support@gmail.com',
      subject: `🏫 Nová škola má záujem — ${type}`,
      html: `<div style="font-family:sans-serif;max-width:600px"><h2>Nový support ticket</h2><p><b>Od:</b> ${userEmail}</p><p><b>Typ:</b> ${type}</p><p><b>Priorita:</b> ${priority}</p><p><b>Popis:</b></p><p>${description}</p></div>`
    })
  });

  const data = await response.json();
  return res.status(response.ok ? 200 : 400).json(data);
}
