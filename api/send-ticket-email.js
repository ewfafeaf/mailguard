const RESEND_API_KEY = process.env.RESEND_API_KEY;

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { type, priority, description, userEmail, name, school, phone, message } = req.body;

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
      html: `
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
  <div style="background:linear-gradient(135deg,#1a1d27,#0f1117);padding:24px 32px;border-radius:12px 12px 0 0">
    <div style="color:#4f8ef7;font-size:22px;font-weight:800">NonDox</div>
    <div style="color:#7a82a0;font-size:13px;margin-top:4px">Nová škola má záujem o spoluprácu</div>
  </div>
  <div style="background:white;padding:28px 32px;border:1px solid #e5e7eb;border-top:none">
    <table style="width:100%;border-collapse:collapse">
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280;width:140px">👤 Meno</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${name || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">🏫 Škola</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${school || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">📧 Email</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${userEmail || '—'}</td>
      </tr>
      <tr style="border-bottom:1px solid #f3f4f6">
        <td style="padding:12px 0;font-size:13px;color:#6b7280">📞 Telefón</td>
        <td style="padding:12px 0;font-size:14px;font-weight:600;color:#111">${phone || '—'}</td>
      </tr>
      <tr>
        <td style="padding:12px 0;font-size:13px;color:#6b7280;vertical-align:top">💬 Správa</td>
        <td style="padding:12px 0;font-size:14px;color:#374151">${message || '—'}</td>
      </tr>
    </table>
  </div>
  <div style="background:#f9fafb;padding:16px 32px;border-radius:0 0 12px 12px;border:1px solid #e5e7eb;border-top:none;text-align:center">
    <div style="font-size:12px;color:#9ca3af">NonDox — Kybernetická ochrana škôl | nondox.com</div>
  </div>
</div>`
    })
  });

  const data = await response.json();
  return res.status(response.ok ? 200 : 400).json(data);
}
