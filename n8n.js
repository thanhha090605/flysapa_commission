// Vercel serverless proxy: Mini App -> n8n Cloud
// Env vars (Vercel -> Settings -> Environment Variables):
//   BOT_TOKEN   token bot Telegram (để xác thực initData)
//   CS_IDS      Telegram user ID được phép dùng, cách nhau dấu phẩy (VD: 123456,789012)
//   N8N_BASE    https://flysapa.app.n8n.cloud
//   N8N_SECRET  giá trị của credential Header Auth trên n8n (header X-Api-Secret)
//   N8N_PREFIX  (tuỳ chọn) "webhook" (mặc định) hoặc "webhook-test" khi test

const crypto = require('crypto');

const ROUTES = { agents: 'GET', ocr: 'POST', 'create-order': 'POST' };
const MAX_AGE_SEC = 24 * 3600;

function verifyInitData(initData, botToken) {
  if (!initData) return null;
  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return null;
  params.delete('hash');

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secret = crypto.createHmac('sha256', 'WebAppData').update(botToken).digest();
  const calc = crypto.createHmac('sha256', secret).update(dataCheckString).digest('hex');

  const a = Buffer.from(calc, 'hex');
  const b = Buffer.from(hash, 'hex');
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;

  const authDate = Number(params.get('auth_date'));
  if (!authDate || Date.now() / 1000 - authDate > MAX_AGE_SEC) return null;

  try {
    return JSON.parse(params.get('user'));
  } catch {
    return null;
  }
}

module.exports = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  const { BOT_TOKEN, CS_IDS, N8N_BASE, N8N_SECRET } = process.env;
  const prefix = process.env.N8N_PREFIX || 'webhook';
  if (!BOT_TOKEN || !CS_IDS || !N8N_BASE || !N8N_SECRET) {
    return res.status(500).json({ error: 'Server chưa cấu hình đủ biến môi trường' });
  }

  const path = String(req.query.path || '');
  if (!Object.prototype.hasOwnProperty.call(ROUTES, path)) {
    return res.status(404).json({ error: 'Không tìm thấy endpoint' });
  }
  if (req.method !== ROUTES[path]) {
    return res.status(405).json({ error: 'Sai method' });
  }

  const auth = req.headers.authorization || '';
  const initData = auth.startsWith('tma ') ? auth.slice(4) : '';
  const user = verifyInitData(initData, BOT_TOKEN);
  if (!user) return res.status(401).json({ error: 'Phiên Telegram không hợp lệ, hãy mở lại Mini App' });

  const allowed = CS_IDS.split(',').map((s) => s.trim()).filter(Boolean);
  if (!allowed.includes(String(user.id))) {
    return res.status(403).json({ error: 'Tài khoản này chưa được cấp quyền' });
  }

  const url = `${N8N_BASE.replace(/\/$/, '')}/${prefix}/${path}`;
  const headers = {
    'X-Api-Secret': N8N_SECRET,
    'X-TG-User': String(user.id),
  };
  const init = { method: ROUTES[path], headers, signal: AbortSignal.timeout(55000) };
  if (init.method === 'POST') {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(req.body || {});
  }

  try {
    const r = await fetch(url, init);
    const text = await r.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: r.ok ? 'n8n trả về dữ liệu không hợp lệ' : `n8n lỗi ${r.status}` };
    }
    return res.status(r.ok ? 200 : r.status === 400 ? 400 : 502).json(data);
  } catch (e) {
    return res.status(504).json({ error: 'Không kết nối được n8n: ' + (e.name === 'TimeoutError' ? 'quá thời gian' : e.message) });
  }
};

module.exports.config = { api: { bodyParser: { sizeLimit: '4mb' } } };
