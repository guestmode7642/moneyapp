const crypto = require('crypto');

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
const SECRET = process.env.AUTH_SECRET || REDIS_TOKEN || 'moneyapp-fallback-secret';

async function redisCmd(command) {
  const res = await fetch(REDIS_URL, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${REDIS_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(command)
  });
  const data = await res.json();
  return data.result;
}

function signToken(username) {
  const sig = crypto.createHmac('sha256', SECRET).update(username).digest('hex');
  return `${username}.${sig}`;
}

function verifyToken(token) {
  if (!token || !token.includes('.')) return null;
  const [username, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SECRET).update(username).digest('hex');
  if (sig !== expected) return null;
  return username;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!REDIS_URL || !REDIS_TOKEN) return res.status(500).json({ error: 'Redis env vars missing' });

  const { action, username, password, appData } = req.body || {};

  try {
    if (action === 'signup' || action === 'login') {
      const cleanUser = (username || '').trim().toLowerCase();
      if (!cleanUser || !password) return res.status(400).json({ error: 'Username and password required' });

      const userKey = `moneyapp:user:${cleanUser}`;
      const existingRaw = await redisCmd(['GET', userKey]);

      if (action === 'signup') {
        if (existingRaw) return res.status(409).json({ error: 'Username already exists' });
        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.scryptSync(password, salt, 64).toString('hex');
        await redisCmd(['SET', userKey, JSON.stringify({ salt, hash })]);
        const token = signToken(cleanUser);
        return res.status(200).json({ username: cleanUser, token, appData: null });
      }

      if (!existingRaw) return res.status(404).json({ error: 'Account not found' });
      const { salt, hash } = JSON.parse(existingRaw);
      const verifyHash = crypto.scryptSync(password, salt, 64).toString('hex');
      if (verifyHash !== hash) return res.status(401).json({ error: 'Invalid password' });

      const token = signToken(cleanUser);
      const savedDataRaw = await redisCmd(['GET', `moneyapp:data:${cleanUser}`]);
      return res.status(200).json({
        username: cleanUser,
        token,
        appData: savedDataRaw ? JSON.parse(savedDataRaw) : null
      });
    }

    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();
    const authedUser = verifyToken(token);
    if (!authedUser) return res.status(401).json({ error: 'Unauthorized session' });

    const dataKey = `moneyapp:data:${authedUser}`;

    if (action === 'pull') {
      const raw = await redisCmd(['GET', dataKey]);
      return res.status(200).json({ appData: raw ? JSON.parse(raw) : null });
    }

    if (action === 'push') {
      await redisCmd(['SET', dataKey, JSON.stringify(appData)]);
      return res.status(200).json({ ok: true, updatedAt: appData?.updatedAt });
    }

    return res.status(400).json({ error: 'Invalid action' });
  } catch (err) {
    return res.status(500).json({ error: 'Server sync error' });
  }
};
