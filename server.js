import express from 'express';
import bodyParser from 'body-parser';
import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;

// Supabase
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
if (!SUPABASE_URL || !SUPABASE_KEY) {
    console.error("Supabase URL or KEY not set in environment variables!");
    process.exit(1);
}
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Challenge-response функции
function computeExpected1(r1) {
    return 3 * (r1 * r1) + 7 * r1 - 19;
}
function computeExpected2(r2) {
    return 5 * (r2 * r2 * r2) - 11 * r2 + 42;
}

// Генератор одноразового токена
function generateToken() {
    return crypto.randomBytes(16).toString('hex');
}

// ---- GET / ----
app.get('/', (req, res) => {
    res.send('Work'); // Отвечает "Work", чтобы проверить, что сервер поднят
});

// ---- /check ----
app.post('/check', async (req, res) => {
    const { hwid, key, first_val, second_val } = req.body;

    if (!hwid || !key || first_val == null || second_val == null) {
        return res.status(400).json({ status: 'error', message: 'Invalid body' });
    }

    const { data: whitelistData, error } = await supabase
        .from('whitelist')
        .select('*')
        .eq('whitelistkey', key)
        .limit(1)
        .single();

    if (error || !whitelistData) {
        return res.status(403).json({ status: 'deny', message: 'Invalid key' });
    }

    const expected1 = computeExpected1(first_val);
    const expected2 = computeExpected2(second_val);

    if (Math.abs(expected1 - first_val) > 0.0001 || Math.abs(expected2 - second_val) > 0.0001) {
        return res.status(403).json({ status: 'deny', message: 'Challenge-response failed' });
    }

    const token = generateToken();
    const expires = Date.now() + 60 * 1000;
    app.locals.sessions = app.locals.sessions || new Map();
    app.locals.sessions.set(token, { hwid, key, expires, used: false });

    // Обновляем HWID в базе
    await supabase.from('whitelist').update({ hwid }).eq('whitelistkey', key);

    return res.json({ status: 'allow', session_token: token });
});

// ---- /log ----
app.post('/log', async (req, res) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.replace('Bearer ', '').trim();

    if (!token) return res.status(401).json({ status: 'error', message: 'No token' });

    const sessions = app.locals.sessions || new Map();
    const session = sessions.get(token);
    if (!session) return res.status(403).json({ status: 'error', message: 'Invalid token' });

    if (Date.now() > session.expires) {
        sessions.delete(token);
        return res.status(403).json({ status: 'error', message: 'Token expired' });
    }

    if (session.used) return res.status(403).json({ status: 'error', message: 'Token already used' });
    session.used = true;

    const { key, hwid } = session;
    const { placeName, ip, note } = req.body;

    if (!placeName || !ip) return res.status(400).json({ status: 'error', message: 'Invalid body' });

    await supabase.from('logs').insert([
        { whitelistkey: key, place_name: placeName, ip, note: note || '' }
    ]);

    console.log(`[LOG] Key: ${key} | HWID: ${hwid} | Place: ${placeName} | IP: ${ip}`);

    return res.json({ status: 'success' });
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
