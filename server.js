// server.js
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());

const PORT = 3000;

// Ключи для whitelist (можно хранить в БД)
const validKeys = new Set(['NIGGERSKEYS', 'ANOTHERKEY']); 

// Сессии: session_token -> { hwid, key, expires }
const sessions = new Map();

// Хелпер для генерации токена
function generateToken() {
    return crypto.randomBytes(16).toString('hex');
}

// Challenge-response функции (как в Lua)
function computeExpected1(r1) {
    return 3 * (r1 * r1) + 7 * r1 - 19;
}

function computeExpected2(r2) {
    return 5 * (r2 * r2 * r2) - 11 * r2 + 42;
}

// ---- /check ----
app.post('/check', (req, res) => {
    const { hwid, key, first_val, second_val } = req.body;
    if (!hwid || !key || first_val == null || second_val == null) {
        return res.status(400).json({ status: 'error', message: 'Invalid body' });
    }

    if (!validKeys.has(key)) {
        return res.status(403).json({ status: 'deny', message: 'Invalid key' });
    }

    const expected1 = computeExpected1(first_val);
    const expected2 = computeExpected2(second_val);

    if (Math.abs(expected1 - first_val) > 0.0001 || Math.abs(expected2 - second_val) > 0.0001) {
        return res.status(403).json({ status: 'deny', message: 'Challenge-response failed' });
    }

    // Генерируем session token
    const token = generateToken();
    const expires = Date.now() + 60 * 1000; // 60 секунд жизни токена
    sessions.set(token, { hwid, key, expires, used: false });

    return res.json({ status: 'allow', session_token: token });
});

// ---- /log ----
app.post('/log', (req, res) => {
    const auth = req.headers['authorization'] || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ status: 'error', message: 'No token' });

    const session = sessions.get(token);
    if (!session) return res.status(403).json({ status: 'error', message: 'Invalid token' });

    // Проверяем срок жизни
    if (Date.now() > session.expires) {
        sessions.delete(token);
        return res.status(403).json({ status: 'error', message: 'Token expired' });
    }

    // Можно сделать одноразовый токен
    if (session.used) return res.status(403).json({ status: 'error', message: 'Token already used' });
    session.used = true;

    const { key, hwid } = session;
    const { placeName, ip } = req.body;

    if (!placeName || !ip) return res.status(400).json({ status: 'error', message: 'Invalid body' });

    // Логируем (можно в файл или базу)
    console.log(`[LOG] Key: ${key} | HWID: ${hwid} | Place: ${placeName} | IP: ${ip}`);

    return res.json({ status: 'success' });
});

app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
});
