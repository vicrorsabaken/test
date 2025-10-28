import { createClient } from '@supabase/supabase-js';
import crypto from 'crypto';

export default async function handler(req, res) {
    if (req.method === 'GET') {
        res.status(200).send('Work'); // GET / -> проверка, что сервер жив
    } else {
        res.status(405).send('Method Not Allowed');
    }
}
