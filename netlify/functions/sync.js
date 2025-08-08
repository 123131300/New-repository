// netlify/functions/sync.js
import crypto from "crypto";

function verifyTelegram(initData, botToken) {
  // initData — URL-строка из Telegram.WebApp.initData
  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  params.delete("hash");
  const data = Array.from(params.entries())
    .sort(([a],[b])=>a.localeCompare(b))
    .map(([k,v])=>`${k}=${v}`).join('\n');

  const secret = crypto.createHash('sha256').update(botToken).digest();
  const hmac = crypto.createHmac('sha256', secret).update(data).digest('hex');
  if (hmac !== hash) return null;

  const userStr = params.get("user");
  const authDate = Number(params.get("auth_date")||0);
  if (!userStr) return null;
  if (Date.now()/1000 - authDate > 86400*7) return null; // 7 дней

  try { return JSON.parse(userStr); } catch { return null; }
}

export async function handler(event) {
  const action = (new URL(event.rawUrl)).searchParams.get("action"); // pull | push
  const initData = event.headers["x-telegram-init-data"] || "";
  const BOT_TOKEN = process.env.BOT_TOKEN;
  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

  if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return { statusCode: 500, body: "Env BOT_TOKEN/SUPABASE_URL/SUPABASE_SERVICE_KEY required" };
  }

  const user = verifyTelegram(initData, BOT_TOKEN);
  if (!user) return { statusCode: 401, body: "Bad Telegram signature" };

  const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

  const tg_id = user.id;
  if (action === "pull") {
    const { data, error } = await supabase.from("user_state").select("*").eq("tg_id", tg_id).single();
    if (error && error.code !== "PGRST116") return { statusCode: 500, body: error.message };
    return { statusCode: 200, body: JSON.stringify(data || { tg_id, pairs:[], known:[], counters:{} }) };
  }

  if (action === "push") {
    if (event.httpMethod !== "POST") return { statusCode: 405, body: "POST only" };
    const incoming = JSON.parse(event.body||"{}");
    const payload = {
      tg_id,
      username: user.username||null,
      first_name: user.first_name||null,
      last_name: user.last_name||null,
      pairs: incoming.pairs||[],
      known: incoming.known||[],
      counters: incoming.counters||{},
      updated_at: new Date().toISOString()
    };
    const { error } = await supabase.from("user_state").upsert(payload);
    if (error) return { statusCode: 500, body: error.message };
    return { statusCode: 200, body: JSON.stringify({ ok:true }) };
  }

  return { statusCode: 400, body: "Unknown action" };
}
