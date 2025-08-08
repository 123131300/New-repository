// netlify/functions/sync.js
import crypto from "crypto";

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, x-telegram-init-data",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS"
};

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };

  const action = new URL(event.rawUrl).searchParams.get("action"); // pull | push | ping
  const initData = event.headers["x-telegram-init-data"] || "";

  const { BOT_TOKEN, SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
  if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return resp(500, { error: "Env BOT_TOKEN / SUPABASE_URL / SUPABASE_SERVICE_KEY required" });
  }

  if (action === "ping") return resp(200, { ok: true });

  const user = verifyTelegram(initData, BOT_TOKEN);
  if (!user) return resp(401, { error: "Bad Telegram signature" });

  // ... остальная логика pull/push как была ...
  return resp(200, { ok: true, user: { id: user.id, username: user.username || null } });
}

function resp(code, body) {
  return { statusCode: code, headers, body: JSON.stringify(body) };
}

/**
 * ВЕРНАЯ проверка подписи ДЛЯ TELEGRAM WEB APP.
 * secretKey = HMAC_SHA256("WebAppData", bot_token)
 * signature = HMAC_SHA256(secretKey, data_check_string)
 */
function verifyTelegram(initData, botToken) {
  if (!initData) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  // 👇 ключ для WebApp
  const secretKey = crypto.createHmac("sha256", "WebAppData")
    .update(botToken)
    .digest();

  const sign = crypto.createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  if (sign !== hash) return null;

  const userStr = params.get("user");
  const authDate = Number(params.get("auth_date") || 0);
  if (!userStr) return null;
  if (Date.now() / 1000 - authDate > 86400 * 7) return null; // TTL 7 дней

  try { return JSON.parse(userStr); } catch { return null; }
}
