// netlify/functions/sync.js
// Node 18+, ESM. Проверка Telegram WebAppData + Supabase pull/push.
// ВАЖНО: в Netlify задать env: BOT_TOKEN, SUPABASE_URL, SUPABASE_SERVICE_KEY

import crypto from "crypto";

const headers = {
  "Content-Type": "application/json; charset=utf-8",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
  // чтобы фронт мог передавать подпись Telegram:
  "Access-Control-Allow-Headers": "Content-Type, x-telegram-init-data",
};

const json = (code, body) => ({
  statusCode: code,
  headers,
  body: JSON.stringify(body),
});

export async function handler(event) {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers, body: "" };
  }

  const url = new URL(event.rawUrl);
  const action = url.searchParams.get("action");

  // env
  const { BOT_TOKEN, SUPABASE_URL, SUPABASE_SERVICE_KEY } = process.env;
  if (!BOT_TOKEN || !SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    return json(500, { error: "Env BOT_TOKEN / SUPABASE_URL / SUPABASE_SERVICE_KEY required" });
  }

  // healthcheck без подписи
  if (action === "ping") return json(200, { ok: true });

  // подпись WebAppData
  const initData = event.headers["x-telegram-init-data"] || "";
  const user = verifyTelegram(initData, BOT_TOKEN);
  if (!user) return json(401, { error: "Bad Telegram signature" });

  try {
    if (action === "pull") {
      // ЧИТАЕМ из VIEW: user_state_v (tg_id приведён к тексту)
      const row = await sGet(SUPABASE_URL, SUPABASE_SERVICE_KEY, user.id);
      return json(200, row || { tg_id: user.id, pairs: [], known: [], counters: {} });
    }

    if (action === "push") {
      if (event.httpMethod !== "POST") return json(405, { error: "POST only" });
      const incoming = JSON.parse(event.body || "{}");

      const payload = {
        tg_id: user.id,                           // записываем как есть в таблицу user_state
        username: user.username ?? null,
        first_name: user.first_name ?? null,
        last_name: user.last_name ?? null,
        pairs: incoming.pairs ?? [],
        known: incoming.known ?? [],
        counters: incoming.counters ?? {},
        updated_at: new Date().toISOString(),
      };

      const saved = await sUpsert(SUPABASE_URL, SUPABASE_SERVICE_KEY, payload);
      return json(200, { ok: true, saved });
    }

    return json(400, { error: "Unknown action" });
  } catch (e) {
    return json(500, { error: e?.message || String(e) });
  }
}

// --- Telegram WebAppData verify (RFC от Telegram) --------------------------
function verifyTelegram(initData, botToken) {
  if (!initData) return null;

  const params = new URLSearchParams(initData);
  const hash = params.get("hash");
  if (!hash) return null;
  params.delete("hash");

  const dataCheckString = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
  const sign = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
  if (sign !== hash) return null;

  const userStr = params.get("user");
  const authDate = Number(params.get("auth_date") || 0);
  if (!userStr) return null;
  // можно ограничить «свежесть» подписи, например 7 дней:
  if (Date.now() / 1000 - authDate > 86400 * 7) return null;

  try {
    return JSON.parse(userStr);
  } catch {
    return null;
  }
}

// --- Supabase helpers ------------------------------------------------------

// ВАЖНО: читаем из VIEW (tg_id уже текст, поле tg_id_s)
async function sGet(url, key, tg_id) {
  const endpoint = `${url}/rest/v1/user_state_v?tg_id_s=eq.${encodeURIComponent(String(tg_id))}&select=*`;
  const r = await fetch(endpoint, {
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      Accept: "application/json",
    },
  });

  if (r.status === 406) return null; // no rows
  if (!r.ok) {
    const t = await r.text();
    throw new Error(`Supabase select failed: ${r.status} ${t}`);
  }

  const arr = await r.json();
  if (!Array.isArray(arr) || arr.length === 0) return null;

  // Приведём к единому виду (возвращаем tg_id числом, если это число)
  const row = arr[0];
  // tg_id в VIEW текстовый; передадим наружу как есть (или можешь вернуть Number)
  return {
    tg_id: tg_id,
    username: row.username ?? null,
    first_name: row.first_name ?? null,
    last_name: row.last_name ?? null,
    pairs: row.pairs ?? [],
    known: row.known ?? [],
    counters: row.counters ?? {},
    updated_at: row.updated_at ?? null,
  };
}

// Пишем в ТАБЛИЦУ user_state (merge-duplicates)
async function sUpsert(url, key, row) {
  const r = await fetch(`${url}/rest/v1/user_state`, {
    method: "POST",
    headers: {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=representation",
    },
    body: JSON.stringify([row]),
  });

  if (!r.ok) {
    const t = await r.text();
    throw new Error(`Supabase upsert failed: ${r.status} ${t}`);
  }

  const out = await r.json();
  return out?.[0] || row;
}
