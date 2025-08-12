import type { Handler } from "@netlify/functions";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

// === ENV ===
const SUPABASE_URL = (process.env.SUPABASE_URL || process.env.SUPABASE_URL_PUBLIC || "").trim();
const SUPABASE_SERVICE_ROLE = (process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_SERVICE_KEY || "").trim();
const TELEGRAM_BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || process.env.BOT_TOKEN || "").trim();
const ALLOW_ORIGIN = (process.env.ALLOW_ORIGIN || "*").trim();

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, { auth: { persistSession: false } });

type StatKind = "cards" | "quiz" | "cheese" | "accent";

type EventItem =
  | { type: "stat"; payload: { kind: StatKind }; ts: number }
  | { type: "sync"; payload: { stats: Partial<Record<StatKind, number>> }; ts: number };

function resp(body: unknown, status = 200) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": ALLOW_ORIGIN,
      "Access-Control-Allow-Headers": "Content-Type, X-Dev-User, X-Dev-Username, X-Dev-FirstName",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      Vary: "Origin",
    },
    body: JSON.stringify(body),
  };
}
const bad = (msg: string, status = 400) => resp({ ok: false, error: msg }, status);

// --- Telegram initData verification ---
interface TgVerifyOk { ok: true; userId: number; username?: string; first_name?: string }
interface TgVerifyFail { ok: false; reason: string }

type TgVerify = TgVerifyOk | TgVerifyFail;

function verifyTelegramInitData(initData: string): TgVerify {
  if (!initData) return { ok: false, reason: "EMPTY" };
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  if (!hash) return { ok: false, reason: "NO_HASH" };

  const pairs: string[] = [];
  params.forEach((v, k) => {
    if (k !== "hash") pairs.push(`${k}=${v}`);
  });
  pairs.sort();
  const dataCheckString = pairs.join("\n");

  try {
    const secretKey = crypto.createHmac("sha256", "WebAppData").update(TELEGRAM_BOT_TOKEN).digest();
    const calcHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
    const isEqual = crypto.timingSafeEqual(Buffer.from(calcHash), Buffer.from(hash));
    if (!isEqual) return { ok: false, reason: "HASH_MISMATCH" };
  } catch (e) {
    return { ok: false, reason: "CRYPTO_FAIL" };
  }

  // allow long-lived sessions (<=30d) — не валим при истечении
  const userJson = params.get("user");
  if (!userJson) return { ok: false, reason: "NO_USER" };
  try {
    const user = JSON.parse(userJson);
    return { ok: true, userId: Number(user.id), username: user.username, first_name: user.first_name };
  } catch {
    return { ok: false, reason: "USER_PARSE" };
  }
}

function devUser(headers: Record<string, string | undefined>): { id?: number; username?: string; first_name?: string } {
  const idRaw = headers["x-dev-user"]; if (!idRaw) return {};
  const id = Number(idRaw); if (!Number.isFinite(id)) return {};
  return { id, username: headers["x-dev-username"], first_name: headers["x-dev-firstname"] };
}

async function upsertUserProfile(params: { id: number; username?: string; first_name?: string }) {
  const row: any = { id: params.id };
  if (params.username !== undefined) row.username = params.username;
  if (params.first_name !== undefined) row.first_name = params.first_name;
  const { error } = await supabase.from("users").upsert(row, { onConflict: "id" }).select().single();
  if (error) throw new Error("upsert users: " + error.message);
}

async function applyEvents(userId: number, events: EventItem[]) {
  if (!events.length) return { logged: 0, inc: { cards: 0, quiz: 0, cheese: 0, accent: 0 } };

  const toLog = events.map((e) => ({
    user_id: userId,
    type: e.type === "stat" ? e.payload.kind : "sync",
    payload: e.payload,
    ts: new Date(e.ts).toISOString(),
  }));
  const ins = await supabase.from("events").insert(toLog).select();
  if (ins.error) throw new Error("insert events: " + ins.error.message);

  const today = new Date().toISOString().slice(0, 10);
  let inc = { cards: 0, quiz: 0, cheese: 0, accent: 0 } as Record<StatKind, number>;
  let sync: Partial<Record<StatKind, number>> | null = null;
  for (const e of events) {
    if (e.type === "stat") inc[e.payload.kind] += 1;
    else if (e.type === "sync") sync = e.payload.stats ?? null;
  }
  if (sync) {
    const up = await supabase
      .from("progress")
      .upsert(
        { user_id: userId, day: today, cards: sync.cards ?? 0, quiz: sync.quiz ?? 0, cheese: sync.cheese ?? 0, accent: sync.accent ?? 0 },
        { onConflict: "user_id,day" }
      )
      .select();
    if (up.error) throw new Error("upsert progress: " + up.error.message);
  }
  if (Object.values(inc).some((v) => v > 0)) {
    const rpc = await supabase.rpc("mnc_increment_progress", {
      p_user_id: userId, p_day: today, p_cards: inc.cards, p_quiz: inc.quiz, p_cheese: inc.cheese, p_accent: inc.accent,
    });
    if (rpc.error) throw new Error("rpc mnc_increment_progress: " + rpc.error.message);
  }
  return { logged: toLog.length, inc };
}

const handler: Handler = async (ev) => {
  if (ev.httpMethod === "OPTIONS") return resp({});

  if (ev.httpMethod === "GET") {
    const op = ev.queryStringParameters?.op || "ping";
    if (op === "diag") {
      const can = !!SUPABASE_URL && !!SUPABASE_SERVICE_ROLE; let dbOk = false;
      if (can) { const t = await supabase.from("users").select("id", { count: "exact", head: true }); dbOk = !t.error; }
      return resp({ ok: true, env: { SUPABASE_URL: !!SUPABASE_URL, SUPABASE_SERVICE_ROLE: !!SUPABASE_SERVICE_ROLE, TELEGRAM_BOT_TOKEN: !!TELEGRAM_BOT_TOKEN }, dbOk });
    }
    if (op === "probe") {
      const sentinel = -9999;
      try { const ins = await supabase.from("users").upsert({ id: sentinel }).select(); const del = await supabase.from("users").delete().eq("id", sentinel); return resp({ ok: !ins.error && !del.error, insErr: ins.error?.message || null, delErr: del.error?.message || null }); } catch (e: any) { return bad("probe_failed: "+(e?.message||"unknown")); }
    }
    return resp({ ok: true, ping: "pong" });
  }

  if (ev.httpMethod !== "POST") return bad("Method not allowed", 405);

  const hdrs = Object.fromEntries(Object.entries(ev.headers).map(([k, v]) => [k.toLowerCase(), v]));

  let body: any = {}; try { body = JSON.parse(ev.body || "{}"); } catch { return bad("Invalid JSON"); }

  let userId: number | undefined; let username: string | undefined; let first_name: string | undefined;
  if (body.initData) {
    const v = verifyTelegramInitData(body.initData);
    if (!v.ok) return bad("Invalid Telegram initData: " + v.reason, 401);
    userId = v.userId; username = v.username; first_name = v.first_name;
  } else {
    const u = devUser(hdrs); userId = u.id; username = u.username; first_name = u.first_name;
  }
  if (!userId) return bad("No user", 401);

  const { op, events = [] } = body as { op: "batch"; events: EventItem[] };
  if (op !== "batch" || !Array.isArray(events)) return bad("Invalid op");

  try {
    await upsertUserProfile({ id: userId, username, first_name });
    const result = await applyEvents(userId, events);
    return resp({ ok: true, saved: result.logged, inc: result.inc });
  } catch (e: any) {
    console.error("/progress error", e?.message || e);
    return bad("DB_ERROR: " + (e?.message || "unknown"), 500);
  }
};

export { handler };
