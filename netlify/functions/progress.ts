import type { Handler } from "@netlify/functions";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

// === ENV with aliases (to match your screenshot) ===
const SUPABASE_URL = (process.env.SUPABASE_URL || process.env.SUPABASE_URL_PUBLIC || "").trim();
const SUPABASE_SERVICE_ROLE = (process.env.SUPABASE_SERVICE_ROLE || process.env.SUPABASE_SERVICE_KEY || "").trim();
const TELEGRAM_BOT_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || process.env.BOT_TOKEN || "").trim();
const ALLOW_ORIGIN = (process.env.ALLOW_ORIGIN || "*").trim();

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE) {
  console.warn("[progress] Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE/SUPABASE_SERVICE_KEY envs");
}
if (!TELEGRAM_BOT_TOKEN) {
  console.warn("[progress] Missing TELEGRAM_BOT_TOKEN/BOT_TOKEN env — Telegram verification will fail in prod");
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE, {
  auth: { persistSession: false },
});

type StatKind = "cards" | "quiz" | "cheese" | "accent";

type EventItem =
  | { type: "stat"; payload: { kind: StatKind }; ts: number }
  | { type: "sync"; payload: { stats: Partial<Record<StatKind, number>> }; ts: number };

function ok(body: unknown, status = 200) {
  return {
    statusCode: status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": ALLOW_ORIGIN,
      "Access-Control-Allow-Headers": "Content-Type, X-Dev-User",
      "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
      Vary: "Origin",
    },
    body: JSON.stringify(body),
  };
}
const bad = (msg: string, status = 400) => ok({ error: msg }, status);

function verifyTelegramInitData(initData: string): { ok: boolean; userId?: number } {
  if (!initData) return { ok: false };
  const params = new URLSearchParams(initData);
  const hash = params.get("hash") || "";
  if (!hash) return { ok: false };

  const pairs: string[] = [];
  params.forEach((v, k) => {
    if (k !== "hash") pairs.push(`${k}=${v}`);
  });
  pairs.sort();
  const dataCheckString = pairs.join("\n");

  const secretKey = crypto
    .createHmac("sha256", "WebAppData")
    .update(TELEGRAM_BOT_TOKEN)
    .digest();
  const calcHash = crypto
    .createHmac("sha256", secretKey)
    .update(dataCheckString)
    .digest("hex");

  const isEqual = crypto.timingSafeEqual(Buffer.from(calcHash), Buffer.from(hash));
  if (!isEqual) return { ok: false };

  const ad = Number(params.get("auth_date") || "0") * 1000;
  if (!ad || Date.now() - ad > 2 * 24 * 60 * 60 * 1000) return { ok: false };

  const userJson = params.get("user");
  if (!userJson) return { ok: false };
  const user = JSON.parse(userJson);
  return { ok: true, userId: Number(user.id) };
}

function devUser(headers: Record<string, string | undefined>): number | undefined {
  const h = headers["x-dev-user"];
  if (!h) return undefined;
  const id = Number(h);
  return Number.isFinite(id) ? id : undefined;
}

async function upsertUserProfile(userId: number) {
  await supabase.from("users").upsert({ id: userId }).select().single();
}

async function applyEvents(userId: number, events: EventItem[]) {
  if (!events.length) return;
  const toLog = events.map((e) => ({
    user_id: userId,
    type: e.type === "stat" ? e.payload.kind : "sync",
    payload: e.payload,
    ts: new Date(e.ts).toISOString(),
  }));
  await supabase.from("events").insert(toLog).select();

  const today = new Date().toISOString().slice(0, 10);
  let inc = { cards: 0, quiz: 0, cheese: 0, accent: 0 } as Record<StatKind, number>;
  let sync: Partial<Record<StatKind, number>> | null = null;
  for (const e of events) {
    if (e.type === "stat") inc[e.payload.kind] += 1;
    else if (e.type === "sync") sync = e.payload.stats ?? null;
  }
  if (sync) {
    await supabase
      .from("progress")
      .upsert({
        user_id: userId,
        day: today,
        cards: sync.cards ?? 0,
        quiz: sync.quiz ?? 0,
        cheese: sync.cheese ?? 0,
        accent: sync.accent ?? 0,
      })
      .select();
  }
  if (Object.values(inc).some((v) => v > 0)) {
    await supabase.rpc("mnc_increment_progress", {
      p_user_id: userId,
      p_day: today,
      p_cards: inc.cards,
      p_quiz: inc.quiz,
      p_cheese: inc.cheese,
      p_accent: inc.accent,
    });
  }
}

const handler: Handler = async (ev) => {
  if (ev.httpMethod === "OPTIONS") return ok({});
  if (ev.httpMethod === "GET") return ok({ ok: true, ping: "pong" });
  if (ev.httpMethod !== "POST") return bad("Method not allowed", 405);

  const hdrs = Object.fromEntries(
    Object.entries(ev.headers).map(([k, v]) => [k.toLowerCase(), v])
  );

  let body: any = {};
  try {
    body = JSON.parse(ev.body || "{}");
  } catch {
    return bad("Invalid JSON");
  }

  let userId: number | undefined;
  if (body.initData) {
    const v = verifyTelegramInitData(body.initData);
    if (!v.ok) return bad("Invalid Telegram initData", 401);
    userId = v.userId;
  } else {
    userId = devUser(hdrs);
  }
  if (!userId) return bad("No user", 401);

  const { op, events = [] } = body as { op: "batch"; events: EventItem[] };
  if (op !== "batch" || !Array.isArray(events)) return bad("Invalid op");

  try {
    await upsertUserProfile(userId);
  } catch (e) {
    console.warn("[progress] upsertUserProfile", e);
  }

  await applyEvents(userId, events);
  return ok({ ok: true, saved: events.length });
};

export { handler };
