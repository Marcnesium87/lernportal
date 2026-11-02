// Lernportal-API auf Cloudflare Workers + D1: Nutzer anlegen, anmelden, Fortschritt speichern.
// Die Seite selbst kommt aus dem Ordner public (Assets).

const MAX_USERS = 300;          // Schutz vor Missbrauch
const MAX_PROG = 40000;         // Zeichen im Fortschritt eines Nutzers
const MAX_TOKENS = 8;           // Geräte pro Nutzer
const HUES = [8, 28, 150, 190, 215, 265, 320];
const ORIGINS = [
  "https://marcnesium87.github.io",
  "http://127.0.0.1:8765",
  "http://localhost:8765",
];

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

function key(name) {
  return String(name || "").replace(/\s+/g, " ").trim().toLowerCase();
}
function cleanName(name) {
  const n = String(name || "").replace(/\s+/g, " ").trim();
  return n.length >= 1 && n.length <= 20 && !/[\u0000-\u001f<>]/.test(n) ? n : null;
}
async function pinHash(pin, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations: 20000 }, k, 256);
  return hex(bits);
}
async function sha256(s) {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
}
function randomHex(n) {
  return hex(crypto.getRandomValues(new Uint8Array(n)));
}

// Fortschritte zusammenführen: beste Werte, gefundene Begriffe vereinigen, neuester Stand gewinnt
function mergeProg(a, b) {
  const out = {};
  a = a || {}; b = b || {};
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[k] || {}, y = b[k] || {};
    const n = (y.at || 0) > (x.at || 0) ? y : x;
    const found = [...new Set([...(x.found || []), ...(y.found || [])])];
    const best = x.best == null ? (y.best == null ? null : y.best) : (y.best == null ? x.best : Math.max(x.best, y.best));
    out[k] = { best, tries: Math.max(x.tries || 0, y.tries || 0), cards: Math.max(x.cards || 0, y.cards || 0), last: n.last == null ? null : n.last, at: n.at || 0, found };
    // Vokabel-Stand (Lernen) kommt vom neueren Eintrag
    const vk = (y.at || 0) > (x.at || 0) ? (y.vk || x.vk) : (x.vk || y.vk);
    if (vk) out[k].vk = vk;
  }
  return out;
}

function cors(req) {
  const o = req.headers.get("Origin");
  const h = { "Vary": "Origin" };
  if (o && (ORIGINS.includes(o) || o === new URL(req.url).origin)) {
    h["Access-Control-Allow-Origin"] = o;
    h["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    h["Access-Control-Allow-Headers"] = "Content-Type";
    h["Access-Control-Max-Age"] = "86400";
  }
  return h;
}
function json(req, obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...cors(req) } });
}

async function newToken(env, nameKey) {
  const token = randomHex(24);
  await env.DB.prepare("INSERT INTO tokens (token_hash, name_key, created_at) VALUES (?, ?, ?)").bind(await sha256(token), nameKey, Date.now()).run();
  // alte Geräte-Anmeldungen aufräumen
  await env.DB.prepare("DELETE FROM tokens WHERE name_key = ? AND token_hash NOT IN (SELECT token_hash FROM tokens WHERE name_key = ? ORDER BY created_at DESC LIMIT ?)").bind(nameKey, nameKey, MAX_TOKENS).run();
  return token;
}
async function userByToken(env, token) {
  if (typeof token !== "string" || !/^[0-9a-f]{48}$/.test(token)) return null;
  const t = await env.DB.prepare("SELECT name_key FROM tokens WHERE token_hash = ?").bind(await sha256(token)).first();
  if (!t) return null;
  return await env.DB.prepare("SELECT * FROM users WHERE name_key = ?").bind(t.name_key).first();
}
const okUser = (u, token) => ({ ok: true, name: u.name, hue: u.hue, token, prog: JSON.parse(u.prog || "{}") });

async function register(env, body) {
  const name = cleanName(body.name), pin = String(body.pin || "");
  if (!name) return { error: "name" };
  if (!/^\d{4,6}$/.test(pin)) return { error: "pin" };
  const k = key(name);
  if (await env.DB.prepare("SELECT 1 FROM users WHERE name_key = ?").bind(k).first()) return { error: "exists" };
  const { n } = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
  if (n >= MAX_USERS) return { error: "full" };
  const salt = randomHex(12), hue = HUES[n % HUES.length];
  try {
    await env.DB.prepare("INSERT INTO users (name_key, name, hue, pin_hash, pin_salt, prog, created_at) VALUES (?, ?, ?, ?, ?, '{}', ?)")
      .bind(k, name, hue, await pinHash(pin, salt), salt, Date.now()).run();
  } catch (e) { return { error: "exists" }; }
  return okUser({ name, hue, prog: "{}" }, await newToken(env, k));
}

async function login(env, body) {
  const k = key(body.name), pin = String(body.pin || "");
  const u = await env.DB.prepare("SELECT * FROM users WHERE name_key = ?").bind(k).first();
  if (!u) return { error: "wrong" };
  if (u.locked_until > Date.now()) return { error: "locked" };
  if (u.pin_hash === (await pinHash(pin, u.pin_salt))) {
    if (u.fails > 0) await env.DB.prepare("UPDATE users SET fails = 0, locked_until = 0 WHERE name_key = ?").bind(k).run();
    return okUser(u, await newToken(env, k));
  }
  const fails = u.fails + 1;
  await env.DB.prepare("UPDATE users SET fails = ?, locked_until = ? WHERE name_key = ?")
    .bind(fails >= 5 ? 0 : fails, fails >= 5 ? Date.now() + 5 * 60 * 1000 : 0, k).run();
  return { error: fails >= 5 ? "locked" : "wrong" };
}

async function save(env, body) {
  const u = await userByToken(env, body.token);
  if (!u) return { error: "auth" };
  const p = body.prog;
  if (!p || typeof p !== "object" || Array.isArray(p) || JSON.stringify(p).length > MAX_PROG) return { error: "data" };
  const merged = mergeProg(JSON.parse(u.prog || "{}"), p);
  const text = JSON.stringify(merged);
  if (text.length > MAX_PROG) return { error: "data" };
  await env.DB.prepare("UPDATE users SET prog = ? WHERE name_key = ?").bind(text, u.name_key).run();
  return { ok: true, prog: merged };
}

async function logout(env, body) {
  if (typeof body.token === "string") await env.DB.prepare("DELETE FROM tokens WHERE token_hash = ?").bind(await sha256(body.token)).run();
  return { ok: true };
}

async function remove(env, body) {
  const u = await userByToken(env, body.token);
  if (!u) return { error: "auth" };
  await env.DB.batch([
    env.DB.prepare("DELETE FROM tokens WHERE name_key = ?").bind(u.name_key),
    env.DB.prepare("DELETE FROM users WHERE name_key = ?").bind(u.name_key),
  ]);
  return { ok: true };
}

const ROUTES = { "/api/register": register, "/api/login": login, "/api/save": save, "/api/logout": logout, "/api/delete": remove };

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(req);
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors(req) });
    const fn = ROUTES[url.pathname];
    if (req.method !== "POST" || !fn) return json(req, { error: "not_found" }, 404);
    let body;
    try { body = await req.json(); } catch (e) { return json(req, { error: "data" }, 400); }
    if (!body || typeof body !== "object") return json(req, { error: "data" }, 400);
    try {
      return json(req, await fn(env, body));
    } catch (e) {
      return json(req, { error: "server" }, 500);
    }
  },
};
