const DISCORD_API = "https://discord.com/api/v10";
const COOKIE = "abyss_session";
const STATE_COOKIE = "abyss_oauth_state";
const RETURN_COOKIE = "abyss_return_to";
const SHOTCALLER_ROLE_ID = "1558500349835354242";
const SESSION_VIEWER_ROLE_ID = "1558147579529797705";
const SESSION_MARK_TYPES = new Set(["danger","star","diamond","dot","safe","navyLine","redLine"]);
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

function cors(request, env) {
  const origin = request.headers.get("Origin");
  // Always allow the canonical GitHub Pages frontend, even if the Worker variable is misconfigured.
  const allowedOrigins = new Set(["https://callmequack.github.io", env.ALLOWED_ORIGIN].filter(Boolean));
  if (!origin || !allowedOrigins.has(origin)) return null;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin"
  };
}
function response(request, env, body, status = 200, extra = {}) {
  const headers = cors(request, env);
  if (!headers) return new Response("Origin not allowed", { status: 403 });
  return new Response(body, { status, headers: { ...headers, ...extra } });
}
function cookieValue(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const item = raw.split(";").map(x => x.trim()).find(x => x.startsWith(name + "="));
  return item ? item.slice(name.length + 1) : "";
}
function b64url(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function unb64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  s += "=".repeat((4 - s.length % 4) % 4);
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
}
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}
async function seal(data, env) {
  const body = b64url(new TextEncoder().encode(JSON.stringify(data)));
  return body + "." + await sign(body, env.SESSION_SECRET);
}
async function unseal(value, env) {
  try {
    const [body, signature] = value.split(".");
    if (!body || !signature || await sign(body, env.SESSION_SECRET) !== signature) return null;
    const data = JSON.parse(new TextDecoder().decode(unb64url(body)));
    if (!data.exp || data.exp < Date.now() || !data.access_token) return null;
    return data;
  } catch { return null; }
}
function randomCode(bytes = 12) {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const raw = crypto.getRandomValues(new Uint8Array(bytes));
  let out = "";
  for (const b of raw) out += alphabet[b % alphabet.length];
  return out.match(/.{1,4}/g).join("-");
}
async function hashCode(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(value || "").replace(/-/g, "").toUpperCase()));
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");
}
function cookie(name, value, maxAge) {
  return name + "=" + value + "; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=" + maxAge;
}
async function discord(path, token) {
  const r = await fetch(DISCORD_API + path, { headers: { Authorization: "Bearer " + token } });
  if (!r.ok) throw new Error("Discord API returned " + r.status);
  return r.json();
}
async function exchangeCode(code, env, requestUrl) {
  const body = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: env.DISCORD_REDIRECT_URI
  });
  const r = await fetch(DISCORD_API + "/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  if (!r.ok) throw new Error("Discord OAuth token exchange failed");
  return r.json();
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      const headers = cors(request, env);
      return headers ? new Response(null, { status: 204, headers }) : new Response("Origin not allowed", { status: 403 });
    }
    if (url.pathname === "/health" && request.method === "GET") return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json" });
    if (url.pathname === "/login" && request.method === "GET") {
      const state = crypto.randomUUID();
      const requestedReturn = url.searchParams.get("return_to") || env.ALLOWED_ORIGIN;
      let returnTo = env.ALLOWED_ORIGIN;
      try { const candidate = new URL(requestedReturn); if (candidate.origin === env.ALLOWED_ORIGIN && candidate.pathname.startsWith("/Abyss-watch/")) returnTo = candidate.href; } catch {}
      const callback = new URL("/callback", url.origin);
      const authorize = new URL(DISCORD_API + "/oauth2/authorize");
      authorize.search = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        redirect_uri: env.DISCORD_REDIRECT_URI,
        response_type: "code",
        scope: "identify guilds.members.read",
        state
      }).toString();
      const headers = new Headers({ Location: authorize.toString(), "Cache-Control": "no-store" });
      headers.append("Set-Cookie", cookie(STATE_COOKIE, state, 600));
      headers.append("Set-Cookie", cookie(RETURN_COOKIE, encodeURIComponent(returnTo), 600));
      return new Response(null, { status: 302, headers });
    }
    if (url.pathname === "/callback" && request.method === "GET") {
      const state = url.searchParams.get("state") || "";
      if (!state || state !== cookieValue(request, STATE_COOKIE)) return new Response("Invalid OAuth state. Please restart login.", { status: 400 });
      if (url.searchParams.get("error")) return new Response("Discord login was cancelled.", { status: 400 });
      const code = url.searchParams.get("code");
      if (!code) return new Response("Missing OAuth code.", { status: 400 });
      try {
        const token = await exchangeCode(code, env, url);
        const user = await discord("/users/@me", token.access_token);
        const session = await seal({ access_token: token.access_token, user: { id: user.id, username: user.username, global_name: user.global_name }, exp: Date.now() + Math.min(token.expires_in || 3600, 3600) * 1000 }, env);
        let returnTo = env.ALLOWED_ORIGIN;
        try { const saved = decodeURIComponent(cookieValue(request, RETURN_COOKIE)); const candidate = new URL(saved); if (candidate.origin === env.ALLOWED_ORIGIN && candidate.pathname.startsWith("/Abyss-watch/")) returnTo = candidate.href; } catch {}
        const headers = new Headers({ Location: returnTo, "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" });
        headers.append("Set-Cookie", cookie(COOKIE, session, 3600));
        headers.append("Set-Cookie", cookie(STATE_COOKIE, "", 0));
        headers.append("Set-Cookie", cookie(RETURN_COOKIE, "", 0));
        return new Response(null, { status: 302, headers });
      } catch { return new Response("Discord sign-in failed. Please try again.", { status: 502 }); }
    }
    if (url.pathname === "/logout" && request.method === "POST") return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json", "Set-Cookie": cookie(COOKIE, "", 0) });
    if (url.pathname === "/me" && request.method === "GET") {
      const session = await getSession(request, env);
      if (!session) return response(request, env, JSON.stringify({ authenticated: false, canViewSessions: false, canShotcall: false }), 200, { "Content-Type": "application/json" });
      try {
        const member = await discord("/users/@me/guilds/" + env.DISCORD_GUILD_ID + "/member", session.access_token);
        const roles = Array.isArray(member.roles) ? member.roles : [];
        const canPublish = roles.includes(env.POLICE_PATROL_ROLE_ID);
        const canShotcall = roles.includes(SHOTCALLER_ROLE_ID);
        const canViewSessions = roles.includes(SESSION_VIEWER_ROLE_ID);
        return response(request, env, JSON.stringify({ authenticated: true, user: session.user, canPublish, canShotcall, canViewSessions }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      } catch { return response(request, env, JSON.stringify({ authenticated: false, canPublish: false, canViewSessions: false, canShotcall: false }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" }); }
    }
    if (url.pathname === "/sessions" && request.method === "POST") {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const visibility = body.visibility === "public" ? "public" : "private";
      const id = crypto.randomUUID() + "-" + crypto.randomUUID().replace(/-/g, "");
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const ownerKey = visibility === "private" ? randomCode(32) : null;
      const viewerCode = visibility === "private" ? randomCode(12) : null;
      const shotcallerCode = visibility === "private" ? randomCode(12) : null;
      const created = await stub.fetch("https://session.internal/init", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ createdBy: null, createdAt: Date.now(), visibility }) });
      if (!created.ok) return response(request, env, JSON.stringify({ error: "Could not create the live session." }), 500, { "Content-Type": "application/json" });
      if (visibility === "private") {
        const saved = await stub.fetch("https://session.internal/auth-init", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ownerHash: await hashCode(ownerKey), viewerHash: await hashCode(viewerCode), shotcallerHash: await hashCode(shotcallerCode) }) });
        if (!saved.ok) return response(request, env, JSON.stringify({ error: "Could not secure session codes." }), 500, { "Content-Type": "application/json" });
      }
      return response(request, env, JSON.stringify({ ok: true, id, visibility, ...(visibility === "private" ? { ownerKey, viewerCode, shotcallerCode } : {}) }), 201, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    const codeMatch = url.pathname.match(/^\\/sessions\\/([a-f0-9-]{60,80})\\/codes$/i);
    if (codeMatch && request.method === "POST") {
      const id = codeMatch[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const ownerKey = request.headers.get("X-Owner-Key") || "";
      const auth = await stub.fetch("https://session.internal/auth-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ownerHash: await hashCode(ownerKey) }) });
      if (!auth.ok) return response(request, env, JSON.stringify({ error: "Only the session owner can rotate invitation codes." }), 403, { "Content-Type": "application/json" });
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const kind = body.kind === "viewer" ? "viewer" : body.kind === "shotcaller" ? "shotcaller" : "";
      if (!kind) return response(request, env, JSON.stringify({ error: "Choose viewer or shotcaller code." }), 400, { "Content-Type": "application/json" });
      const code = randomCode(12);
      const changed = await stub.fetch("https://session.internal/auth-rotate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind, hash: await hashCode(code) }) });
      if (!changed.ok) return response(request, env, JSON.stringify({ error: "Could not rotate the invitation code." }), 500, { "Content-Type": "application/json" });
      return response(request, env, JSON.stringify({ ok: true, kind, code }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    const sessionMatchAny = url.pathname.match(/^\\/sessions\\/([a-f0-9-]{60,80})(?:\\/codes)?$/i);
    if (sessionMatchAny && request.method === "GET" && !url.pathname.endsWith("/codes")) {
      const id = sessionMatchAny[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const result = await stub.fetch("https://session.internal/state");
      const raw = await result.text();
      if (!result.ok) return response(request, env, raw, result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      let data;
      try { data = JSON.parse(raw); } catch { return response(request, env, JSON.stringify({ error: "Invalid session state." }), 500, { "Content-Type": "application/json" }); }
      if (data.visibility !== "public") {
        const supplied = request.headers.get("X-Session-Code") || "";
        const ownerKey = request.headers.get("X-Owner-Key") || "";
        const checked = await stub.fetch("https://session.internal/auth-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ codeHash: await hashCode(supplied), ownerHash: await hashCode(ownerKey) }) });
        if (!checked.ok) return response(request, env, JSON.stringify({ error: "Enter a valid viewer or shotcaller code to access this private session." }), 401, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      }
      return response(request, env, JSON.stringify(data), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    if (sessionMatchAny && request.method === "PUT") {
      const id = sessionMatchAny[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const currentResponse = await stub.fetch("https://session.internal/state");
      if (!currentResponse.ok) return response(request, env, JSON.stringify({ error: "Session not found." }), 404, { "Content-Type": "application/json" });
      const current = await currentResponse.json();
      let canEdit = current.visibility === "public";
      if (current.visibility !== "public") {
        const supplied = request.headers.get("X-Session-Code") || "";
        const ownerKey = request.headers.get("X-Owner-Key") || "";
        const checked = await stub.fetch("https://session.internal/auth-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ codeHash: await hashCode(supplied), ownerHash: await hashCode(ownerKey) }) });
        if (!checked.ok) return response(request, env, JSON.stringify({ error: "Enter a valid shotcaller code to edit this private session." }), 401, { "Content-Type": "application/json" });
        const perms = await checked.json();
        canEdit = perms.owner === true || perms.role === "shotcaller";
        if (!canEdit) return response(request, env, JSON.stringify({ error: "Viewer codes cannot edit markers. Enter the shotcaller code." }), 403, { "Content-Type": "application/json" });
      }
      let body;
      try { body = await request.json(); } catch { return response(request, env, JSON.stringify({ error: "Invalid JSON body." }), 400, { "Content-Type": "application/json" }); }
      if (!Array.isArray(body.marks) || body.marks.length > 500) return response(request, env, JSON.stringify({ error: "Map must contain 500 markers or fewer." }), 400, { "Content-Type": "application/json" });
      const marks = [];
      for (const m of body.marks) {
        if (!m || !SESSION_MARK_TYPES.has(m.type) || !Number.isFinite(m.x) || !Number.isFinite(m.y) || m.x < 0 || m.x > 1200 || m.y < 0 || m.y > 760) return response(request, env, JSON.stringify({ error: "Invalid marker data." }), 400, { "Content-Type": "application/json" });
        const line = m.type === "navyLine" || m.type === "redLine";
        if (line && (!Number.isFinite(m.x2) || !Number.isFinite(m.y2) || m.x2 < 0 || m.x2 > 1200 || m.y2 < 0 || m.y2 > 760)) return response(request, env, JSON.stringify({ error: "Invalid line endpoint." }), 400, { "Content-Type": "application/json" });
        marks.push({ x: m.x, y: m.y, ...(line ? { x2: m.x2, y2: m.y2 } : {}), r: Number.isFinite(m.r) ? Math.max(4, Math.min(150, m.r)) : 48, size: Number.isFinite(m.size) ? Math.max(4, Math.min(150, m.size)) : 48, type: m.type });
      }
      const result = await stub.fetch("https://session.internal/state", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ marks, updatedAt: Date.now(), updatedBy: canEdit ? "Shotcaller" : "Public link user" }) });
      return response(request, env, await result.text(), result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
        if (url.pathname === "/publish" && request.method === "POST") {
      const origin = request.headers.get("Origin");
      if (origin !== env.ALLOWED_ORIGIN) return response(request, env, JSON.stringify({ error: "Invalid origin" }), 403, { "Content-Type": "application/json" });
      const session = await getSession(request, env);
      if (!session) return response(request, env, JSON.stringify({ error: "Sign in with Discord first." }), 401, { "Content-Type": "application/json" });
      try {
        const member = await discord("/users/@me/guilds/" + env.DISCORD_GUILD_ID + "/member", session.access_token);
        if (!Array.isArray(member.roles) || !member.roles.includes(env.POLICE_PATROL_ROLE_ID)) return response(request, env, JSON.stringify({ error: "Police Patrol role required." }), 403, { "Content-Type": "application/json" });
      } catch { return response(request, env, JSON.stringify({ error: "Could not verify your Discord server membership." }), 403, { "Content-Type": "application/json" }); }
      const form = await request.formData();
      const image = form.get("image");
      const title = String(form.get("title") || "Abyss danger report").slice(0, 100);
      const note = String(form.get("note") || "").slice(0, 1500);
      if (!(image instanceof File) || !image.type.startsWith("image/")) return response(request, env, JSON.stringify({ error: "Attach a map image." }), 400, { "Content-Type": "application/json" });
      if (image.size > MAX_IMAGE_BYTES) return response(request, env, JSON.stringify({ error: "Image must be 8 MB or smaller." }), 413, { "Content-Type": "application/json" });
      const discordForm = new FormData();
      discordForm.set("payload_json", JSON.stringify({ content: note ? "**" + title + "**\n" + note : "**" + title + "**", allowed_mentions: { parse: [] } }));
      discordForm.set("files[0]", image, "abyss-danger-map.png");
      const sent = await fetch(env.DISCORD_WEBHOOK_URL, { method: "POST", body: discordForm });
      if (!sent.ok) return response(request, env, JSON.stringify({ error: "Discord could not accept the report." }), 502, { "Content-Type": "application/json" });
      return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json" });
    }
    return response(request, env, JSON.stringify({ error: "Not found" }), 404, { "Content-Type": "application/json" });
  }
};

export class LiveSession {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/auth-init" && request.method === "POST") {
      if (await this.state.storage.get("sessionAuth")) return new Response("Already initialized", { status: 409 });
      let data;
      try { data = await request.json(); } catch { return new Response("Invalid body", { status: 400 }); }
      if (!data.ownerHash || !data.viewerHash || !data.shotcallerHash) return new Response("Missing hashes", { status: 400 });
      await this.state.storage.put("sessionAuth", { ownerHash: data.ownerHash, viewerHash: data.viewerHash, shotcallerHash: data.shotcallerHash });
      return Response.json({ ok: true });
    }
    if (url.pathname === "/auth-check" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const auth = await this.state.storage.get("sessionAuth");
      if (!auth) return new Response("Not configured", { status: 404 });
      if (data.ownerHash && data.ownerHash === auth.ownerHash) return Response.json({ owner: true, role: "owner" });
      if (data.codeHash && data.codeHash === auth.shotcallerHash) return Response.json({ owner: false, role: "shotcaller" });
      if (data.codeHash && data.codeHash === auth.viewerHash) return Response.json({ owner: false, role: "viewer" });
      return new Response("Forbidden", { status: 403 });
    }
    if (url.pathname === "/auth-rotate" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const auth = await this.state.storage.get("sessionAuth");
      if (!auth || !["viewer", "shotcaller"].includes(data.kind) || !data.hash) return new Response("Invalid rotation", { status: 400 });
      auth[data.kind + "Hash"] = data.hash;
      await this.state.storage.put("sessionAuth", auth);
      return Response.json({ ok: true });
    }
    if (url.pathname === "/init" && request.method === "POST") {
      const current = await this.state.storage.get("session");
      if (current) return new Response(JSON.stringify({ error: "Already initialized" }), { status: 409 });
      let data = {};
      try { data = await request.json(); } catch {}
      await this.state.storage.put("session", { marks: [], visibility: data.visibility === "public" ? "public" : "private", createdAt: data.createdAt || Date.now(), createdBy: data.createdBy || null, updatedAt: Date.now(), updatedBy: null });
      return Response.json({ ok: true });
    }
    if (url.pathname === "/state" && request.method === "GET") {
      const data = await this.state.storage.get("session");
      if (!data) return Response.json({ error: "Session not found" }, { status: 404 });
      return Response.json(data, { headers: { "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/state" && request.method === "PUT") {
      const old = await this.state.storage.get("session");
      if (!old) return Response.json({ error: "Session not found" }, { status: 404 });
      let update;
      try { update = await request.json(); } catch { return Response.json({ error: "Invalid body" }, { status: 400 }); }
      const next = { ...old, marks: update.marks, updatedAt: update.updatedAt || Date.now(), updatedBy: update.updatedBy || null };
      await this.state.storage.put("session", next);
      return Response.json({ ok: true, updatedAt: next.updatedAt });
    }
    return new Response("Not found", { status: 404 });
  }
}
