const DISCORD_API = "https://discord.com/api/v10";
const COOKIE = "abyss_session";
const STATE_COOKIE = "abyss_oauth_state";
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

function cors(request, env) {
  const origin = request.headers.get("Origin");
  const allowed = env.ALLOWED_ORIGIN;
  if (!origin || origin !== allowed) return null;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
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
      const callback = new URL("/callback", url.origin);
      const authorize = new URL(DISCORD_API + "/oauth2/authorize");
      authorize.search = new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        redirect_uri: env.DISCORD_REDIRECT_URI,
        response_type: "code",
        scope: "identify guilds.members.read",
        state
      }).toString();
      return new Response(null, { status: 302, headers: {
        Location: authorize.toString(),
        "Set-Cookie": cookie(STATE_COOKIE, state, 600),
        "Cache-Control": "no-store"
      }});
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
        return new Response(null, { status: 302, headers: {
          Location: env.ALLOWED_ORIGIN,
          "Set-Cookie": cookie(COOKIE, session, 3600) + "\nSet-Cookie: " + cookie(STATE_COOKIE, "", 0),
          "Cache-Control": "no-store",
          "Referrer-Policy": "no-referrer"
        }});
      } catch { return new Response("Discord sign-in failed. Please try again.", { status: 502 }); }
    }
    if (url.pathname === "/logout" && request.method === "POST") return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json", "Set-Cookie": cookie(COOKIE, "", 0) });
    if (url.pathname === "/me" && request.method === "GET") {
      const session = await unseal(cookieValue(request, COOKIE), env);
      if (!session) return response(request, env, JSON.stringify({ authenticated: false }), 200, { "Content-Type": "application/json" });
      try {
        const member = await discord("/users/@me/guilds/" + env.DISCORD_GUILD_ID + "/member", session.access_token);
        const canPublish = Array.isArray(member.roles) && member.roles.includes(env.POLICE_PATROL_ROLE_ID);
        return response(request, env, JSON.stringify({ authenticated: true, user: session.user, canPublish }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      } catch { return response(request, env, JSON.stringify({ authenticated: false, canPublish: false }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" }); }
    }
    if (url.pathname === "/publish" && request.method === "POST") {
      const origin = request.headers.get("Origin");
      if (origin !== env.ALLOWED_ORIGIN) return response(request, env, JSON.stringify({ error: "Invalid origin" }), 403, { "Content-Type": "application/json" });
      const session = await unseal(cookieValue(request, COOKIE), env);
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
