const FRONTEND_ORIGIN = "https://callmequack.github.io";
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;
const SESSION_MARK_TYPES = new Set(["danger","star","diamond","dot","safe","navyLine","redLine"]);
const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

function cors(request, env) {
  const origin = request.headers.get("Origin");
  // Always allow the canonical GitHub Pages frontend, even if the Worker variable is misconfigured.
  const allowedOrigins = new Set(["https://callmequack.github.io", env.ALLOWED_ORIGIN].filter(Boolean));
  if (!origin || !allowedOrigins.has(origin)) return null;
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Session-Code, X-Owner-Key, X-Participant-Token, X-Publish-Code",
    "Vary": "Origin"
  };
}
function response(request, env, body, status = 200, extra = {}) {
  const headers = cors(request, env);
  if (!headers) return new Response("Origin not allowed", { status: 403 });
  return new Response(body, { status, headers: { ...headers, ...extra } });
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
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") {
      const headers = cors(request, env);
      return headers ? new Response(null, { status: 204, headers }) : new Response("Origin not allowed", { status: 403 });
    }
    if (url.pathname === "/health" && request.method === "GET") return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json" });
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
    const codeMatch = url.pathname.match(/^\/sessions\/([a-f0-9-]{60,80})\/codes$/i);
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
    const joinMatch = url.pathname.match(/^\/sessions\/([a-f0-9-]{60,80})\/join$/i);
    if (joinMatch && request.method === "POST") {
      const id = joinMatch[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const stateResponse = await stub.fetch("https://session.internal/state");
      if (!stateResponse.ok) return response(request, env, JSON.stringify({ error: "Session not found." }), 404, { "Content-Type": "application/json" });
      const state = await stateResponse.json();
      if (state.visibility === "public") return response(request, env, JSON.stringify({ error: "Public sessions do not need a code. Open the session link." }), 400, { "Content-Type": "application/json" });
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const name = String(body.name || "").trim().replace(/[<>]/g, "").slice(0, 32);
      const suppliedCode = String(body.code || "");
      if (!name) return response(request, env, JSON.stringify({ error: "Enter a display name." }), 400, { "Content-Type": "application/json" });
      if (name.length < 2) return response(request, env, JSON.stringify({ error: "Name must be at least 2 characters." }), 400, { "Content-Type": "application/json" });
      const ownerKey = String(body.ownerKey || "");
      const participantId = crypto.randomUUID();
      const token = randomCode(32);
      const joined = await stub.fetch("https://session.internal/join", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name, participantId, tokenHash: await hashCode(token), codeHash: await hashCode(suppliedCode), ownerHash: await hashCode(ownerKey), now: Date.now() }) });
      const joinedBody = await joined.json().catch(() => ({}));
      if (!joined.ok) return response(request, env, JSON.stringify({ error: joinedBody.error || "Invalid invitation code." }), joined.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      return response(request, env, JSON.stringify({ ok: true, id, token, participant: joinedBody.participant }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    const participantsMatch = url.pathname.match(/^\/sessions\/([a-f0-9-]{60,80})\/participants(?:\/([a-f0-9-]{36}))?$/i);
    if (participantsMatch && request.method === "GET") {
      const id = participantsMatch[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const token = request.headers.get("X-Participant-Token") || "";
      const checked = await stub.fetch("https://session.internal/participant-auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tokenHash: await hashCode(token), now: Date.now() }) });
      if (!checked.ok) return response(request, env, JSON.stringify({ error: "Your access has expired or been revoked. Rejoin with an invitation code." }), 401, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      const participant = await checked.json();
      if (participant.role !== "owner") return response(request, env, JSON.stringify({ error: "Only the session owner can view the participant list." }), 403, { "Content-Type": "application/json" });
      const result = await stub.fetch("https://session.internal/participants");
      return response(request, env, await result.text(), result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    if (participantsMatch && participantsMatch[2] && request.method === "PATCH") {
      const id = participantsMatch[1], targetId = participantsMatch[2];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const token = request.headers.get("X-Participant-Token") || "";
      const checked = await stub.fetch("https://session.internal/participant-auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tokenHash: await hashCode(token), now: Date.now() }) });
      if (!checked.ok || (await checked.json()).role !== "owner") return response(request, env, JSON.stringify({ error: "Only the session owner can change roles." }), 403, { "Content-Type": "application/json" });
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const result = await stub.fetch("https://session.internal/participant-role", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ participantId: targetId, role: body.role }) });
      return response(request, env, await result.text(), result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    if (participantsMatch && participantsMatch[2] && request.method === "DELETE") {
      const id = participantsMatch[1], targetId = participantsMatch[2];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const token = request.headers.get("X-Participant-Token") || "";
      const checked = await stub.fetch("https://session.internal/participant-auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tokenHash: await hashCode(token), now: Date.now() }) });
      if (!checked.ok || (await checked.json()).role !== "owner") return response(request, env, JSON.stringify({ error: "Only the session owner can revoke participants." }), 403, { "Content-Type": "application/json" });
      const result = await stub.fetch("https://session.internal/participant-revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ participantId: targetId }) });
      const revoked = await result.json().catch(() => ({}));
      if (!result.ok) return response(request, env, JSON.stringify(revoked), result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      let rotated = null;
      if (["viewer", "shotcaller"].includes(revoked.inviteKind)) {
        const code = randomCode(12);
        const changed = await stub.fetch("https://session.internal/auth-rotate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind: revoked.inviteKind, hash: await hashCode(code) }) });
        if (changed.ok) rotated = { kind: revoked.inviteKind, code };
      }
      return response(request, env, JSON.stringify({ ok: true, rotated }), 200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    }
    const sessionMatchAny = url.pathname.match(/^\/sessions\/([a-f0-9-]{60,80})(?:\/codes)?$/i);
    if (sessionMatchAny && request.method === "GET" && !url.pathname.endsWith("/codes")) {
      const id = sessionMatchAny[1];
      const stub = env.LIVE_SESSIONS.get(env.LIVE_SESSIONS.idFromName(id));
      const result = await stub.fetch("https://session.internal/state");
      const raw = await result.text();
      if (!result.ok) return response(request, env, raw, result.status, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      let data;
      try { data = JSON.parse(raw); } catch { return response(request, env, JSON.stringify({ error: "Invalid session state." }), 500, { "Content-Type": "application/json" }); }
      if (data.visibility !== "public") {
        const token = request.headers.get("X-Participant-Token") || "";
        const checked = await stub.fetch("https://session.internal/participant-auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tokenHash: await hashCode(token), now: Date.now() }) });
        if (!checked.ok) return response(request, env, JSON.stringify({ error: "Your access has expired or been revoked. Join with your name and invitation code." }), 401, { "Content-Type": "application/json", "Cache-Control": "no-store" });
        const access = await checked.json();
        data.accessRole = access.role;
        data.participantId = access.id;
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
        const token = request.headers.get("X-Participant-Token") || "";
        const checked = await stub.fetch("https://session.internal/participant-auth", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ tokenHash: await hashCode(token), now: Date.now() }) });
        if (!checked.ok) return response(request, env, JSON.stringify({ error: "Your access has expired or been revoked." }), 401, { "Content-Type": "application/json" });
        const perms = await checked.json();
        canEdit = perms.role === "owner" || perms.role === "shotcaller";
        if (!canEdit) return response(request, env, JSON.stringify({ error: "Your current role is read-only." }), 403, { "Content-Type": "application/json" });
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
      const suppliedCode = request.headers.get("X-Publish-Code") || "";
      const expectedCode = env.PUBLISH_CODE || "";
      if (!expectedCode) return response(request, env, JSON.stringify({ error: "Publishing is not configured on the server yet." }), 503, { "Content-Type": "application/json" });
      if (suppliedCode.length < 16 || suppliedCode !== expectedCode) return response(request, env, JSON.stringify({ error: "Invalid publishing code." }), 401, { "Content-Type": "application/json", "Cache-Control": "no-store" });
      const form = await request.formData();
      const image = form.get("image");
      const title = String(form.get("title") || "Abyss danger report").slice(0, 100);
      const note = String(form.get("note") || "").slice(0, 1500);
      if (!(image instanceof File) || !image.type.startsWith("image/")) return response(request, env, JSON.stringify({ error: "Attach a map image." }), 400, { "Content-Type": "application/json" });
      if (image.size > MAX_IMAGE_BYTES) return response(request, env, JSON.stringify({ error: "Image must be 8 MB or smaller." }), 413, { "Content-Type": "application/json" });
      const reportForm = new FormData();
      discordForm.set("payload_json", JSON.stringify({ content: note ? "**" + title + "**\n" + note : "**" + title + "**", allowed_mentions: { parse: [] } }));
      reportForm.set("files[0]", image, "abyss-danger-map.png");
      const sent = await fetch(env.DISCORD_WEBHOOK_URL, { method: "POST", body: reportForm });
      if (!sent.ok) return response(request, env, JSON.stringify({ error: "The report webhook could not accept the report." }), 502, { "Content-Type": "application/json" });
      return response(request, env, JSON.stringify({ ok: true }), 200, { "Content-Type": "application/json" });
    }
    return response(request, env, JSON.stringify({ error: "Not found" }), 404, { "Content-Type": "application/json" });
  }
};

export class LiveSession {
  constructor(state, env) { this.state = state; this.env = env; }
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/join" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const auth = await this.state.storage.get("sessionAuth");
      if (!auth) return Response.json({ error: "Session access is not configured." }, { status: 500 });
      let role = "";
      if (data.ownerHash && data.ownerHash === auth.ownerHash) role = "owner";
      else if (data.codeHash && data.codeHash === auth.shotcallerHash) role = "shotcaller";
      else if (data.codeHash && data.codeHash === auth.viewerHash) role = "viewer";
      if (!role) return Response.json({ error: "That invitation code is not valid." }, { status: 401 });
      const participants = await this.state.storage.get("participants") || {};
      const inviteKind = role === "owner" ? "owner" : role;
      const participant = { id: data.participantId, name: String(data.name || "Guest").slice(0, 32), role, inviteKind, tokenHash: data.tokenHash, joinedAt: data.now || Date.now(), lastSeen: data.now || Date.now() };
      participants[participant.id] = participant;
      await this.state.storage.put("participants", participants);
      return Response.json({ participant: { id: participant.id, name: participant.name, role: participant.role, joinedAt: participant.joinedAt, lastSeen: participant.lastSeen } });
    }
    if (url.pathname === "/participant-auth" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const participants = await this.state.storage.get("participants") || {};
      const found = Object.values(participants).find(p => p.tokenHash && p.tokenHash === data.tokenHash);
      if (!found) return Response.json({ error: "Access revoked." }, { status: 401 });
      found.lastSeen = data.now || Date.now();
      participants[found.id] = found;
      await this.state.storage.put("participants", participants);
      return Response.json({ id: found.id, name: found.name, role: found.role, joinedAt: found.joinedAt, lastSeen: found.lastSeen });
    }
    if (url.pathname === "/participants" && request.method === "GET") {
      const participants = await this.state.storage.get("participants") || {};
      const now = Date.now();
      const list = Object.values(participants).map(p => ({ id: p.id, name: p.name, role: p.role, joinedAt: p.joinedAt, lastSeen: p.lastSeen, online: now - (p.lastSeen || 0) < 20000 })).sort((a,b) => (a.role === "owner" ? -1 : b.role === "owner" ? 1 : a.name.localeCompare(b.name)));
      return Response.json({ participants: list }, { headers: { "Cache-Control": "no-store" } });
    }
    if (url.pathname === "/participant-role" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const participants = await this.state.storage.get("participants") || {};
      const target = participants[data.participantId];
      if (!target) return Response.json({ error: "Participant not found." }, { status: 404 });
      if (target.role === "owner") return Response.json({ error: "Owner permissions cannot be changed here." }, { status: 400 });
      if (!["viewer", "shotcaller"].includes(data.role)) return Response.json({ error: "Choose Viewer or Shotcaller." }, { status: 400 });
      target.role = data.role;
      participants[target.id] = target;
      await this.state.storage.put("participants", participants);
      return Response.json({ ok: true, participant: { id: target.id, name: target.name, role: target.role } });
    }
    if (url.pathname === "/participant-revoke" && request.method === "POST") {
      let data;
      try { data = await request.json(); } catch { data = {}; }
      const participants = await this.state.storage.get("participants") || {};
      const target = participants[data.participantId];
      if (!target) return Response.json({ error: "Participant not found." }, { status: 404 });
      if (target.role === "owner") return Response.json({ error: "Owner access cannot be revoked from the roster." }, { status: 400 });
      delete participants[target.id];
      await this.state.storage.put("participants", participants);
      return Response.json({ ok: true, inviteKind: target.inviteKind || (target.role === "shotcaller" ? "shotcaller" : "viewer") });
    }
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

