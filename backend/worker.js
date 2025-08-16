// RUMAT backend: login + content (GET/PUT) + CORS + session cookie + KV
const JSON_TYPE = { "content-type": "application/json; charset=utf-8" };

function cors(origin) {
  return {
    "access-control-allow-origin": origin || "*",
    "access-control-allow-credentials": "true",
    "access-control-allow-headers": "content-type, authorization",
    "access-control-allow-methods": "GET,PUT,POST,OPTIONS",
  };
}
function getCookie(req, name) {
  const h = req.headers.get("cookie") || "";
  return ("; " + h).split("; " + name + "=").pop().split(";").shift();
}
async function requireSession(env, req) {
  const sid = getCookie(req, "sid");
  if (!sid) return false;
  const ok = await env.SESSIONS.get(`S:${sid}`);
  return !!ok;
}
async function setSession(env, ttlSec = 7 * 24 * 3600) {
  const sid = crypto.randomUUID();
  await env.SESSIONS.put(`S:${sid}`, "1", { expirationTtl: ttlSec });
  return sid;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const origin = env.ALLOWED_ORIGIN || "*";
    const headers = { ...cors(origin) };

    if (req.method === "OPTIONS") return new Response(null, { headers });

    if (url.pathname === "/api/login" && req.method === "POST") {
      try {
        const { password } = await req.json();
        if (!password || password !== env.ADMIN_PASSWORD) {
          return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), { status: 401, headers: { ...headers, ...JSON_TYPE } });
        }
        const sid = await setSession(env);
        const resp = new Response(JSON.stringify({ ok: true }), { headers: { ...headers, ...JSON_TYPE } });
        resp.headers.append("set-cookie", `sid=${sid}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${7 * 24 * 3600}`);
        return resp;
      } catch {
        return new Response(JSON.stringify({ ok: false, error: "bad_request" }), { status: 400, headers: { ...headers, ...JSON_TYPE } });
      }
    }

    if (url.pathname === "/api/logout" && req.method === "POST") {
      const resp = new Response(JSON.stringify({ ok: true }), { headers: { ...headers, ...JSON_TYPE } });
      resp.headers.append("set-cookie", `sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`);
      return resp;
    }

    if (url.pathname === "/api/content" && req.method === "GET") {
      const raw = (await env.CONTENT.get("site")) || "{}";
      return new Response(raw, { headers: { ...headers, ...JSON_TYPE } });
    }

    if (url.pathname === "/api/content" && req.method === "PUT") {
      const authed = await requireSession(env, req);
      if (!authed) {
        return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), { status: 401, headers: { ...headers, ...JSON_TYPE } });
      }
      const body = await req.text();
      try { JSON.parse(body); } catch {
        return new Response(JSON.stringify({ ok:false, error:"invalid_json" }), { status:400, headers:{...headers, ...JSON_TYPE} });
      }
      await env.CONTENT.put("site", body);
      return new Response(JSON.stringify({ ok: true }), { headers: { ...headers, ...JSON_TYPE } });
    }

    return new Response("Not found", { status: 404, headers });
  }
}
