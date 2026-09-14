// Same-origin reverse proxy for the backend API.
//
// The backend Container App is internal-only (no public ingress) — the
// browser can never reach it directly. This route runs server-side inside
// the UI container, which CAN reach it via BACKEND_URL (the internal FQDN),
// and forwards the request through. Pairs with NEXT_PUBLIC_API_URL being
// left unset in production builds so every `${API}/api/...` fetch in the
// frontend resolves to a same-origin relative path that lands here.
//
// /api/auth/* is excluded by Next.js's own routing (pages/api/auth/ owns
// that whole prefix via [...nextauth].js, refresh.js, mode.js and
// local-login.js — static/dynamic routes there take priority over this
// catch-all).

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export const config = {
  api: {
    bodyParser: false,
  },
};

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  const segments = Array.isArray(req.query.proxy) ? req.query.proxy : [];
  if (segments.some((s) => s === ".." || s === ".")) {
    return res.status(400).json({ detail: "Invalid path" });
  }
  const path = "/api/" + segments.map(encodeURIComponent).join("/");
  const qsIndex = req.url.indexOf("?");
  const qs = qsIndex >= 0 ? req.url.slice(qsIndex) : "";
  const target = `${BACKEND_URL}${path}${qs}`;

  const headers = {};
  if (req.headers["authorization"]) {
    headers["authorization"] = req.headers["authorization"];
  }
  if (req.headers["content-type"]) {
    headers["content-type"] = req.headers["content-type"];
  }

  const init = { method: req.method, headers };
  if (req.method !== "GET" && req.method !== "HEAD") {
    init.body = await readRawBody(req);
  }

  let upstream;
  try {
    upstream = await fetch(target, init);
  } catch (err) {
    return res.status(502).json({ detail: "Backend unreachable" });
  }

  res.status(upstream.status);
  const contentType = upstream.headers.get("content-type");
  if (contentType) {
    res.setHeader("content-type", contentType);
  }
  const buf = Buffer.from(await upstream.arrayBuffer());
  res.send(buf);
}
