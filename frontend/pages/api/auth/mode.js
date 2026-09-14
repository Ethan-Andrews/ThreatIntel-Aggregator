// Static route — takes priority over [...nextauth].js's catch-all for this
// exact path. Proxies to the backend the same way [...proxy].js does for
// everything outside /api/auth/*, since this endpoint has to be reachable
// before the caller knows whether Entra or local auth is in play.

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export default async function handler(req, res) {
  if (req.method !== "GET") {
    return res.status(405).json({ detail: "Method not allowed" });
  }

  let upstream;
  try {
    upstream = await fetch(`${BACKEND_URL}/api/auth/mode`);
  } catch (err) {
    return res.status(502).json({ detail: "Backend unreachable" });
  }

  const body = await upstream.json();
  return res.status(upstream.status).json(body);
}
