// Static route — takes priority over [...nextauth].js's catch-all for this
// exact path. Proxies the local-auth-mode login exchange to the backend.

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ detail: "Method not allowed" });
  }

  let upstream;
  try {
    upstream = await fetch(`${BACKEND_URL}/api/auth/local-login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req.body),
    });
  } catch (err) {
    return res.status(502).json({ detail: "Backend unreachable" });
  }

  const body = await upstream.json();
  return res.status(upstream.status).json(body);
}
