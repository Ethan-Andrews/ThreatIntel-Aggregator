import { getToken } from "next-auth/jwt";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ detail: "Method not allowed" });
  }

  const token = await getToken({ req, secret: process.env.NEXTAUTH_SECRET });
  const idToken = token?.idToken;

  if (!idToken) {
    return res.status(401).json({ detail: "No active session" });
  }

  const upstream = await fetch(`${BACKEND_URL}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ id_token: idToken }),
  });

  const body = await upstream.json();
  if (!upstream.ok) {
    return res.status(upstream.status).json(body);
  }

  return res.status(200).json(body);
}
