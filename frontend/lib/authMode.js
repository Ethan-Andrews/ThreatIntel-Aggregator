const API = process.env.NEXT_PUBLIC_API_URL || "";

let cachedMode = null;

// AUTH_MODE is fixed per deployment (set once via env vars on the backend),
// so a single fetch per page load is safe to cache in memory.
export async function getAuthMode() {
  if (cachedMode) {
    return cachedMode;
  }
  const r = await fetch(`${API}/api/auth/mode`);
  if (!r.ok) {
    throw new Error(`auth mode lookup failed ${r.status}`);
  }
  const data = await r.json();
  cachedMode = data.mode === "local" ? "local" : "entra";
  return cachedMode;
}

export function __resetAuthModeForTests() {
  cachedMode = null;
}
