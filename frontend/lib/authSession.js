const TOKEN_KEY = "ti_app_token";
const ROLE_KEY = "ti_user_role";
const REDIRECT_COOLDOWN_MS = 2500;

let inflightRefreshPromise = null;
let lastRedirectTs = 0;

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(accessToken, role = "viewer") {
  sessionStorage.setItem(TOKEN_KEY, accessToken);
  sessionStorage.setItem(ROLE_KEY, role);
}

export function clearAuthState(reason = "UNKNOWN") {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(ROLE_KEY);
  sessionStorage.setItem("ti_auth_reason", reason);
}

export function shouldRedirectNow(now = Date.now()) {
  if (now - lastRedirectTs < REDIRECT_COOLDOWN_MS) {
    return false;
  }
  lastRedirectTs = now;
  return true;
}

// JWT payloads are base64url-encoded (RFC 7519): `-`→`+`, `_`→`/`, no `=` padding.
// atob() only handles standard base64, so we must normalise first.
export function decodeJwtPayload(payloadB64url) {
  const base64 = payloadB64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, "=");
  return JSON.parse(atob(padded));
}

export function isTokenExpired(token) {
  if (!token) return true;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return true;
    const exp = decodeJwtPayload(parts[1]).exp;
    if (typeof exp !== "number") return true;
    return exp * 1000 < Date.now();
  } catch {
    return true; // genuinely malformed JWT — treat as expired
  }
}

export async function refreshTokenOnce(refreshImpl) {
  if (inflightRefreshPromise) {
    return inflightRefreshPromise;
  }

  inflightRefreshPromise = (async () => {
    const data = await refreshImpl();
    setToken(data.accessToken, data.role || "viewer");
    return data;
  })();

  try {
    return await inflightRefreshPromise;
  } finally {
    inflightRefreshPromise = null;
  }
}

export async function logout({ signOutImpl, redirectImpl }) {
  clearAuthState("LOGOUT");
  try {
    await signOutImpl({ redirect: false, callbackUrl: "/login" });
  } catch (_err) {
    // Ignore errors from signOut; always redirect
  }
  redirectImpl("/login");
}

export function __resetAuthSessionForTests() {
  inflightRefreshPromise = null;
  lastRedirectTs = 0;
}
