import { signIn, useSession } from "next-auth/react";
import { useEffect, useState } from "react";
import { useRouter } from "next/router";
import { clearAuthState, decodeJwtPayload, isTokenExpired, refreshTokenOnce, setToken } from "../lib/authSession";
import { getAuthMode } from "../lib/authMode";

const API = process.env.NEXT_PUBLIC_API_URL || "";

async function refreshViaApi() {
  const r = await fetch("/api/auth/refresh", { method: "POST" });
  if (!r.ok) {
    throw new Error(`refresh failed ${r.status}`);
  }
  const data = await r.json();
  const [, payloadB64] = data.access_token.split(".");
  const payload = decodeJwtPayload(payloadB64);
  return { accessToken: data.access_token, role: payload.role || "viewer" };
}

function LocalKeyLogin() {
  const router = useRouter();
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setSubmitting(true);
    try {
      const r = await fetch(`${API}/api/auth/local-login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ api_key: apiKey }),
      });
      if (!r.ok) {
        throw new Error(r.status === 401 ? "Invalid API key" : `Login failed (${r.status})`);
      }
      const data = await r.json();
      const [, payloadB64] = data.access_token.split(".");
      const payload = decodeJwtPayload(payloadB64);
      setToken(data.access_token, payload.role || "viewer");
      router.replace("/");
    } catch (err) {
      setError(err.message || "Login failed");
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <input
        type="password"
        value={apiKey}
        onChange={(e) => setApiKey(e.target.value)}
        placeholder="API key"
        autoFocus
        style={input}
      />
      {error && (
        <div style={{ color: "#f87171", marginBottom: "1rem", fontSize: "0.8rem" }}>{error}</div>
      )}
      <button type="submit" style={btn} disabled={submitting || !apiKey}>
        {submitting ? "Signing in..." : "Sign in"}
      </button>
    </form>
  );
}

export default function Login() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [authMode, setAuthMode] = useState(null);
  const [authModeError, setAuthModeError] = useState(false);

  useEffect(() => {
    let mounted = true;
    getAuthMode()
      .then((mode) => mounted && setAuthMode(mode))
      .catch(() => {
        if (!mounted) return;
        // A failed /api/auth/mode call (backend unreachable, wrong
        // NEXT_PUBLIC_API_URL, CORS) is not the same thing as "this
        // deployment uses Entra" -- render a distinct error instead of a
        // Microsoft sign-in button that can never work.
        setAuthModeError(true);
        setAuthMode("entra");
      });
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    let mounted = true;
    (async () => {
      if (status !== "authenticated") {
        return;
      }

      if (session?.appToken && !isTokenExpired(session.appToken)) {
        setToken(session.appToken, session.role || "viewer");
        if (mounted) {
          router.replace("/");
        }
        return;
      }

      try {
        const data = await refreshTokenOnce(refreshViaApi);
        if (!mounted) return;
        setToken(data.accessToken, data.role || "viewer");
        router.replace("/");
      } catch {
        clearAuthState("REFRESH_FAILED");
      }
    })();

    return () => {
      mounted = false;
    };
  }, [status, session, router]);

  if (authModeError) {
    return (
      <div style={shell}>
        <div style={box}>
          <div style={logo}>⚡ THREAT INTEL AGGREGATOR</div>
          <div style={{ color: "#f87171", marginBottom: "1rem", fontSize: "0.875rem" }}>
            Can't reach the backend at {API || "the configured API URL"}. Confirm
            it's running and that NEXT_PUBLIC_API_URL is set correctly, then
            reload this page.
          </div>
          <button onClick={() => window.location.reload()} style={btn}>
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (authMode === "local") {
    return (
      <div style={shell}>
        <div style={box}>
          <div style={logo}>⚡ THREAT INTEL AGGREGATOR</div>
          <div style={subtitle}>Enter the shared API key to sign in</div>
          <LocalKeyLogin />
        </div>
      </div>
    );
  }

  if (authMode === null || status === "loading") {
    return (
      <div style={shell}>
        <div style={box}>
          <div style={logo}>⚡ THREAT INTEL AGGREGATOR</div>
          <div style={subtitle}>Loading...</div>
        </div>
      </div>
    );
  }

  if (session?.error === "BackendAuthError") {
    return (
      <div style={shell}>
        <div style={box}>
          <div style={logo}>⚡ THREAT INTEL AGGREGATOR</div>
          <div style={{ color: "#f87171", marginBottom: "1rem", fontSize: "0.875rem" }}>
            Authentication service unavailable. Please try again.
          </div>
          <button
            onClick={() => signIn("azure-ad")}
            style={btn}
          >
            Try Again
          </button>
        </div>
      </div>
    );
  }

  return (
    <div style={shell}>
      <div style={box}>
        <div style={logo}>⚡ THREAT INTEL AGGREGATOR</div>
        <div style={subtitle}>Sign in with your organization's Microsoft account</div>
        <button
          onClick={() => signIn("azure-ad")}
          style={btn}
        >
          Sign in with Microsoft
        </button>
      </div>
    </div>
  );
}

// ── Styles ────────────────────────────────────────────────────────────────────

const shell = {
  minHeight:       "100vh",
  display:         "flex",
  alignItems:      "center",
  justifyContent:  "center",
  background:      "#0d1117",
};

const box = {
  background:   "#161b22",
  border:       "1px solid #30363d",
  borderRadius: "8px",
  padding:      "2rem",
  width:        "320px",
  textAlign:    "center",
};

const logo = {
  color:        "#e6edf3",
  fontWeight:   "700",
  fontSize:     "1rem",
  marginBottom: "0.5rem",
  letterSpacing: "0.05em",
};

const subtitle = {
  color:        "#8b949e",
  fontSize:     "0.8rem",
  marginBottom: "1.5rem",
};

const btn = {
  width:           "100%",
  padding:         "0.625rem",
  background:      "#0078d4",
  color:           "#fff",
  border:          "none",
  borderRadius:    "4px",
  cursor:          "pointer",
  fontSize:        "0.875rem",
  fontWeight:      "600",
};

const input = {
  width:        "100%",
  padding:      "0.625rem",
  marginBottom: "1rem",
  background:   "#0d1117",
  color:        "#e6edf3",
  border:       "1px solid #30363d",
  borderRadius: "4px",
  fontSize:     "0.875rem",
  boxSizing:    "border-box",
};