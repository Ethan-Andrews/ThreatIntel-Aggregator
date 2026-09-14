import {
  getToken,
  setToken,
  clearAuthState,
  decodeJwtPayload,
  isTokenExpired,
  shouldRedirectNow,
  refreshTokenOnce,
  __resetAuthSessionForTests,
} from "../authSession";

// Produces a base64url-encoded payload the same way python-jose does:
// no `=` padding, `-` instead of `+`, `_` instead of `/`.
function makeB64urlToken(claims) {
  const json = JSON.stringify(claims);
  const b64 = btoa(json);
  const b64url = b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `header.${b64url}.sig`;
}

describe("authSession", () => {
  beforeEach(() => {
    sessionStorage.clear();
    __resetAuthSessionForTests();
  });

  test("setToken/getToken round-trip", () => {
    setToken("abc.jwt.token", "admin");
    expect(getToken()).toBe("abc.jwt.token");
    expect(sessionStorage.getItem("ti_user_role")).toBe("admin");
  });

  test("clearAuthState removes token + role", () => {
    setToken("abc.jwt.token", "viewer");
    clearAuthState("TOKEN_EXPIRED");
    expect(getToken()).toBeNull();
    expect(sessionStorage.getItem("ti_user_role")).toBeNull();
  });

  test("shouldRedirectNow applies cooldown", () => {
    expect(shouldRedirectNow()).toBe(true);
    expect(shouldRedirectNow()).toBe(false);
  });

  test("refreshTokenOnce shares one in-flight promise", async () => {
    let calls = 0;
    const refreshImpl = async () => {
      calls += 1;
      return { accessToken: "new.jwt", role: "viewer" };
    };

    const [a, b] = await Promise.all([
      refreshTokenOnce(refreshImpl),
      refreshTokenOnce(refreshImpl),
    ]);

    expect(calls).toBe(1);
    expect(a.accessToken).toBe("new.jwt");
    expect(b.accessToken).toBe("new.jwt");
    expect(getToken()).toBe("new.jwt");
  });
});

describe("decodeJwtPayload", () => {
  test("decodes standard base64 payload", () => {
    const payload = btoa(JSON.stringify({ sub: "user", exp: 9999999999 }));
    expect(decodeJwtPayload(payload)).toEqual({ sub: "user", exp: 9999999999 });
  });

  test("decodes base64url payload (no padding, - and _ chars)", () => {
    // Construct a payload that produces + and / in base64, then convert to base64url
    const raw = JSON.stringify({ sub: "user@example.com", exp: 9999999999, role: "admin" });
    const b64url = btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(decodeJwtPayload(b64url)).toEqual({ sub: "user@example.com", exp: 9999999999, role: "admin" });
  });
});

describe("isTokenExpired", () => {
  test("returns true for null/undefined/empty token", () => {
    expect(isTokenExpired(null)).toBe(true);
    expect(isTokenExpired(undefined)).toBe(true);
    expect(isTokenExpired("")).toBe(true);
  });

  test("returns false for a valid non-expired standard-base64 token", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    const payload = btoa(JSON.stringify({ exp, role: "viewer" }));
    expect(isTokenExpired(`header.${payload}.sig`)).toBe(false);
  });

  test("returns false for a valid non-expired base64url token (python-jose format)", () => {
    const exp = Math.floor(Date.now() / 1000) + 3600;
    expect(isTokenExpired(makeB64urlToken({ exp, role: "viewer" }))).toBe(false);
  });

  test("returns true for an expired standard-base64 token", () => {
    const exp = Math.floor(Date.now() / 1000) - 60;
    const payload = btoa(JSON.stringify({ exp, role: "viewer" }));
    expect(isTokenExpired(`header.${payload}.sig`)).toBe(true);
  });

  test("returns true for an expired base64url token (python-jose format)", () => {
    const exp = Math.floor(Date.now() / 1000) - 60;
    expect(isTokenExpired(makeB64urlToken({ exp, role: "viewer" }))).toBe(true);
  });

  test("returns true for a token with missing exp claim", () => {
    expect(isTokenExpired(makeB64urlToken({ sub: "user", role: "viewer" }))).toBe(true);
  });

  test("returns true for a malformed token", () => {
    expect(isTokenExpired("not.valid.jwt")).toBe(true);
  });

  test("returns true for a token with only two parts", () => {
    expect(isTokenExpired("header.payload")).toBe(true);
  });
});
