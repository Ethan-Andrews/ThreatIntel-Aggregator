import { authFetch } from "../authFetch";
import * as authSession from "../authSession";

describe("authFetch", () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    sessionStorage.clear();
    authSession.__resetAuthSessionForTests();
  });

  test("retries once after 401 when refresh succeeds", async () => {
    authSession.setToken("old.jwt", "viewer");
    const refreshImpl = jest.fn().mockResolvedValue({ accessToken: "new.jwt", role: "viewer" });

    const first = { status: 401 };
    const second = { status: 200, json: async () => ({ ok: true }) };

    global.fetch = jest.fn()
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);

    const res = await authFetch("/api/entries", { refreshImpl });
    expect(refreshImpl).toHaveBeenCalledTimes(1);
    expect(global.fetch).toHaveBeenCalledTimes(2);
    expect(res.status).toBe(200);
  });

  test("clears auth and throws when refresh fails", async () => {
    authSession.setToken("old.jwt", "viewer");
    const refreshImpl = jest.fn().mockRejectedValue(new Error("refresh failed"));
    global.fetch = jest.fn().mockResolvedValue({ status: 401 });

    await expect(authFetch("/api/entries", { refreshImpl })).rejects.toThrow("AUTH_REAUTH_REQUIRED");
    expect(authSession.getToken()).toBeNull();
  });
});
