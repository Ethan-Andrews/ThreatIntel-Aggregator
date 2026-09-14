import { clearAuthState, getToken, refreshTokenOnce } from "./authSession";

function mergeHeaders(userHeaders = {}) {
  const token = getToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...userHeaders,
  };
}

export async function authFetch(url, { refreshImpl, ...opts } = {}) {
  const doFetch = () => fetch(url, { ...opts, headers: mergeHeaders(opts.headers) });

  let response = await doFetch();
  if (response.status !== 401) {
    return response;
  }

  try {
    await refreshTokenOnce(refreshImpl);
  } catch (_err) {
    clearAuthState("REFRESH_FAILED");
    throw new Error("AUTH_REAUTH_REQUIRED");
  }

  response = await doFetch();
  if (response.status === 401) {
    clearAuthState("TOKEN_EXPIRED");
    throw new Error("AUTH_REAUTH_REQUIRED");
  }

  return response;
}
