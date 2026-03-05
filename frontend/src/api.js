import { auth } from "./firebase";

// perform fetch with Authorization header populated from current user token
export async function authFetch(url, opts = {}) {
  const user = auth.currentUser;
  const headers = opts.headers || {};
  if (user) {
    try {
      const token = await user.getIdToken();
      headers["Authorization"] = `Bearer ${token}`;
    } catch (e) {
      console.error("Failed to get ID token", e);
    }
  }
  return fetch(url, { ...opts, headers });
}
