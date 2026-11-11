import axios from 'axios';

// `withCredentials: true` makes the browser send (and store) the auth cookie on
// cross-origin requests to the API. The JWT is no longer kept in localStorage,
// so there is no token to attach by hand anymore.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
});

// --- Anti-CSRF token ---------------------------------------------------------
// The server requires an x-csrf-token header on every state-changing request.
// The token is bound to the current session, so it is fetched lazily (on the
// first write) and dropped whenever the session changes (login/register/logout).
const SAFE_METHODS = ['get', 'head', 'options'];
const SESSION_CHANGING = ['/auth/login', '/auth/register', '/auth/logout'];
let csrfToken = null;

export async function fetchCsrfToken() {
  const { data } = await api.get('/csrf-token');
  csrfToken = data.csrfToken;
  return csrfToken;
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase();
  const url = config.url || '';
  if (!SAFE_METHODS.includes(method) && !url.includes('/csrf-token')) {
    const token = csrfToken || (await fetchCsrfToken());
    config.headers.set('x-csrf-token', token);
  }
  return config;
});

api.interceptors.response.use(
  (res) => {
    if (SESSION_CHANGING.some((p) => (res.config.url || '').includes(p))) csrfToken = null;
    return res;
  },
  async (err) => {
    // Stale token (e.g. the session changed in another tab): refresh once and retry.
    const config = err.config;
    const badToken = err.response?.status === 403 && err.response?.data?.message === 'Invalid CSRF token';
    if (badToken && config && !config._csrfRetried) {
      config._csrfRetried = true;
      csrfToken = null;
      return api(config);
    }
    return Promise.reject(err);
  }
);
