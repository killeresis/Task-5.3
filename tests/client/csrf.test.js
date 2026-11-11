import { api } from '../../client/src/api.js';

// Read a header value whether axios stored it as a plain object or an AxiosHeaders.
function getHeader(headers, name) {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name);
  return headers[name] ?? headers[name.toLowerCase()];
}

describe('client api CSRF behavior', () => {
  let captured;

  beforeEach(() => {
    captured = [];
    // Stub the network layer. Answer the CSRF-token request with a known token
    // and record every other outgoing request so we can inspect its headers.
    api.defaults.adapter = async (config) => {
      if ((config.url || '').includes('/csrf-token')) {
        return { data: { csrfToken: 'test-token' }, status: 200, statusText: 'OK', headers: {}, config };
      }
      captured.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };
  });

  test('requests are sent with credentials so the auth cookie rides along', () => {
    expect(api.defaults.withCredentials).toBe(true);
  });

  // A state-changing request must carry an anti-CSRF token in a header. The
  // attacker's forged request cannot set this header (and cannot read the token),
  // so this is what defeats CSRF. The vulnerable client never attaches it.
  test('a mutating request carries the x-csrf-token header', async () => {
    await api.post('/settings/recovery-email', { recoveryEmail: 'legit@user.com' });

    const sent = captured.find((c) => (c.url || '').includes('/settings/recovery-email'));
    expect(sent).toBeDefined();
    expect(getHeader(sent.headers, 'x-csrf-token')).toBe('test-token');
  });
});
