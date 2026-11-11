import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { doubleCsrf } from 'csrf-csrf';
import authRoutes from './routes/auth.js';
import itemRoutes from './routes/items.js';
import userRoutes from './routes/users.js';
import settingRoutes from './routes/settings.js';

const app = express();

app.use(morgan('dev'));
// The browser must be allowed to send the auth cookie on cross-origin XHR,
// so CORS is locked to the client origin AND credentials are enabled.
app.use(cors({ origin: 'http://localhost:5175', credentials: true }));
app.use(express.json());
// Parse HTML-form bodies too. A classic CSRF payload is an auto-submitting
// <form> (application/x-www-form-urlencoded), so the endpoints must understand it.
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Anti-CSRF: double-submit-cookie pattern via csrf-csrf (v4 API).
// The token is an HMAC of the session (the auth cookie) signed with a server
// secret. It is stored in a cookie AND must be echoed back in the x-csrf-token
// header. A cross-site page can make the browser send cookies, but it can never
// read the token or set a custom header, so a forged request is rejected (403).
const { generateCsrfToken, doubleCsrfProtection } = doubleCsrf({
  getSecret: () => process.env.CSRF_SECRET || process.env.JWT_SECRET,
  // Bind the token to the current session, so a token from another session
  // (or one minted before login) is useless.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  cookieName: 'csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'strict',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
  },
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  // GET/HEAD/OPTIONS are ignored by default: safe requests stay exempt.
});

// Pre-auth routes run before a session exists, so they are exempt.
const CSRF_EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

// The client fetches its token here (a safe GET) and echoes it on every write.
app.get('/api/csrf-token', (req, res) => {
  res.json({ csrfToken: generateCsrfToken(req, res) });
});

// Require the token on every state-changing request, except the exempt routes.
app.use((req, res, next) =>
  CSRF_EXEMPT.has(req.path) ? next() : doubleCsrfProtection(req, res, next)
);

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/items', itemRoutes);
app.use('/api/users', userRoutes);
app.use('/api/settings', settingRoutes);

// Not found
app.use((req, res) => {
  res.status(404).json({ message: 'Not Found' });
});

// Error handler (handles CSRF validation errors with 403)
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).json({ message: 'Invalid CSRF token' });
  }
  console.error(err);
  res.status(err.status || err.statusCode || 500).json({
    message: err.message || 'Server Error',
  });
});

export default app;