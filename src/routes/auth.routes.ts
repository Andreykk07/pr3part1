import { Router, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Pool } from 'pg';
import { AuthenticatedRequest, authMiddleware } from '../middlewares/auth.middleware';
import { loginRateLimiter } from '../middlewares/rateLimiter.middleware';
import { validateEmail, validatePassword } from '../utils/validation';

const router = Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.post('/register', async (req, res) => {
  const { email, password, role, bio, avatarUrl } = req.body;

  if (!validateEmail(email)) return res.status(400).json({ error: 'Invalid email format' });
  if (!validatePassword(password)) return res.status(400).json({ error: 'Password does not meet complexity requirements' });

  const targetRole = ['author', 'reader'].includes(role) ? role : 'reader';

  try {
    const userExists = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userExists.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (email, password, role, bio, avatar_url) VALUES ($1, $2, $3, $4, $5) RETURNING id, email, role',
      [email, hashedPassword, targetRole, bio || null, avatarUrl || null]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', loginRateLimiter, async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const accessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_ACCESS_SECRET as string, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user.id }, process.env.JWT_REFRESH_SECRET as string, { expiresIn: '7d' });

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query('INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)', [user.id, refreshToken, expiresAt]);

    res.json({ accessToken, refreshToken });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET as string) as any;
    const dbToken = await pool.query('SELECT * FROM refresh_tokens WHERE token = $1 AND user_id = $2', [refreshToken, payload.id]);

    if (dbToken.rows.length === 0) return res.status(401).json({ error: 'Invalid or revoked refresh token' });

    const userResult = await pool.query('SELECT id, email, role FROM users WHERE id = $1', [payload.id]);
    const user = userResult.rows[0];

    const newAccessToken = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_ACCESS_SECRET as string, { expiresIn: '15m' });
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: 'Refresh token required' });

  try {
    await pool.query('DELETE FROM refresh_tokens WHERE token = $1', [refreshToken]);
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.get('/me', authMiddleware, async (req: AuthenticatedRequest, res) => {
  try {
    const result = await pool.query('SELECT id, email, role, bio, avatar_url FROM users WHERE id = $1', [req.user?.id]);
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.put('/profile', authMiddleware, async (req: AuthenticatedRequest, res) => {
  const { bio, avatarUrl } = req.body;
  try {
    await pool.query('UPDATE users SET bio = $1, avatar_url = $2 WHERE id = $3', [bio, avatarUrl, req.user?.id]);
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/change-password', authMiddleware, async (req: AuthenticatedRequest, res) => {
  const { oldPassword, newPassword } = req.body;
  if (!validatePassword(newPassword)) return res.status(400).json({ error: 'New password complexity requirements not met' });

  try {
    const userResult = await pool.query('SELECT password FROM users WHERE id = $1', [req.user?.id]);
    const match = await bcrypt.compare(oldPassword, userResult.rows[0].password);
    if (!match) return res.status(400).json({ error: 'Incorrect old password' });

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, req.user?.id]);

    res.json({ message: 'Password updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
