import { Router } from 'express';
import { Pool } from 'pg';
import { authMiddleware, checkRole } from '../middlewares/auth.middleware';

const router = Router();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

router.get('/users', authMiddleware, checkRole(['admin']), async (req, res) => {
  try {
    const result = await pool.query('SELECT id, email, role, bio, created_at FROM users');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
