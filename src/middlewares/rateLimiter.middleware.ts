import { Request, Response, NextFunction } from 'express';

const loginAttempts = new Map<string, { count: number; resetTime: number }>();

export const loginRateLimiter = (req: Request, res: Response, next: NextFunction) => {
  const ip = req.ip || 'unknown';
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;

  const record = loginAttempts.get(ip);

  if (!record || now > record.resetTime) {
    loginAttempts.set(ip, { count: 1, resetTime: now + windowMs });
    return next();
  }

  if (record.count >= 5) {
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }

  record.count += 1;
  next();
};
