import crypto from 'crypto';
import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/User';
import passport from '../config/passport';
import { authCookieOptions, makeGoogleAccessToken, makeGoogleRefreshToken } from '../config/passport';
import {
  register, registerValidators,
  login, loginValidators,
  logout,
  refreshToken,
  me,
  updateProfile,
  verifyContact,
  sendPhoneOtp,
  verifyPhoneOtp,
  resendVerification,
  uploadAvatar,
} from '../controllers/authController';
import { authenticate } from '../middleware/auth';
import upload from '../middleware/upload';

const router = Router();

const FRONTEND_URL = (
  process.env.FRONTEND_URL ||
  process.env.FRONTEND_URLS?.split(',')[0] ||
  'http://localhost:3001'
).trim().replace(/^['"]|['"]$/g, '');
const GOOGLE_CONFIGURED = Boolean(
  process.env.GOOGLE_CLIENT_ID &&
  process.env.GOOGLE_CLIENT_SECRET,
);

const googleRedirect = (status: 'success' | 'error', params: Record<string, string>) => {
  const search = new URLSearchParams({ googleAuth: status, ...params });
  return `${FRONTEND_URL}/login?${search.toString()}`;
};

const GOOGLE_CALLBACK_URL = (process.env.GOOGLE_CALLBACK_URL || '').trim().replace(/^['"]|['"]$/g, '');

const getGoogleCallbackUrl = (_req: Request) => {
  return GOOGLE_CALLBACK_URL;
};

const ENABLE_DEBUG = process.env.ENABLE_DEBUG_ROUTES === 'true' && process.env.NODE_ENV !== 'production';

if (ENABLE_DEBUG) {
  router.get('/debug', async (_req: Request, res: Response) => {
    try {
      const count = await User.count();
      return res.json({ success: true, db: 'ok', userCount: count });
    } catch (e: any) {
      return res.status(500).json({ success: false, dbError: e?.message });
    }
  });

  router.get('/dev-setup', async (_req: Request, res: Response) => {
    const email = 'admin@medtech.com';
    const password = crypto.randomUUID().slice(0, 16);
    const hashed = await bcrypt.hash(password, 12);
    let user = await User.findOne({ where: { email } });
    if (!user) {
      user = await User.create({
        firstName: 'Admin',
        lastName: 'MedTech',
        email,
        password: hashed,
        role: 'admin',
      });
      return res.json({ success: true, message: 'Admin user created', email, password });
    }
    user.password = hashed;
    await user.save();
    return res.json({ success: true, message: 'Admin password reset', email, password });
  });
}

router.get('/google', (req, res, next) => {
  if (!GOOGLE_CONFIGURED) {
    return res.redirect(googleRedirect('error', { message: 'Google sign-in is not configured yet.' }));
  }

  const state = crypto.randomUUID();
  res.cookie('google_oauth_state', state, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 10 * 60 * 1000,
    path: '/',
  });

  return passport.authenticate('google', {
    session: false,
    scope: ['profile', 'email'],
    prompt: 'select_account',
    state,
    callbackURL: getGoogleCallbackUrl(req),
  } as any)(req, res, next);
});

router.get('/google/callback', (req, res, next) => {
  if (!GOOGLE_CONFIGURED) {
    return res.redirect(googleRedirect('error', { message: 'Google sign-in is not configured yet.' }));
  }

  const storedState = req.cookies?.google_oauth_state;
  const returnedState = req.query.state as string | undefined;
  res.clearCookie('google_oauth_state', { path: '/' });

  if (!storedState || !returnedState || storedState !== returnedState) {
    return res.redirect(googleRedirect('error', { message: 'OAuth state mismatch. Possible CSRF attack.' }));
  }

  return passport.authenticate('google', { session: false, callbackURL: getGoogleCallbackUrl(req) } as any, async (error: unknown, user?: InstanceType<typeof User>) => {
    if (error || !user) {
      const message = error instanceof Error ? error.message : 'Google sign-in failed.';
      return res.redirect(googleRedirect('error', { message }));
    }

    const accessToken = makeGoogleAccessToken(user.id);
    const refreshToken = makeGoogleRefreshToken(user.id);

    res.cookie('medtech_refresh', refreshToken, authCookieOptions(30 * 24 * 60 * 60 * 1000));
    return res.redirect(googleRedirect('success', { token: accessToken }));
  })(req, res, next);
});

router.post('/register', registerValidators, register);
router.post('/login', loginValidators, login);
router.post('/logout', logout);
router.post('/refresh', refreshToken);
router.get('/me', authenticate, me);
router.put('/profile', authenticate, updateProfile);
router.post('/verify-contact', authenticate, verifyContact);
router.post('/send-phone-otp', authenticate, sendPhoneOtp);
router.post('/verify-phone-otp', authenticate, verifyPhoneOtp);
router.post('/resend-verification', authenticate, resendVerification);
router.post('/avatar', authenticate, upload.single('avatar'), uploadAvatar);

export default router;
