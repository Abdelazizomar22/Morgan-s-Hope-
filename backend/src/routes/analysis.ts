import { Router } from 'express';
import { authenticate } from '../middleware/auth';
import { userRateLimiter } from '../middleware/rateLimiter';
import upload from '../middleware/upload';
import {
  upload as uploadAnalysis,
  getHistory,
  getById,
  deleteAnalysis,
} from '../controllers/analysisController';

const router = Router();

const analysisUploadLimit = userRateLimiter({ windowMs: 15 * 60 * 1000, max: 20, message: 'Too many upload requests, please try again later.' });

router.post('/upload',  authenticate, analysisUploadLimit, upload.single('image'), uploadAnalysis);
router.get('/history',  authenticate, getHistory);
router.get('/:id',      authenticate, getById);
router.delete('/:id',   authenticate, deleteAnalysis);

export default router;
