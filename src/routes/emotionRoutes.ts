import { Router } from 'express';
import { authenticateToken } from '../middlewares/authMiddleware';
import {
  createEmotionRecord,
  getEmotionRecords,
  getEmotionRecordById,
  updateEmotionRecord,
  deleteEmotionRecord,
} from '../controllers/emotionController';

const router = Router();

router.use(authenticateToken); // All routes below this will be protected

router.post('/', createEmotionRecord);
router.get('/', getEmotionRecords);
router.get('/:id', getEmotionRecordById);
router.put('/:id', updateEmotionRecord);
router.delete('/:id', deleteEmotionRecord);

export default router;