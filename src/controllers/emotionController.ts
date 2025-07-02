import { Request, Response } from 'express';
import prisma from '../config/prisma';

interface AuthRequest extends Request {
  userId?: string;
}

export const createEmotionRecord = async (req: AuthRequest, res: Response) => {
  const { emotion, intensity, notes } = req.body;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  if (!emotion || !intensity) {
    return res.status(400).json({ message: 'Emotion and intensity are required' });
  }

  try {
    const newRecord = await prisma.emotionRecord.create({
      data: {
        emotion,
        intensity,
        notes,
        userId,
      },
    });
    res.status(201).json(newRecord);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const getEmotionRecords = async (req: AuthRequest, res: Response) => {
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const records = await prisma.emotionRecord.findMany({
      where: { userId },
      orderBy: { date: 'desc' },
    });
    res.status(200).json(records);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const getEmotionRecordById = async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const record = await prisma.emotionRecord.findUnique({
      where: { id },
    });

    if (!record || record.userId !== userId) {
      return res.status(404).json({ message: 'Record not found or unauthorized' });
    }

    res.status(200).json(record);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const updateEmotionRecord = async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const { emotion, intensity, notes } = req.body;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const existingRecord = await prisma.emotionRecord.findUnique({
      where: { id },
    });

    if (!existingRecord || existingRecord.userId !== userId) {
      return res.status(404).json({ message: 'Record not found or unauthorized' });
    }

    const updatedRecord = await prisma.emotionRecord.update({
      where: { id },
      data: {
        emotion: emotion || existingRecord.emotion,
        intensity: intensity || existingRecord.intensity,
        notes: notes || existingRecord.notes,
      },
    });
    res.status(200).json(updatedRecord);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};

export const deleteEmotionRecord = async (req: AuthRequest, res: Response) => {
  const { id } = req.params;
  const userId = req.userId;

  if (!userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }

  try {
    const existingRecord = await prisma.emotionRecord.findUnique({
      where: { id },
    });

    if (!existingRecord || existingRecord.userId !== userId) {
      return res.status(404).json({ message: 'Record not found or unauthorized' });
    }

    await prisma.emotionRecord.delete({
      where: { id },
    });
    res.status(204).send(); // No Content
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal server error' });
  }
};