import dotenv from 'dotenv'
import express from 'express'

import { authenticateToken } from './middlewares/authMiddleware'
import authRoutes from './routes/authRoutes'
import emotionRoutes from './routes/emotionRoutes'

dotenv.config()

const app = express()
const PORT = process.env.PORT || 3000

app.use(express.json())

app.get('/', (req, res) => {
  res.send('Humora Backend is running!')
})

app.use('/auth', authRoutes)
app.use('/emotions', emotionRoutes)

app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route!', userId: (req as any).userId })
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
