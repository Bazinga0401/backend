// === UPDATED BACKEND CODE ===
require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const webPush = require('web-push');
const cron = require('node-cron');
const multer = require('multer');
const path = require('path');
const moment = require('moment-timezone');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { GridFsStorage } = require('multer-gridfs-storage');
const Grid = require('gridfs-stream');

const SECRET = process.env.SECRET;
const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const otpStore = {}; // { username/email: { otp, expiresAt } }
const subscriptions = [];

const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// Mongo Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB error:', err));

let gfs, gridFSBucket;
const conn = mongoose.connection;
conn.once('open', () => {
  gridFSBucket = new mongoose.mongo.GridFSBucket(conn.db, { bucketName: 'uploads' });
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('uploads');
});

// Auth Middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Missing token' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (!['Harsh Ninania', 'Satyam Pr'].includes(req.user.username)) {
    return res.status(403).json({ success: false, message: 'Only admins can perform this action' });
  }
  next();
}

// Models
const User = mongoose.model('User', new mongoose.Schema({ username: String, email: String, password: String }));
const Task = mongoose.model('Task', new mongoose.Schema({ day: Number, name: String, time: String, file: String, week: { type: String, enum: ['this', 'next'], default: 'this' } }));
const UploadedFile = mongoose.model('UploadedFile', new mongoose.Schema({ filename: String, originalName: String, uploadedAt: { type: Date, default: Date.now } }));

const storage = new GridFsStorage({
  url: process.env.MONGO_URI,
  file: (req, file) => new Promise((resolve, reject) => {
    crypto.randomBytes(16, (err, buf) => {
      if (err) return reject(err);
      resolve({ filename: buf.toString('hex') + path.extname(file.originalname), bucketName: 'uploads' });
    });
  })
});
const upload = multer({ storage });

// --- Routes (Same as earlier but updated ones below) ---

// DELETE TASK (Auto cleanup file)
app.delete('/task/:id', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const task = await Task.findByIdAndDelete(req.params.id);
    if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
    if (task.file) {
      const file = await gfs.files.findOne({ filename: task.file });
      if (file) {
        await gridFSBucket.delete(file._id);
        await UploadedFile.deleteOne({ filename: task.file });
      }
    }
    res.json({ success: true, message: 'Task and associated file deleted' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// PATCH REPLACE FILE
app.patch('/task/:id/add-file', authMiddleware, adminMiddleware, async (req, res) => {
  const { filename } = req.body;
  if (!filename || !mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ success: false, message: 'Invalid input' });
  try {
    const task = await Task.findById(req.params.id);
    if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
    if (task.file) {
      const oldFile = await gfs.files.findOne({ filename: task.file });
      if (oldFile) {
        await gridFSBucket.delete(oldFile._id);
        await UploadedFile.deleteOne({ filename: task.file });
      }
    }
    task.file = filename;
    await task.save();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// CRON: Sunday midnight transfer next -> this, delete old this week + files
cron.schedule('0 0 * * 1', async () => {
  try {
    // Delete all this week's tasks and files
    const oldTasks = await Task.find({ week: 'this' });
    for (const task of oldTasks) {
      if (task.file) {
        const file = await gfs.files.findOne({ filename: task.file });
        if (file) {
          await gridFSBucket.delete(file._id);
          await UploadedFile.deleteOne({ filename: task.file });
        }
      }
    }
    await Task.deleteMany({ week: 'this' });

    // Move all next week's tasks to this week
    await Task.updateMany({ week: 'next' }, { $set: { week: 'this' } });
    console.log('[CRON] Weekly rotation done.');
  } catch (err) {
    console.error('[CRON ERROR]', err);
  }
}, {
  timezone: 'Asia/Kolkata'
});

// ...keep all remaining unchanged routes below this line


// === public/sw.js (must be served as static file) ===
// self.addEventListener('push', event => {
//   if (event.data) {
//     const data = event.data.json();
//     self.registration.showNotification(data.title, {
//       body: data.body,
//       icon: '/icon.png',
//       vibrate: data.vibrate || [100, 50, 100]
//     });
//   }
// });


// File upload
app.post('/upload', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
  try {
    await UploadedFile.create({
      filename: req.file.filename,
      originalName: req.file.originalname
    });
    res.json({ success: true, file: req.file });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error saving file metadata' });
  }
});

app.get('/files', authMiddleware, async (req, res) => {
  const files = await UploadedFile.find().sort({ uploadedAt: -1 });
  res.json({ success: true, files });
});

app.get('/download/:filename', authMiddleware, async (req, res) => {
  try {
    const file = await gfs.files.findOne({ filename: req.params.filename });
    if (!file) return res.status(404).json({ success: false, message: 'File not found' });

    const readStream = gridFSBucket.openDownloadStreamByName(file.filename);
    res.set('Content-Type', file.contentType || 'application/octet-stream');
    res.set('Content-Disposition', `attachment; filename="${file.filename}"`);

    readStream.on('error', err => {
      res.status(500).json({ success: false, message: 'Stream error while downloading file' });
    });

    readStream.pipe(res);
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error retrieving file' });
  }
});

app.delete('/delete-file/:filename', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const file = await gfs.files.findOne({ filename: req.params.filename });
    if (!file) return res.status(404).json({ success: false, message: 'File not found' });

    gridFSBucket.delete(file._id, async (err) => {
      if (err) return res.status(500).json({ success: false, message: 'Error deleting file' });

      await UploadedFile.deleteOne({ filename: file.filename });
      res.json({ success: true, message: 'File deleted from DB' });
    });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error deleting file' });
  }
});

app.post('/send-test-push', (req, res) => {
  const payload = JSON.stringify({
    title: 'Breaking News: You Have a Task 📰',
    body: 'This is a manual push from backend!',
    icon: './pfp.ico',
    vibrate: [100, 50, 100]
  });

  subscriptions.forEach(sub => {
    webPush.sendNotification(sub, payload).catch(err => console.error('Push failed:', err));
  });

  res.json({ success: true, message: 'Test push sent!' });
});

// Start server
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
