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

const otpStore = {};
const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, 
          pass: process.env.EMAIL_PASS }
});

// MongoDB connection
mongoose.connect(process.env.MONGO_URI).then(() => console.log('MongoDB connected')).catch(console.error);

// GridFS setup
let gfs, gridFSBucket;
mongoose.connection.once('open', () => {
  gridFSBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
  gfs = Grid(mongoose.connection.db, mongoose.mongo);
  gfs.collection('uploads');
});

// Middleware for auth
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, message: 'Missing token' });
  try {
    req.user = jwt.verify(authHeader.split(' ')[1], SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}
// Admin check

function adminMiddleware(req, res, next) {
  const allowed = ['Harsh Ninania', 'Satyam Pr'];
  if (!allowed.includes(req.user.username)) return res.status(403).json({ success: false, message: 'Admins only' });
  next();
}
// Mongoose Models

const userSchema = new mongoose.Schema({
   username: String, 
   email: String, 
   password: String });
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  day: Number, name: String, time: String, file: String, week: { type: String, enum: ['this', 'next'], default: 'this' }
});
const Task = mongoose.model('Task', taskSchema);

const fileSchema = new mongoose.Schema({ filename: String, originalName: String, uploadedAt: { type: Date, default: Date.now } });
const UploadedFile = mongoose.model('UploadedFile', fileSchema);

// Multer-GridFS storage setup

const storage = new GridFsStorage({
  url: process.env.MONGO_URI,
  file: (req, file) => new Promise((resolve, reject) => {
    crypto.randomBytes(16, (err, buf) => {
      if (err) return reject(err);
      const filename = buf.toString('hex') + path.extname(file.originalname);
      resolve({ filename, bucketName: 'uploads' });
    });
  })
});
const upload = multer({ storage });

app.post('/request-reset', async (req, res) => {
  const { username } = req.body;

  try {
  const { username } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[username] = { otp, expiresAt: Date.now() + 300000 };

  const mailOptions = {
      from: process.env.EMAIL_USER,
      to: user.email, // ✅ DB email
      subject: 'Your OTP for Password Reset',
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`
    };

    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'OTP sent to your registered email' });

  } catch (err) {
    console.error('Reset OTP error:', err);
    res.status(500).json({ success: false, message: 'Server error while sending OTP' });
  }
});

app.post('/verify-reset', async (req, res) => {
  const { username, otp, newPassword } = req.body;
  const record = otpStore[username];
  if (!record || record.otp != otp || Date.now() > record.expiresAt) return res.status(400).json({ success: false, message: 'Invalid/expired OTP' });

  const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
  
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    await user.save();
  
    delete otpStore[username];
    res.json({ success: true, message: 'Password reset successful' });
});

// Auth routes

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
const existing = await User.findOne({ username: name });
if (existing) return res.json({ success: false, message: 'Username already exists' });

const hashed = await bcrypt.hash(password, 10);
await User.create({ username: name, email, password: hashed });
res.json({ success: true, message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.json({ success: false, message: 'Incorrect password' });

  // ✅ Include name in token payload for /api/me
  const token = jwt.sign({ username: user.username, name: user.username }, SECRET, { expiresIn: '1h' });
  res.json({ success: true, message: 'Login successful', token });
});

// ✅ Route to get logged-in user's name
app.get('/api/me', authMiddleware, (req, res) => {
  try {
    res.json({ success: true, name: req.user.name });
  } catch (err) {
    res.status(500).json({ success: false, message: 'Error getting user info' });
  }
});

//SignUp page APis
// === FRONTEND SIGNUP OTP HANDLING ===

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ success: false, message: 'Email is required' });

  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 5 * 60 * 1000;
  otpStore[email] = { otp, expiresAt };

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP for Sign Up',
    text: `Your OTP is ${otp}. It will expire in 5 minutes.`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ success: true, message: 'OTP sent to email' });
  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ success: false, message: 'Failed to send OTP email' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];

  if (!record || record.otp != otp || Date.now() > record.expiresAt) {
    return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
  }

  delete otpStore[email];
  res.json({ success: true, message: 'OTP verified' });
});

app.post('/task', authMiddleware, adminMiddleware, async (req, res) => {
  const { day, name, time, week } = req.body;
  await Task.create({ day, name, time, week });
  res.json({ success: true });
});

// Task routes

app.get('/tasks', authMiddleware, async (req, res) => res.json({ success: true, tasks: await Task.find({}) }));

app.delete('/task/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const task = await Task.findByIdAndDelete(req.params.id);
  if (!task) return res.status(404).json({ success: false, message: 'Task not found' });
  if (task.file) {
    const file = await gfs.files.findOne({ filename: task.file });
    if (file) gridFSBucket.delete(file._id, () => UploadedFile.deleteOne({ filename: task.file }));
  }
  res.json({ success: true });
});

app.patch('/task/:id/add-file', authMiddleware, adminMiddleware, async (req, res) => {
  const { filename } = req.body;
  const existing = await Task.findById(req.params.id);
  if (existing.file) {
    const file = await gfs.files.findOne({ filename: existing.file });
    if (file) gridFSBucket.delete(file._id, () => UploadedFile.deleteOne({ filename: existing.file }));
  }
  const updated = await Task.findByIdAndUpdate(req.params.id, { file: filename }, { new: true });
  res.json({ success: true, task: updated });
});

app.patch('/task/:id/remove-file', authMiddleware, adminMiddleware, async (req, res) => {
  const task = await Task.findById(req.params.id);
  if (task.file) {
    const file = await gfs.files.findOne({ filename: task.file });
    if (file) gridFSBucket.delete(file._id, () => UploadedFile.deleteOne({ filename: task.file }));
  }
  const updated = await Task.findByIdAndUpdate(req.params.id, { $unset: { file: '' } }, { new: true });
  res.json({ success: true, task: updated });
});

//file uplaod
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

app.get('/files', authMiddleware, async (req, res) => res.json({ success: true, files: await UploadedFile.find().sort({ uploadedAt: -1 }) }));

app.get('/download/:filename', authMiddleware, async (req, res) => {
  const file = await gfs.files.findOne({ filename: req.params.filename });
  if (!file) return res.status(404).json({ success: false });
  const readStream = gridFSBucket.openDownloadStreamByName(file.filename);
  res.set('Content-Type', file.contentType || 'application/octet-stream');
  res.set('Content-Disposition', `attachment; filename="${file.filename}"`);
  readStream.pipe(res);
});

app.delete('/delete-file/:filename', authMiddleware, adminMiddleware, async (req, res) => {
  const file = await gfs.files.findOne({ filename: req.params.filename });
  if (!file) return res.status(404).json({ success: false });
  gridFSBucket.delete(file._id, async () => {
    await UploadedFile.deleteOne({ filename: file.filename });
    res.json({ success: true });
  });
});

webPush.setVapidDetails(process.env.ADMIN_EMAIL, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
const subscriptions = [];

app.post('/subscribe', (req, res) => {
  const sub = req.body;
  subscriptions.push(sub);
  res.status(201).json({ success: true, message: 'Subscribed' });
});

cron.schedule('0 0 * * 1', async () => {
  const oldTasks = await Task.find({ week: 'this' });
  for (const task of oldTasks) {
    if (task.file) {
      const file = await gfs.files.findOne({ filename: task.file });
      if (file) gridFSBucket.delete(file._id, () => UploadedFile.deleteOne({ filename: task.file }));
    }
    await Task.findByIdAndDelete(task._id);
  }
  await Task.updateMany({ week: 'next' }, { $set: { week: 'this' } });
  console.log('[CRON] Shifted next week to this week and cleaned old tasks');
}, { timezone: 'Asia/Kolkata' });


cron.schedule('* * * * *', async () => {
  const nowIST = moment().tz('Asia/Kolkata');
  const tomorrow = nowIST.clone().add(1, 'day');

  // Adjust JS Sunday=0 to DB Monday=0
  const jsTomorrowDay = tomorrow.day();
  const dbTomorrowDay = (jsTomorrowDay + 6) % 7;

  console.log('[DEBUG] Now IST:', nowIST.format());
  console.log('[DEBUG] Tomorrow:', tomorrow.format());
  console.log('[DEBUG] JS Day (0=Sun):', jsTomorrowDay);
  console.log('[DEBUG] DB Day (0=Mon):', dbTomorrowDay);

  try {
    const tasks = await Task.find({ day: dbTomorrowDay });
    const payloads = tasks.map(task => JSON.stringify({
      title: '🗓 Task Reminder!',
      body: `"${task.name}" is scheduled for tomorrow at ${task.time}`,
      vibrate: [200, 100, 200]
    }));

    for (const sub of subscriptions) {
      for (const payload of payloads) {
        try {
          await webPush.sendNotification(sub, payload);
        } catch (err) {
          console.error('[PUSH FAILED]', err);
        }
      }
    }

    console.log(`[CRON] Sent ${tasks.length} notifications for DB day ${dbTomorrowDay}.`);
  } catch (err) {
    console.error('[CRON ERROR]', err);
  }
}, {
  timezone: 'Asia/Kolkata'
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

