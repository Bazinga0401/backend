// ✅ Load environment variables
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

const corsOptions = {
  origin: ["https://bazinga0401.github.io", "http://localhost:5500"],
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.use(express.static(path.join(__dirname, 'public')));

const otpStore = {}; // In-memory OTPs { email/username: { otp, expiresAt } }

const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

let gfs, gridFSBucket;
let upload;

const conn = mongoose.connection;
conn.once('open', () => {
  gridFSBucket = new mongoose.mongo.GridFSBucket(conn.db, { bucketName: 'uploads' });
  gfs = Grid(conn.db, mongoose.mongo);
  gfs.collection('uploads');

  const storage = new GridFsStorage({
    url: process.env.MONGO_URI,
    file: (req, file) => new Promise((resolve, reject) => {
      crypto.randomBytes(16, (err, buf) => {
        if (err) return reject(err);
        const filename = buf.toString('hex') + path.extname(file.originalname);
        resolve({ filename, bucketName: 'uploads', metadata: { originalName: file.originalname } });
      });
    })
  });
  upload = multer({ storage });
});

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ success: false, message: 'Missing token' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  const allowed = ['Harsh Ninania', 'Satyam Pr'];
  if (!allowed.includes(req.user.username)) return res.status(403).json({ success: false, message: 'Admins only' });
  next();
}

const User = mongoose.model('User', new mongoose.Schema({ username: String, email: String, password: String }));
const Task = mongoose.model('Task', new mongoose.Schema({ day: Number, name: String, time: String, file: String, week: { type: String, enum: ['this', 'next'], default: 'this' } }));
const UploadedFile = mongoose.model('UploadedFile', new mongoose.Schema({ filename: String, originalName: String, uploadedAt: { type: Date, default: Date.now } }));

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
  const token = jwt.sign({ username: user.username, name: user.username }, SECRET, { expiresIn: '1h' });
  res.json({ success: true, message: 'Login successful', token });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ success: true, name: req.user.name });
});

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  const expiresAt = Date.now() + 5 * 60 * 1000;
  otpStore[email] = { otp, expiresAt };
  try {
    await transporter.sendMail({ from: 'pipikahisab@gmail.com', to: email, subject: 'OTP for Sign Up', text: `Your OTP is ${otp}` });
    res.json({ success: true, message: 'OTP sent' });
  } catch (err) {
    res.status(500).json({ success: false, message: 'OTP email failed' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  if (!record || record.otp != otp || Date.now() > record.expiresAt) return res.status(400).json({ success: false, message: 'Invalid OTP' });
  delete otpStore[email];
  res.json({ success: true });
});

app.post('/task', authMiddleware, adminMiddleware, async (req, res) => {
  const { day, name, time, week } = req.body;
  try {
    await Task.create({ day, name, time, week });
    res.json({ success: true });
  } catch {
    res.status(500).json({ success: false });
  }
});

app.get('/tasks', authMiddleware, async (req, res) => {
  const tasks = await Task.find();
  res.json({ success: true, tasks });
});

app.delete('/task/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const deleted = await Task.findByIdAndDelete(req.params.id);
  if (!deleted) return res.status(404).json({ success: false });
  res.json({ success: true });
});

app.patch('/task/:id/add-file', authMiddleware, adminMiddleware, async (req, res) => {
  const { filename } = req.body;
  const updated = await Task.findByIdAndUpdate(req.params.id, { file: filename }, { new: true });
  if (!updated) return res.status(404).json({ success: false });
  res.json({ success: true, task: updated });
});

app.patch('/task/:id/remove-file', authMiddleware, adminMiddleware, async (req, res) => {
  const updated = await Task.findByIdAndUpdate(req.params.id, { $unset: { file: '' } }, { new: true });
  if (!updated) return res.status(404).json({ success: false });
  res.json({ success: true, task: updated });
});

webPush.setVapidDetails(process.env.ADMIN_EMAIL, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);

const subscriptions = [];
app.post('/subscribe', (req, res) => {
  subscriptions.push(req.body);
  res.status(201).json({ message: 'Subscribed' });
});

cron.schedule('09 12 * * *', async () => {
  const nowIST = moment().tz('Asia/Kolkata');
  const tomorrow = nowIST.clone().add(1, 'day');
  const weekdayIndex = tomorrow.isoWeekday() % 7;
  const tasks = await Task.find({ day: weekdayIndex });
  const payloads = tasks.map(task => JSON.stringify({ title: 'Task Reminder', body: `${task.name} at ${task.time}`, vibrate: [200, 100, 200] }));
  for (const sub of subscriptions) {
    for (const payload of payloads) {
      try {
        await webPush.sendNotification(sub, payload);
      } catch (e) { console.error('[PUSH FAILED]', e); }
    }
  }
});

app.post('/upload', authMiddleware, adminMiddleware, (req, res) => {
  if (!upload) return res.status(503).json({ success: false });
  upload.single('file')(req, res, async err => {
    if (err) return res.status(500).json({ success: false, message: 'Upload error', error: err.message });
    await UploadedFile.create({ filename: req.file.filename, originalName: req.file.originalname });
    res.json({ success: true, file: req.file });
  });
});

app.get('/files', authMiddleware, async (req, res) => {
  const files = await UploadedFile.find().sort({ uploadedAt: -1 });
  res.json({ success: true, files });
});

app.get('/download/:filename', authMiddleware, async (req, res) => {
  const file = await gfs.files.findOne({ filename: req.params.filename });
  if (!file) return res.status(404).json({ success: false });
  const original = file.metadata?.originalName || file.filename;
  const stream = gridFSBucket.openDownloadStreamByName(file.filename);
  res.set('Content-Type', file.contentType || 'application/octet-stream');
  res.set('Content-Disposition', `attachment; filename="${original}"`);
  stream.pipe(res);
});

app.delete('/delete-file/:filename', authMiddleware, adminMiddleware, async (req, res) => {
  const file = await gfs.files.findOne({ filename: req.params.filename });
  if (!file) return res.status(404).json({ success: false });
  gridFSBucket.delete(file._id, async err => {
    if (err) return res.status(500).json({ success: false });
    await UploadedFile.deleteOne({ filename: file.filename });
    res.json({ success: true });
  });
});

app.post('/send-test-push', (req, res) => {
  const payload = JSON.stringify({ title: 'Reminder', body: 'Test push notification', vibrate: [100, 50, 100] });
  subscriptions.forEach(sub => {
    webPush.sendNotification(sub, payload).catch(err => console.error('Push failed:', err));
  });
  res.json({ success: true });
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
