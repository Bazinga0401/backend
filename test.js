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
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

mongoose.connect(process.env.MONGO_URI).then(() => console.log('MongoDB connected')).catch(console.error);

let gfs, gridFSBucket;
mongoose.connection.once('open', () => {
  gridFSBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
  gfs = Grid(mongoose.connection.db, mongoose.mongo);
  gfs.collection('uploads');
});

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

function adminMiddleware(req, res, next) {
  const allowed = ['Harsh Ninania', 'Satyam Pr'];
  if (!allowed.includes(req.user.username)) return res.status(403).json({ success: false, message: 'Admins only' });
  next();
}

const userSchema = new mongoose.Schema({ username: String, email: String, password: String });
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  day: Number, name: String, time: String, file: String, week: { type: String, enum: ['this', 'next'], default: 'this' }
});
const Task = mongoose.model('Task', taskSchema);

const fileSchema = new mongoose.Schema({ filename: String, originalName: String, uploadedAt: { type: Date, default: Date.now } });
const UploadedFile = mongoose.model('UploadedFile', fileSchema);

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
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ success: false, message: 'User not found' });

  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[username] = { otp, expiresAt: Date.now() + 300000 };

  await transporter.sendMail({ from: process.env.EMAIL_USER, to: user.email, subject: 'OTP for Password Reset', text: `Your OTP is ${otp}` });
  res.json({ success: true, message: 'OTP sent to registered email' });
});

app.post('/verify-reset', async (req, res) => {
  const { username, otp, newPassword } = req.body;
  const record = otpStore[username];
  if (!record || record.otp != otp || Date.now() > record.expiresAt) return res.status(400).json({ success: false, message: 'Invalid/expired OTP' });

  const user = await User.findOne({ username });
  user.password = await bcrypt.hash(newPassword, 10);
  await user.save();
  delete otpStore[username];
  res.json({ success: true, message: 'Password reset successful' });
});

app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const existing = await User.findOne({ username: name });
  if (existing) return res.json({ success: false, message: 'Username exists' });
  await User.create({ username: name, email, password: await bcrypt.hash(password, 10) });
  res.json({ success: true, message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) return res.json({ success: false, message: 'Invalid credentials' });
  const token = jwt.sign({ username: user.username, name: user.username }, SECRET, { expiresIn: '1h' });
  res.json({ success: true, token });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ success: true, name: req.user.name }));

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[email] = { otp, expiresAt: Date.now() + 300000 };

  await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: 'OTP for Signup', text: `Your OTP is ${otp}` });
  res.json({ success: true, message: 'OTP sent' });
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  if (!record || record.otp != otp || Date.now() > record.expiresAt) return res.status(400).json({ success: false, message: 'Invalid/expired OTP' });
  delete otpStore[email];
  res.json({ success: true });
});

app.post('/task', authMiddleware, adminMiddleware, async (req, res) => {
  const { day, name, time, week } = req.body;
  await Task.create({ day, name, time, week });
  res.json({ success: true });
});

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

app.post('/upload', authMiddleware, adminMiddleware, upload.single('file'), async (req, res) => {
  await UploadedFile.create({ filename: req.file.filename, originalName: req.file.originalname });
  res.json({ success: true, file: req.file });
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
  subscriptions.push(req.body);
  res.status(201).json({ success: true });
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

app.listen(process.env.PORT, () => console.log('Server running'));
