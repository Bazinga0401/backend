require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const Busboy = require('busboy');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(cors({
  origin: ["https://bazinga0401.github.io", "http://localhost:5500"],
  credentials: true
}));

// === Mongo Setup ===
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

let gridFSBucket;
mongoose.connection.once('open', () => {
  gridFSBucket = new mongoose.mongo.GridFSBucket(mongoose.connection.db, { bucketName: 'uploads' });
  console.log('✅ GridFS Ready');
});

// === Models ===
const userSchema = new mongoose.Schema({ username: String, email: String, password: String });
const User = mongoose.model('User', userSchema);

const otpStore = {};

const fileSchema = new mongoose.Schema({ filename: String, originalName: String });
const UploadedFile = mongoose.model('UploadedFile', fileSchema);

const taskSchema = new mongoose.Schema({ day: Number, name: String, time: String, file: String, week: String });
const Task = mongoose.model('Task', taskSchema);

// === Middleware ===
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'No token' });
  try {
    req.user = jwt.verify(token, process.env.SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, message: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  const admins = ['Satyam Pr', 'Harsh Ninania'];
  if (!admins.includes(req.user.username)) return res.status(403).json({ success: false, message: 'Admin only' });
  next();
}

// === Email Setup ===
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

// === Routes ===
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  const existing = await User.findOne({ username: name });
  if (existing) return res.json({ success: false, message: 'Username taken' });
  const hashed = await bcrypt.hash(password, 10);
  await User.create({ username: name, email, password: hashed });
  res.json({ success: true });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.json({ success: false, message: 'Invalid credentials' });
  }
  const token = jwt.sign({ username }, process.env.SECRET, { expiresIn: '1h' });
  res.json({ success: true, token });
});

app.get('/api/me', authMiddleware, (req, res) => {
  res.json({ success: true, name: req.user.username });
});

app.post('/api/send-otp', async (req, res) => {
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000);
  otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };
  await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject: 'Your OTP', text: `OTP: ${otp}` });
  res.json({ success: true });
});

app.post('/api/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  const record = otpStore[email];
  if (!record || record.otp != otp || Date.now() > record.expiresAt) return res.status(400).json({ success: false });
  delete otpStore[email];
  res.json({ success: true });
});

app.post('/task', authMiddleware, adminMiddleware, async (req, res) => {
  const { day, name, time, week } = req.body;
  await Task.create({ day, name, time, week });
  res.json({ success: true });
});

app.get('/tasks', authMiddleware, async (req, res) => {
  const tasks = await Task.find();
  res.json({ success: true, tasks });
});

app.delete('/task/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await Task.findByIdAndDelete(req.params.id);
  res.json({ success: true });
});

app.patch('/task/:id/add-file', authMiddleware, adminMiddleware, async (req, res) => {
  const { filename } = req.body;
  const updated = await Task.findByIdAndUpdate(req.params.id, { file: filename }, { new: true });
  res.json({ success: true, task: updated });
});

app.patch('/task/:id/remove-file', authMiddleware, adminMiddleware, async (req, res) => {
  const updated = await Task.findByIdAndUpdate(req.params.id, { $unset: { file: '' } }, { new: true });
  res.json({ success: true, task: updated });
});

// === File Upload ===
app.post('/upload', authMiddleware, adminMiddleware, (req, res) => {
  const busboy = new Busboy({ headers: req.headers });
  let fileSaved = false;

  busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
    const uploadStream = gridFSBucket.openUploadStream(filename, {
      contentType: mimetype,
      metadata: { originalName: filename }
    });

    file.pipe(uploadStream)
      .on('error', err => res.status(500).json({ success: false, message: 'Upload error' }))
      .on('finish', async () => {
        await UploadedFile.create({ filename: uploadStream.id.toString(), originalName: filename });
        fileSaved = true;
        res.json({ success: true, file: { filename: uploadStream.id.toString(), originalName: filename } });
      });
  });

  req.pipe(busboy);
});

app.get('/download/:filename', authMiddleware, async (req, res) => {
  try {
    const meta = await UploadedFile.findOne({ filename: req.params.filename });
    const readStream = gridFSBucket.openDownloadStream(new mongoose.Types.ObjectId(req.params.filename));
    res.set('Content-Disposition', `attachment; filename=\"${meta.originalName}\"`);
    readStream.pipe(res);
  } catch {
    res.status(404).json({ success: false, message: 'File not found' });
  }
});

app.delete('/delete-file/:filename', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    await gridFSBucket.delete(new mongoose.Types.ObjectId(req.params.filename));
    await UploadedFile.deleteOne({ filename: req.params.filename });
    res.json({ success: true });
  } catch {
    res.status(500).json({ success: false });
  }
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
