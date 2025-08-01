require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const cron = require('node-cron');
const multer = require('multer');
const path = require('path');
const moment = require('moment-timezone');
const fs = require('fs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { GridFsStorage } = require('multer-gridfs-storage');
const Grid = require('gridfs-stream');
const admin = require('firebase-admin');
// const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

// const Subscription = require('./subscription');
// admin.initializeApp({
//   credential: admin.credential.cert(serviceAccount)
// });

const FCMToken = mongoose.model('FCMToken', new mongoose.Schema({ token: String }));

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
  const allowed = ['Harsh Ninania', 'Bazinga!', '24119080','24119081'];
  if (!allowed.includes(req.user.username)) return res.status(403).json({ success: false, message: 'Admins only' });
  next();
}
// Mongoose Models

const userSchema = new mongoose.Schema({
   username: String,
  email: String,
  password: String,
  subbatch: String});
const User = mongoose.model('User', userSchema);

const taskSchema = new mongoose.Schema({
  day: Number,
  name: String,
  time: String,
  file: String,
  week: { type: String, enum: ['this', 'next'], default: 'this' },
  subbatch: { type: String, required: true }
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
  const { name, email, password, subbatch } = req.body;

  if (!email.endsWith('@me.iitr.ac.in')) {
    return res.status(400).json({ success: false, message: 'Only IITR emails are allowed' });
  }

  const existing = await User.findOne({ username: name });
  if (existing) {
    return res.json({ success: false, message: 'Username already exists' });
  }

  const hashed = await bcrypt.hash(password, 10);

  try {
    await User.create({ username: name, email, password: hashed, subbatch });
    res.json({ success: true, message: 'User registered' });

  } catch (err) {
    if (err.code === 11000 && err.keyPattern?.email) {
      console.warn('⚠️ Duplicate email but ignoring for testing:', email);
      return res.json({
        success: true,
        message: 'Duplicate email allowed for testing (not saved again)'
      });
    }

    console.error('❌ Signup error:', err);
    res.status(500).json({ success: false, message: 'Server error during signup' });
  }
});



app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.json({ success: false, message: 'User not found' });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.json({ success: false, message: 'Incorrect password' });

  // ✅ Include name in token payload for /api/me
  const token = jwt.sign({ username: user.username, name: user.username,  subbatch: user.subbatch }, SECRET, { expiresIn: '150d' });
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


//New task routes will send notificaitons useing sendMultiCast
app.post('/task', authMiddleware, adminMiddleware, async (req, res) => {


  try {
    const { day, name, time, file, week } = req.body;
    const subbatch = req.user.subbatch; // ✅ Secure from token

    const newTask = new Task({
      day,
      name,
      time,
      file,
      week,
      subbatch
    });

    await newTask.save();

    // ✅ Notify users from same subbatch
    const users = await User.find({ subbatch });
    const notifications = users.map(user => {
      if (user.fcmToken) {
        return sendPushNotification(user.fcmToken, {
          title: 'Breaking News: You Have a Task 📰',
          body: `${name} at ${time} (${week === 'this' ? 'This Week' : 'Next Week'})`,
        });
      }
    });

    await Promise.all(notifications);

    res.status(201).json({ success: true, task: newTask });

  } catch (err) {
  console.error('Error creating task:', err);
  res.status(500).json({ success: false, message: 'Server error' });
}

});





// Task routes

app.get('/task', authMiddleware, async (req, res) => {
  try {
    const subbatch = req.user.subbatch;
    const tasks = await Task.find({ subbatch });
    res.json({ success: true, tasks }); // ✅ Fixed structure
  } catch (err) {
    console.error('Error fetching tasks:', err);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

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
app.get('/preview/:filename' ,async (req, res) => {
  try {
    const { filename } = req.params;
    const file = await gfs.files.findOne({ filename });
    if (!file) return res.status(404).json({ success: false, message: 'File not found' });

    const readStream = gridFSBucket.openDownloadStream(file._id);

    res.setHeader('Content-Type', file.contentType || 'application/octet-stream');
    res.setHeader('Content-Disposition', 'inline'); // 👁️ allows preview
    readStream.pipe(res);
  } catch (err) {
    console.error('[Preview Error]', err);
    res.status(500).json({ success: false, message: 'Server error' });
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

app.post('/fcm-subscribe', authMiddleware, async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ success: false, message: 'Token missing' });

  try {
    await FCMToken.findOneAndUpdate({ token }, { token, subbatch: req.user.subbatch }, { upsert: true });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: 'DB error' });
  }
});


app.post('/send-fcm', async (req, res) => {
  const tokens = await FCMToken.find();

  const message = {
    notification: {
      title: '🔥 Task Reminder!',
      body: 'This is a Firebase test push!',
    }
  };

  for (const entry of tokens) {
  try {
    await admin.messaging().send({
      token: entry.token,
      notification: {
        title: '🆕 New Task!',
        body: 'Check your new task!'
      }
    });
  } catch (err) {
    console.error('[FCM ERROR]', err);

    // 🛠️ Clean up invalid tokens from DB
    if (err.code === 'messaging/registration-token-not-registered') {
      await FCMToken.deleteOne({ token: entry.token });
      console.log('🧹 Removed invalid FCM token:', entry.token);
    }
  }}}
);

app.post('/subscribe', async (req, res) => {
  const sub = req.body;

  // 🛡️ Validate: if endpoint is missing, reject
  if (!sub || !sub.endpoint) {
    console.error('❌ Invalid subscription received');
    return res.status(400).json({ success: false, message: 'Invalid subscription' });
  }

  try {
    await Subscription.findOneAndUpdate(
      { endpoint: sub.endpoint },
      sub,
      { upsert: true, new: true }
    );
    res.status(201).json({ success: true, message: 'Subscribed' });
  } catch (err) {
    console.error('Subscription save error:', err);
    res.status(500).json({ success: false, message: 'Subscription failed' });
  }
});



// Every Monday 00:00 IST — clear old "this" week & promote "next" week
cron.schedule('0 0 * * 1', async () => {
  console.log('[CRON] ⏰ Weekly rotation triggered');

  try {
    const oldTasks = await Task.find({ week: 'this' });

    for (const task of oldTasks) {
      // Delete associated file if any
      if (task.file) {
        const file = await gfs.files.findOne({ filename: task.file });
        if (file) {
          await gridFSBucket.delete(file._id);
          await UploadedFile.deleteOne({ filename: task.file });
          console.log(`[CRON] 🗑 Deleted file: ${task.file}`);
        }
      }

      // Delete the task
      await Task.findByIdAndDelete(task._id);
      console.log(`[CRON] 🗑 Deleted task: ${task.name}`);
    }

    // Promote "next" week → "this" week
    await Task.updateMany({ week: 'next' }, { $set: { week: 'this' } });

    console.log('[CRON] ✅ Next week promoted to this week');
  } catch (err) {
    console.error('[CRON ERROR]', err);
  }
}, {
  timezone: 'Asia/Kolkata'
});

//dont forget it uses 24 hour format
cron.schedule('45 17 * * *', async () => {
  const nowIST = moment().tz('Asia/Kolkata');
  const tomorrow = nowIST.clone().add(1, 'day');

  const jsTomorrowDay = tomorrow.day(); // JS: Sunday = 0
  const dbTomorrowDay = (jsTomorrowDay + 6) % 7; // Convert to DB style: Monday = 0

  console.log('[DEBUG] Now IST:', nowIST.format());
  console.log('[DEBUG] Tomorrow:', tomorrow.format());
  console.log('[DEBUG] DB Day (0=Mon):', dbTomorrowDay);

  try {
    if(dbTomorrowDay== 0){
      const tasks = await Task.find({ day: dbTomorrowDay, week: 'next' });
    const tokenDocs = await FCMToken.find();
    const tokens = tokenDocs.map(doc => doc.token).filter(Boolean);

    if (tokens.length === 0) {
      console.log('[INFO] No tokens found, skipping FCM push.');
      return;
    }

    for (const task of tasks) {
      const message = {
        notification: {
          title: 'Breaking News: You Have a Task 📰',
          body: `"${task.name}" is scheduled for tomorrow at ${task.time}`
        },
        tokens: tokens // sendMulticast requires this key
      };

      try {
        const response = await admin.messaging().sendEachForMulticast(message);
        console.log(`[FCM] Sent task "${task.name}" to ${response.successCount}/${tokens.length} devices.`);
        if (response.failureCount > 0) {
          response.responses.forEach((resp, idx) => {
            if (!resp.success) {
              console.error(`[FCM ERROR] Token: ${tokens[idx]} =>`, resp.error?.message);
            }
          });
        }
      } catch (err) {
        console.error('[FCM MULTICAST ERROR]', err.message || err);
      }
    }

    console.log(`[CRON] Processed ${tasks.length} tasks for day ${dbTomorrowDay}.`);
  }
    
    else {
    const tasks = await Task.find({ day: dbTomorrowDay, week: 'this' });
    const tokenDocs = await FCMToken.find();
    const tokens = tokenDocs.map(doc => doc.token).filter(Boolean);

    if (tokens.length === 0) {
      console.log('[INFO] No tokens found, skipping FCM push.');
      return;
    }

    for (const task of tasks) {
      const message = {
        notification: {
          title: 'Breaking News: You Have a Task 📰',
          body: `"${task.name}" is scheduled for tomorrow at ${task.time}`
        },
        tokens: tokens // sendMulticast requires this key
      };

      try {
        const response = await admin.messaging().sendEachForMulticast(message);
        console.log(`[FCM] Sent task "${task.name}" to ${response.successCount}/${tokens.length} devices.`);
        if (response.failureCount > 0) {
          response.responses.forEach((resp, idx) => {
            if (!resp.success) {
              console.error(`[FCM ERROR] Token: ${tokens[idx]} =>`, resp.error?.message);
            }
          });
        }
      } catch (err) {
        console.error('[FCM MULTICAST ERROR]', err.message || err);
      }
    }

    console.log(`[CRON] Processed ${tasks.length} tasks for day ${dbTomorrowDay}.`);
  }}
   
  
  catch (err) {
    console.error('[CRON ERROR]', err);
  }
}, {
  timezone: 'Asia/Kolkata'
});


app.get('/send-test-push', (req, res) => {
  res.send('✅ Route exists and server is running');
});

// Start server
const PORT = process.env.PORT;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

