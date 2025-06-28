require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const imap = require('imap');
const { simpleParser } = require('mailparser');

const app = express();
const PORT = process.env.PORT || 8080;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB Atlas (booking_db)'))
.catch((err) => console.error('MongoDB connection error:', err));

// Enhanced Booking Schema
const bookingSchema = new mongoose.Schema({
  customerName: String,
  customerEmail: { type: String, required: true },
  customerPhone: String,
  package: String,
  bookingDates: String,
  preWeddingDate: String,
  address: String,
  transactionId: String,
  paymentStatus: { type: String, default: 'pending' },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    default: 'pending' 
  },
  userId: String,
  createdAt: { type: Date, default: Date.now }
});

// Enhanced Message Schema with rich text support
const messageSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  isHtml: { type: Boolean, default: false },
  attachments: [{
    filename: String,
    path: String,
    contentType: String,
    size: Number
  }],
  createdAt: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false },
  notificationSeen: { type: Boolean, default: false },
  isIncoming: { type: Boolean, default: false },
  from: String,
  date: Date,
  messageId: String
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Gallery Schema for image management
const gallerySchema = new mongoose.Schema({
  name: String,
  description: String,
  category: { type: String, enum: ['portraits', 'events', 'products', 'other'] },
  featured: { type: Boolean, default: false },
  imageUrl: { type: String, required: true },
  thumbnailUrl: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Settings Schema for admin panel
const settingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'Joker Creation Studio' },
  siteDescription: { type: String, default: 'Professional Photography Services' },
  contactEmail: { type: String, default: 'contact@jokercreation.com' },
  contactPhone: { type: String, default: '+1234567890' },
  bookingLeadTime: { type: Number, default: 24 }, // in hours
  maxBookingsPerDay: { type: Number, default: 3 },
  cancellationPolicy: String,
  smtpHost: String,
  smtpPort: Number,
  smtpUser: String,
  smtpPass: String,
  fromEmail: { type: String, default: 'no-reply@jokercreation.com' },
  imapHost: { type: String, default: 'imap.hostinger.com' },
  imapPort: { type: Number, default: 993 },
  imapUser: String,
  imapPass: String,
  currency: { type: String, default: 'USD' },
  paymentMethods: { type: [String], default: ['creditCard'] },
  depositPercentage: { type: Number, default: 30 }
});

const Booking = mongoose.model('Booking', bookingSchema);
const Message = mongoose.model('Message', messageSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Gallery = mongoose.model('Gallery', gallerySchema);
const Settings = mongoose.model('Settings', settingsSchema);

app.use(cors({
  origin: ['https://jokercreation.store', 'http://localhost:3000'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Razorpay Setup
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Configure multer for file uploads
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(__dirname, 'uploads');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
  }),
  limits: {
    fileSize: 50 * 1024 * 1024 // 50MB limit per file
  }
});

// Email Transporter with improved configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.hostinger.com',
  port: 465,
  secure: true,
  auth: {
    user: 'contact@jokercreation.store',
    pass: process.env.EMAIL_PASS
  },
  tls: { 
    ciphers: 'SSLv3',
    rejectUnauthorized: false
  },
  logger: true,  // Enable detailed logging
  debug: true    // Show debug output
});

// Initialize admin account and default settings
async function initializeAdmin() {
  try {
    const adminEmail = 'jokercreationbuisness@gmail.com';
    const adminPassword = '9002405641';
    
    const existingAdmin = await Admin.findOne({ email: adminEmail });
    if (!existingAdmin) {
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      const admin = new Admin({
        email: adminEmail,
        password: hashedPassword
      });
      await admin.save();
      console.log('Admin account created successfully');
    }

    // Initialize default settings if they don't exist
    const existingSettings = await Settings.findOne();
    if (!existingSettings) {
      const defaultSettings = new Settings({
        cancellationPolicy: 'Cancellations must be made at least 24 hours in advance for a full refund.',
        imapHost: 'imap.hostinger.com',
        imapPort: 993,
        imapUser: process.env.EMAIL_USER,
        imapPass: process.env.EMAIL_PASS
      });
      await defaultSettings.save();
      console.log('Default settings initialized');
    }
  } catch (err) {
    console.error('Error initializing admin account:', err);
  }
}

initializeAdmin();

// ===== AUTHENTICATION ROUTES ===== //

// Admin login endpoint
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { email: admin.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    res.json({ success: true, token });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin auth middleware
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    req.admin = decoded;
    next();
  } catch (err) {
    console.error('Admin authentication error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
};

// ===== INBOX ROUTES ===== //

// Fetch emails from IMAP server
// [Previous code remains the same until the fetchEmailsFromIMAP function]

// Fetch emails from IMAP server
async function fetchEmailsFromIMAP() {
  try {
    const settings = await Settings.findOne();
    if (!settings) {
      throw new Error('Settings not found');
    }

    return new Promise((resolve, reject) => {
      const imapConfig = {
        user: settings.imapUser || process.env.EMAIL_USER,
        password: settings.imapPass || process.env.EMAIL_PASS,
        host: settings.imapHost || 'imap.hostinger.com',
        port: settings.imapPort || 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false }
      };

      const imapConnection = new imap(imapConfig);
      const emails = [];

      imapConnection.once('ready', () => {
        imapConnection.openBox('INBOX', false, (err, box) => {
          if (err) return reject(err);

          const searchCriteria = ['UNSEEN'];
          const fetchOptions = {
            bodies: ['HEADER', 'TEXT', ''],
            struct: true
          };

          imapConnection.search(searchCriteria, (err, results) => {
            if (err) return reject(err);
            if (results.length === 0) {
              imapConnection.end();
              return resolve([]);
            }

            const fetch = imapConnection.fetch(results, fetchOptions);
            
            fetch.on('message', (msg) => {
              const email = { attachments: [] };
              
              msg.on('body', (stream, info) => {
                let buffer = '';
                stream.on('data', (chunk) => {
                  buffer += chunk.toString('utf8');
                });
                stream.on('end', () => {
                  if (info.which === 'HEADER') {
                    email.headers = imap.parseHeader(buffer);
                  } else if (info.which === 'TEXT') {
                    email.text = buffer;
                  }
                });
              });

              msg.once('attributes', (attrs) => {
                email.uid = attrs.uid;
                email.flags = attrs.flags;
                email.date = attrs.date;
                email.messageId = attrs['x-gm-msgid'] || attrs.uid;
              });

              msg.once('end', () => {
                emails.push(email);
              });
            });

            fetch.once('error', (err) => {
              imapConnection.end();
              reject(err);
            });

            fetch.once('end', () => {
              imapConnection.end();
              resolve(emails);
            });
          });
        });
      });

      imapConnection.once('error', (err) => {
        reject(err);
      });

      imapConnection.connect();
    });
  } catch (err) {
    console.error('Error in fetchEmailsFromIMAP:', err);
    throw err;
  }
}

// [Rest of the code remains the same]

// Sync incoming emails with database
app.post('/api/admin/inbox/sync', authenticateAdmin, async (req, res) => {
  try {
    const emails = await fetchEmailsFromIMAP();
    const savedMessages = [];

    for (const email of emails) {
      const parsed = await simpleParser(email.text);
      
      const existingMessage = await Message.findOne({ messageId: email.messageId });
      if (existingMessage) continue;

      const newMessage = new Message({
        userEmail: parsed.from.value[0].address,
        subject: parsed.subject,
        message: parsed.text || parsed.html,
        isHtml: !!parsed.html,
        isIncoming: true,
        from: parsed.from.text,
        date: parsed.date,
        messageId: email.messageId
      });

      if (parsed.attachments && parsed.attachments.length > 0) {
        const uploadDir = path.join(__dirname, 'uploads', 'attachments');
        if (!fs.existsSync(uploadDir)) {
          fs.mkdirSync(uploadDir, { recursive: true });
        }

        for (const attachment of parsed.attachments) {
          const filename = `${Date.now()}-${attachment.filename}`;
          const filePath = path.join(uploadDir, filename);
          
          fs.writeFileSync(filePath, attachment.content);
          
          newMessage.attachments.push({
            filename: attachment.filename,
            path: filePath,
            contentType: attachment.contentType,
            size: attachment.size
          });
        }
      }

      await newMessage.save();
      savedMessages.push(newMessage);
    }

    res.json({ 
      success: true, 
      message: 'Inbox synced successfully',
      newMessages: savedMessages.length
    });
  } catch (err) {
    console.error('Error syncing inbox:', err);
    res.status(500).json({ error: 'Failed to sync inbox' });
  }
});

// Get inbox messages for admin
app.get('/api/admin/inbox', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, unreadOnly, search } = req.query;
    let query = { isIncoming: true };

    if (unreadOnly === 'true') {
      query.isRead = false;
    }

    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { userEmail: searchRegex },
        { subject: searchRegex },
        { message: searchRegex },
        { from: searchRegex }
      ];
    }

    const skip = (page - 1) * limit;
    const messages = await Message.find(query)
      .sort({ date: -1 })
      .skip(skip)
      .limit(parseInt(limit));

    const total = await Message.countDocuments(query);

    res.json({
      success: true,
      messages,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (err) {
    console.error('Error fetching inbox messages:', err);
    res.status(500).json({ error: 'Failed to fetch inbox messages' });
  }
});

// Mark message as read
app.patch('/api/admin/inbox/:id/read', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findByIdAndUpdate(
      req.params.id,
      { isRead: true },
      { new: true }
    );

    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }

    res.json({ success: true, message });
  } catch (err) {
    console.error('Error marking message as read:', err);
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

// Delete message
app.delete('/api/admin/inbox/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Delete associated attachments
    message.attachments.forEach(att => {
      if (fs.existsSync(att.path)) {
        fs.unlinkSync(att.path);
      }
    });
    
    await message.remove();
    
    res.json({ success: true, message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Error deleting message:', err);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Get inbox statistics
app.get('/api/admin/inbox/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalMessages = await Message.countDocuments({ isIncoming: true });
    const unreadMessages = await Message.countDocuments({ 
      isIncoming: true, 
      isRead: false 
    });
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayMessages = await Message.countDocuments({ 
      isIncoming: true,
      date: { $gte: today } 
    });

    res.json({
      success: true,
      stats: {
        total: totalMessages,
        unread: unreadMessages,
        today: todayMessages
      }
    });
  } catch (err) {
    console.error('Error fetching inbox stats:', err);
    res.status(500).json({ error: 'Failed to fetch inbox stats' });
  }
});

// [Rest of your existing routes...]

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Static files and server start
app.use(express.static('public'));

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
