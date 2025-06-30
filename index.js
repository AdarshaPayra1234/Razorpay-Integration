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
const router = express.Router();
const { google } = require('googleapis');
require('dotenv').config();
const { Client } = require('@microsoft/microsoft-graph-client');
const { ClientSecretCredential } = require('@azure/identity');
// Use your existing registration details
const credential = new ClientSecretCredential(
  process.env.MS_TENANT_ID,      // '6b193320-9c27-4df8-babd-6f8f43cf7e22'
  process.env.MS_CLIENT_ID,      // '5348d1ae-6a95-481e-a996-8ffa7a8ff3a6'
  process.env.MS_CLIENT_SECRET   // Paste the secret from Step 1
);
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);
const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
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

const client = Client.initWithMiddleware({
  authProvider: {
    getAccessToken: async () => {
      const token = await credential.getToken([
        'https://graph.microsoft.com/.default'
      ]);
      return token.token;
    }
  }
});

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
// Gmail Sync Schema
const gmailSyncSchema = new mongoose.Schema({
  email: { type: String, required: true },
  subject: String,
  snippet: String,
  from: String,
  date: { type: Date, default: Date.now },
  messageId: { type: String, required: true, unique: true },
  labels: [String],
  isRead: { type: Boolean, default: false },
  isStarred: { type: Boolean, default: false },
  syncedAt: { type: Date, default: Date.now }
});

const GmailSync = mongoose.model('GmailSync', gmailSyncSchema);


// 1. First add CORS configuration
const corsOptions = {
  origin: ['https://jokercreation.store', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200
};

// 2. Apply CORS middleware
app.use(cors(corsOptions));

// 3. Handle OPTIONS requests for all routes
app.options('*', cors(corsOptions));

// 4. Then add other middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// 5. Then your routes
app.use('/api', require('./routes'));

// ... rest of your server code

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
  logger: true,
  debug: true
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

const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing' });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (decoded.role !== 'admin') {
        return res.status(403).json({ error: 'Access denied' });
      }
      req.admin = decoded;
      return next();
    } catch (tokenError) {
      if (tokenError.name === 'TokenExpiredError') {
        // Attempt to refresh token
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
          return res.status(401).json({ error: 'Token expired and no refresh token available' });
        }

        const refreshDecoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const admin = await Admin.findOne({ email: refreshDecoded.email });
        
        if (!admin) {
          return res.status(401).json({ error: 'Invalid refresh token' });
        }

        const newToken = jwt.sign(
          { email: admin.email, role: 'admin' },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );

        // Set the new token in the response header
        res.set('New-Access-Token', newToken);
        req.admin = refreshDecoded;
        return next();
      }
      throw tokenError;
    }
  } catch (err) {
    console.error('Admin authentication error:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
};



// Outlook Sync Route
app.get('/api/outlook/sync', authenticateAdmin, async (req, res) => {
  console.log('Sync endpoint hit'); // Add this
  try {
    console.log('Attempting IMAP connection...'); // Add this
    const imap = new Imap({
      user: process.env.OUTLOOK_EMAIL,
      password: process.env.OUTLOOK_PASSWORD,
      host: 'imap.hostinger.com',
      port: 993,
      tls: true,
      authTimeout: 10000
    });

    const emails = [];

    imap.once('ready', () => {
      imap.openBox('INBOX', false, (err, box) => {
        if (err) throw new Error('Failed to open mailbox');

        imap.search(['UNSEEN'], (err, results) => {
          if (err) throw new Error('Email search failed');

          const fetch = imap.fetch(results, {
            bodies: ['HEADER', 'TEXT'],
            markSeen: false
          });

          fetch.on('message', msg => {
            let email = {};
            msg.on('body', stream => {
              simpleParser(stream, (err, parsed) => {
                email = {
                  from: parsed.from?.value[0]?.address || parsed.from?.text || 'Unknown',
                  subject: parsed.subject || 'No Subject',
                  text: parsed.text || '',
                  date: parsed.date || new Date()
                };
              });
            });

            msg.once('end', () => {
              emails.push(email);
            });
          });

          fetch.once('end', () => {
            imap.end();
            res.json({ messages: emails });
          });
        });
      });
    });

    imap.once('error', err => {
      throw err;
    });

    imap.connect();

  } catch (err) {
    console.error('Full sync error:', err); // Enhanced logging
    res.status(500).json({ 
      error: 'Failed to sync emails',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});


// ===== GMAIL SYNC ROUTES ===== //

// Token verification endpoint (already in your frontend)
app.post('/api/admin/verify-token', authenticateAdmin, async (req, res) => {
  try {
    res.json({ 
      success: true, 
      isAdmin: true,
      admin: req.admin
    });
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== AUTHENTICATION ROUTES ===== //

// ... (your existing admin login and authenticateAdmin middleware code remains here) ...

// ===== GMAIL SYNC ROUTES ===== //
// Fetch emails without user login
app.get('/api/emails', async (req, res) => {
  try {
    const emails = await client
      .api('/me/messages')
      .top(25)
      .get();
    res.json(emails);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add this new route here
app.get('/api/gmail/sync', authenticateAdmin, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    if (!settings?.googleAccessToken) {
      return res.status(400).json({ 
        error: 'Google OAuth not configured',
        message: 'Please authenticate with Google first'
      });
    }

    // Set credentials from database
    oauth2Client.setCredentials({
      access_token: settings.googleAccessToken,
      refresh_token: settings.googleRefreshToken
    });

    // Get messages from Gmail API
    const { data } = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 50,
      q: 'is:unread'
    });

    if (!data.messages || data.messages.length === 0) {
      return res.json({ 
        success: true, 
        message: 'No new messages found',
        messages: []
      });
    }

    const savedMessages = [];
    for (const msg of data.messages) {
      try {
        const message = await gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'full'
        });

        const headers = message.data.payload.headers.reduce((acc, header) => {
          acc[header.name.toLowerCase()] = header.value;
          return acc;
        }, {});

        const existing = await GmailSync.findOne({ messageId: msg.id });
        if (existing) continue;

        const gmailMessage = new GmailSync({
          email: headers.from,
          subject: headers.subject || 'No Subject',
          snippet: message.data.snippet,
          from: headers.from,
          date: new Date(parseInt(message.data.internalDate)),
          messageId: msg.id,
          isRead: !message.data.labelIds.includes('UNREAD')
        });

        await gmailMessage.save();
        savedMessages.push(gmailMessage);

        // Mark as read if needed
        if (!message.data.labelIds.includes('UNREAD')) {
          await gmail.users.messages.modify({
            userId: 'me',
            id: msg.id,
            requestBody: {
              removeLabelIds: ['UNREAD']
            }
          });
        }
      } catch (err) {
        console.error('Error processing message:', err);
      }
    }

    res.json({ 
      success: true, 
      message: `Synced ${savedMessages.length} new messages`,
      messages: savedMessages
    });
  } catch (err) {
    console.error('Gmail sync error:', err);
    res.status(500).json({ 
      error: 'Failed to sync Gmail messages',
      details: err.message
    });
  }
});

// ===== BOOKING ROUTES ===== //

// ... (your existing booking routes continue here) ...

// ===== GOOGLE OAUTH ROUTES ===== //

// Initiate Google OAuth flow
app.get('/api/gmail/auth', authenticateAdmin, (req, res) => {
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/gmail.readonly',
      'https://www.googleapis.com/auth/gmail.modify'
    ],
    prompt: 'consent'
  });
  res.json({ authUrl: url });
});

// OAuth callback handler
app.get('/api/gmail/auth/callback', authenticateAdmin, async (req, res) => {
  try {
    const { code } = req.query;
    const { tokens } = await oauth2Client.getToken(code);
    
    oauth2Client.setCredentials(tokens);
    
    // Save tokens to database or .env
    process.env.GOOGLE_ACCESS_TOKEN = tokens.access_token;
    if (tokens.refresh_token) {
      process.env.GOOGLE_REFRESH_TOKEN = tokens.refresh_token;
    }
    
    // Save tokens to settings in database
    await Settings.findOneAndUpdate(
      {},
      { 
        googleAccessToken: tokens.access_token,
        googleRefreshToken: tokens.refresh_token,
        googleTokenExpiry: tokens.expiry_date
      },
      { upsert: true }
    );
    
    res.redirect('/admin?gmail_auth=success');
  } catch (err) {
    console.error('Google OAuth callback error:', err);
    res.redirect('/admin?gmail_auth=error');
  }
});

// Check auth status
app.get('/api/gmail/auth/status', authenticateAdmin, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    const isAuthenticated = !!settings?.googleAccessToken;
    res.json({ authenticated: isAuthenticated });
  } catch (err) {
    console.error('Error checking auth status:', err);
    res.status(500).json({ error: 'Failed to check auth status' });
  }
});

// Get synced messages
app.get('/api/admin/gmail-messages', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    let query = { isIncoming: true };

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
    console.error('Error fetching Gmail messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});
// Google OAuth configuration endpoint
app.get('/api/admin/google-oauth-config', authenticateAdmin, async (req, res) => {
  try {
    res.json({
      success: true,
      config: {
        apiKey: process.env.GOOGLE_API_KEY,
        clientId: process.env.GOOGLE_CLIENT_ID,
        scope: 'https://www.googleapis.com/auth/gmail.readonly',
        discoveryDocs: ["https://www.googleapis.com/discovery/v1/apis/gmail/v1/rest"]
      }
    });
  } catch (err) {
    console.error('Error fetching Google OAuth config:', err);
    res.status(500).json({ error: 'Failed to fetch OAuth config' });
  }
});

// Token refresh endpoint (for frontend)
app.post('/api/admin/refresh-token', async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
      return res.status(401).json({ error: 'Refresh token missing' });
    }

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const admin = await Admin.findOne({ email: decoded.email });
    
    if (!admin) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }

    const newToken = jwt.sign(
      { email: admin.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.json({ 
      success: true, 
      token: newToken 
    });
  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// ===== BOOKING ROUTES ===== //

app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (status && ['pending', 'confirmed', 'cancelled', 'completed'].includes(status)) {
      query.status = status;
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { customerName: searchRegex },
        { customerEmail: searchRegex },
        { package: searchRegex },
        { transactionId: searchRegex },
        { _id: searchRegex }
      ];
    }
    
    const skip = (page - 1) * limit;
    const bookings = await Booking.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Booking.countDocuments(query);
    
    res.json({ 
      success: true, 
      bookings,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

app.get('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    if (!booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    res.json({ success: true, booking });
  } catch (err) {
    console.error('Error fetching booking:', err);
    res.status(500).json({ error: 'Failed to fetch booking' });
  }
});

app.get('/api/admin/bookings/stats', authenticateAdmin, async (req, res) => {
  try {
    const pendingCount = await Booking.countDocuments({ status: 'pending' });
    const confirmedCount = await Booking.countDocuments({ status: 'confirmed' });
    const cancelledCount = await Booking.countDocuments({ status: 'cancelled' });
    const completedCount = await Booking.countDocuments({ status: 'completed' });
    
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayBookings = await Booking.countDocuments({ 
      createdAt: { $gte: today } 
    });
    
    const firstDayOfMonth = new Date(today.getFullYear(), today.getMonth(), 1);
    const monthlyBookings = await Booking.countDocuments({
      createdAt: { $gte: firstDayOfMonth }
    });
    
    res.json({
      success: true,
      stats: {
        total: pendingCount + confirmedCount + cancelledCount + completedCount,
        pending: pendingCount,
        confirmed: confirmedCount,
        cancelled: cancelledCount,
        completed: completedCount,
        today: todayBookings,
        monthly: monthlyBookings
      }
    });
  } catch (err) {
    console.error('Error fetching booking stats:', err);
    res.status(500).json({ error: 'Failed to fetch booking stats' });
  }
});

app.patch('/api/admin/bookings/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    
    const statusUpdateHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #00acc1; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Booking Status Update</h1>
      </div>
      <div class="content">
        <p>Dear ${booking.customerName},</p>
        <p>The status of your booking (ID: ${booking._id}) has been updated to <strong>${status}</strong>.</p>
        <p>If you have any questions, please don't hesitate to contact us.</p>
        <p>Best regards,<br>The Joker Creation Studio Team</p>
      </div>
    </body>
    </html>
    `;
    
    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: booking.customerEmail,
      subject: `Your Booking Status Has Been Updated to ${status}`,
      html: statusUpdateHtml
    });
    
    res.json({ success: true, booking });
  } catch (err) {
    console.error('Error updating booking:', err);
    res.status(500).json({ error: 'Failed to update booking' });
  }
});

// ===== USER MANAGEMENT ROUTES ===== //

app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { search, filter, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { email: searchRegex },
        { name: searchRegex },
        { phone: searchRegex }
      ];
    }
    
    if (filter === 'verified') {
      query.emailVerified = true;
    } else if (filter === 'unverified') {
      query.emailVerified = false;
    } else if (filter === 'active') {
      query.isActive = true;
    } else if (filter === 'inactive') {
      query.isActive = false;
    }
    
    const skip = (page - 1) * limit;
    const users = await Booking.aggregate([
      {
        $group: {
          _id: "$customerEmail",
          name: { $first: "$customerName" },
          phone: { $first: "$customerPhone" },
          bookingsCount: { $sum: 1 },
          lastBooking: { $max: "$createdAt" }
        }
      },
      { $match: query },
      { $sort: { lastBooking: -1 } },
      { $skip: skip },
      { $limit: parseInt(limit) }
    ]);
    
    const total = await Booking.aggregate([
      { $group: { _id: "$customerEmail" } },
      { $count: "total" }
    ]);
    
    res.json({
      success: true,
      users,
      total: total.length > 0 ? total[0].total : 0,
      totalPages: Math.ceil((total.length > 0 ? total[0].total : 0) / limit),
      currentPage: parseInt(page)
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.get('/api/admin/users/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalUsers = await Booking.aggregate([
      { $group: { _id: "$customerEmail" } },
      { $count: "total" }
    ]);
    
    const verifiedUsers = await Booking.aggregate([
      { $match: { customerEmail: { $ne: null } } },
      { $group: { _id: "$customerEmail" } },
      { $count: "total" }
    ]);
    
    res.json({
      success: true,
      stats: {
        totalUsers: totalUsers.length > 0 ? totalUsers[0].total : 0,
        verifiedUsers: verifiedUsers.length > 0 ? verifiedUsers[0].total : 0,
        googleUsers: 0,
        activeUsers: totalUsers.length > 0 ? totalUsers[0].total : 0
      }
    });
  } catch (err) {
    console.error('Error fetching user stats:', err);
    res.status(500).json({ error: 'Failed to fetch user stats' });
  }
});

// ===== MESSAGE ROUTES ===== //

app.post('/api/admin/messages', authenticateAdmin, upload.array('attachments', 5), async (req, res) => {
  try {
    const { userEmails, subject, message, isHtml } = req.body;
    const files = req.files || [];
    
    if (!userEmails || !subject || !message) {
      files.forEach(file => fs.unlinkSync(file.path));
      return res.status(400).json({ error: 'Recipients, subject and message are required' });
    }
    
    const emails = Array.isArray(userEmails) ? userEmails : JSON.parse(userEmails);
    if (!Array.isArray(emails) || emails.length === 0) {
      files.forEach(file => fs.unlinkSync(file.path));
      return res.status(400).json({ error: 'At least one recipient is required' });
    }
    
    const attachments = files.map(file => ({
      filename: file.originalname,
      path: file.path,
      contentType: file.mimetype,
      size: file.size
    }));

    const savedMessages = [];
    for (const email of emails) {
      const newMessage = new Message({
        userEmail: email,
        subject,
        message,
        isHtml: isHtml === 'true',
        attachments
      });
      
      await newMessage.save();
      savedMessages.push(newMessage);
    }
    
    const mailOptions = {
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: emails.join(','),
      subject: subject,
      html: isHtml === 'true' ? message : `<pre>${message}</pre>`,
      attachments: files.map(file => ({
        filename: file.originalname,
        path: file.path,
        contentType: file.mimetype
      }))
    };

    await transporter.sendMail(mailOptions);
    
    files.forEach(file => fs.unlinkSync(file.path));
    
    res.json({ 
      success: true, 
      messages: savedMessages.map(msg => ({
        ...msg.toObject(),
        attachments: msg.attachments.map(att => ({
          filename: att.filename,
          contentType: att.contentType,
          size: att.size
        }))
      }))
    });
  } catch (err) {
    console.error('Error sending message:', err);
    
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to send message' });
  }
});

app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { filter, search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (filter === 'today') {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      query.createdAt = { $gte: today };
    } else if (filter === 'week') {
      const oneWeekAgo = new Date();
      oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
      query.createdAt = { $gte: oneWeekAgo };
    } else if (filter === 'month') {
      const oneMonthAgo = new Date();
      oneMonthAgo.setMonth(oneMonthAgo.getMonth() - 1);
      query.createdAt = { $gte: oneMonthAgo };
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { userEmail: searchRegex },
        { subject: searchRegex },
        { message: searchRegex }
      ];
    }
    
    const skip = (page - 1) * limit;
    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Message.countDocuments(query);
    
    const sanitizedMessages = messages.map(msg => ({
      ...msg.toObject(),
      attachments: msg.attachments.map(att => ({
        filename: att.filename,
        contentType: att.contentType,
        size: att.size
      }))
    }));
    
    res.json({ 
      success: true, 
      messages: sanitizedMessages,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

app.get('/api/admin/messages/recent', authenticateAdmin, async (req, res) => {
  try {
    const messages = await Message.find()
      .sort({ createdAt: -1 })
      .limit(5);
    
    res.json({ success: true, messages });
  } catch (err) {
    console.error('Error fetching recent messages:', err);
    res.status(500).json({ error: 'Failed to fetch recent messages' });
  }
});

app.get('/api/admin/messages/attachment/:messageId/:attachmentId', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    const attachment = message.attachments.id(req.params.attachmentId);
    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }
    
    if (!fs.existsSync(attachment.path)) {
      return res.status(404).json({ error: 'Attachment file not found' });
    }
    
    res.download(attachment.path, attachment.filename);
  } catch (err) {
    console.error('Error downloading attachment:', err);
    res.status(500).json({ error: 'Failed to download attachment' });
  }
});

app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
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

// ===== INBOX ROUTES ===== //

// Add this to your existing backend code (don't remove anything else)

// Enhanced IMAP Email Fetching Function
async function fetchEmailsFromIMAP() {
  try {
    const settings = await Settings.findOne();
    if (!settings) {
      throw new Error('IMAP settings not found in database');
    }

    if (!settings.imapUser || !settings.imapPass) {
      throw new Error('IMAP credentials not configured');
    }

    return new Promise((resolve, reject) => {
      const imapConn = new imap({
        user: settings.imapUser,
        password: settings.imapPass,
        host: settings.imapHost || 'imap.hostinger.com',
        port: settings.imapPort || 993,
        tls: true,
        tlsOptions: { rejectUnauthorized: false },
        authTimeout: 30000,
        debug: console.log
      });

      const emails = [];

      imapConn.once('ready', () => {
        imapConn.openBox('INBOX', false, (err, box) => {
          if (err) {
            imapConn.end();
            return reject(err);
          }

          const searchCriteria = ['UNSEEN']; // Only fetch unread messages
          const fetchOptions = {
            bodies: ['HEADER', 'TEXT'],
            struct: true,
            markSeen: false // Don't mark messages as seen
          };

          imapConn.search(searchCriteria, (err, results) => {
            if (err) {
              imapConn.end();
              return reject(err);
            }
            
            if (results.length === 0) {
              imapConn.end();
              return resolve([]);
            }

            const fetch = imapConn.fetch(results, fetchOptions);
            let emailBuffer = '';

            fetch.on('message', (msg) => {
              const email = { attachments: [] };

              msg.on('body', (stream, info) => {
                stream.on('data', (chunk) => {
                  emailBuffer += chunk.toString('utf8');
                });

                stream.on('end', () => {
                  if (info.which === 'HEADER') {
                    email.headers = imap.parseHeader(emailBuffer);
                  } else if (info.which === 'TEXT') {
                    email.text = emailBuffer;
                  }
                  emailBuffer = '';
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
              imapConn.end();
              reject(err);
            });

            fetch.once('end', () => {
              imapConn.end();
              resolve(emails);
            });
          });
        });
      });

      imapConn.once('error', (err) => {
        console.error('IMAP connection error:', err);
        reject(err);
      });

      imapConn.connect();
    });
  } catch (err) {
    console.error('Error in fetchEmailsFromIMAP:', err);
    throw err;
  }
}
// Temporary test route
app.get('/api/admin/test-imap', authenticateAdmin, async (req, res) => {
  try {
    const emails = await fetchEmailsFromIMAP();
    console.log('Fetched emails:', emails.length);
    res.json({ success: true, count: emails.length });
  } catch (err) {
    console.error('Test failed:', err);
    res.status(500).json({ error: err.message });
  }
});
// Enhanced Email Sync Endpoint
app.post('/api/admin/inbox/sync', authenticateAdmin, async (req, res) => {
  try {
    console.log('[SYNC] Starting email synchronization process...');
    
    // First verify IMAP settings exist
    const settings = await Settings.findOne();
    if (!settings || !settings.imapUser || !settings.imapPass) {
      return res.status(400).json({
        success: false,
        error: 'IMAP settings not configured',
        message: 'Please configure your IMAP settings in the admin panel'
      });
    }

    // Step 1: Fetch emails from IMAP
    console.log('[SYNC] Fetching emails from IMAP server...');
    const emails = await fetchEmailsFromIMAP();
    console.log(`[SYNC] Found ${emails.length} emails in IMAP inbox`);
    
    const savedMessages = [];
    let skippedCount = 0;
    let errorCount = 0;

    // Step 2: Process each email
    for (const [index, email] of emails.entries()) {
      try {
        console.log(`[SYNC] Processing email ${index + 1}/${emails.length}`);
        
        // Parse the email
        console.log('[SYNC] Parsing email content...');
        const parsed = await simpleParser(email.text);
        
        // Check for existing message
        console.log('[SYNC] Checking if message already exists in database...');
        const existingMessage = await Message.findOne({ 
          $or: [
            { messageId: email.messageId },
            { 
              from: parsed.from?.text,
              subject: parsed.subject,
              date: parsed.date 
            }
          ]
        });
        
        if (existingMessage) {
          console.log(`[SYNC] Message already exists, skipping...`);
          skippedCount++;
          continue;
        }

        // Prepare new message
        console.log('[SYNC] Creating new message document...');
        const fromAddress = parsed.from?.value?.[0]?.address || parsed.from?.text || 'unknown';
        const subject = parsed.subject || 'No Subject';
        
        const newMessage = new Message({
          userEmail: fromAddress,
          subject: subject,
          message: parsed.text || parsed.html || '',
          isHtml: !!parsed.html,
          isIncoming: true,
          from: parsed.from?.text || 'Unknown Sender',
          date: parsed.date || new Date(),
          messageId: email.messageId
        });

        // Handle attachments if present
        if (parsed.attachments && parsed.attachments.length > 0) {
          console.log(`[SYNC] Found ${parsed.attachments.length} attachments`);
          const uploadDir = path.join(__dirname, 'uploads', 'attachments');
          
          if (!fs.existsSync(uploadDir)) {
            console.log('[SYNC] Creating attachments directory...');
            fs.mkdirSync(uploadDir, { recursive: true });
          }

          for (const attachment of parsed.attachments) {
            try {
              const filename = `${Date.now()}-${attachment.filename || 'attachment'}`;
              const filePath = path.join(uploadDir, filename);
              
              console.log(`[SYNC] Saving attachment: ${filename}`);
              fs.writeFileSync(filePath, attachment.content);
              
              newMessage.attachments.push({
                filename: attachment.filename || 'file',
                path: filePath,
                contentType: attachment.contentType || 'application/octet-stream',
                size: attachment.size || 0
              });
            } catch (attachmentError) {
              console.error('[SYNC] Error saving attachment:', attachmentError);
              errorCount++;
            }
          }
        }

        // Save the message
        console.log('[SYNC] Saving message to database...');
        await newMessage.save();
        savedMessages.push(newMessage);
        console.log(`[SYNC] Message saved successfully (ID: ${newMessage._id})`);

      } catch (emailError) {
        console.error(`[SYNC] Error processing email ${index + 1}:`, emailError);
        errorCount++;
      }
    }

    // Final summary
    console.log('[SYNC] Synchronization completed:');
    console.log(`- Total emails processed: ${emails.length}`);
    console.log(`- New messages saved: ${savedMessages.length}`);
    console.log(`- Existing messages skipped: ${skippedCount}`);
    console.log(`- Errors encountered: ${errorCount}`);

    res.json({ 
      success: true, 
      message: `Synced ${savedMessages.length} new emails`,
      stats: {
        totalProcessed: emails.length,
        newMessages: savedMessages.length,
        skipped: skippedCount,
        errors: errorCount
      },
      newMessages: savedMessages
    });

  } catch (err) {
    console.error('[SYNC] Critical synchronization error:', err);
    
    let errorMessage = 'Failed to sync emails';
    if (err.code === 'ECONNECTION') {
      errorMessage = 'Could not connect to IMAP server. Check your network and server settings.';
    } else if (err.code === 'EAUTH') {
      errorMessage = 'IMAP authentication failed. Check your email credentials.';
    }
    
    res.status(500).json({ 
      success: false,
      error: errorMessage,
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Enhanced Inbox Fetching
app.get('/api/admin/inbox', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, search } = req.query;
    let query = { isIncoming: true };

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
      messages: messages.map(msg => ({
        ...msg.toObject(),
        attachments: msg.attachments.map(att => ({
          filename: att.filename,
          contentType: att.contentType,
          size: att.size
        }))
      })),  // Fixed: Added missing parenthesis here
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });  // Fixed: Properly closed the response object
  } catch (err) {
    console.error('Error fetching inbox:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch inbox messages'
    });
  }
});

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

app.delete('/api/admin/inbox/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
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

// ===== GALLERY ROUTES ===== //

app.post('/api/admin/gallery', authenticateAdmin, upload.array('images', 10), async (req, res) => {
  try {
    const { name, description, category, featured } = req.body;
    const files = req.files || [];
    
    if (files.length === 0) {
      return res.status(400).json({ error: 'At least one image is required' });
    }
    
    const savedImages = [];
    
    for (const file of files) {
      const imageUrl = `/uploads/${file.filename}`;
      
      const galleryItem = new Gallery({
        name: name || file.originalname,
        description: description || '',
        category: category || 'other',
        featured: featured === 'true',
        imageUrl,
        thumbnailUrl: imageUrl
      });
      
      await galleryItem.save();
      savedImages.push(galleryItem);
    }
    
    res.json({ success: true, images: savedImages });
  } catch (err) {
    console.error('Error uploading gallery images:', err);
    
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to upload images' });
  }
});

app.get('/api/admin/gallery', authenticateAdmin, async (req, res) => {
  try {
    const { category, featured, search, page = 1, limit = 12 } = req.query;
    let query = {};
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.featured = true;
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { name: searchRegex },
        { description: searchRegex }
      ];
    }
    
    const skip = (page - 1) * limit;
    const images = await Gallery.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Gallery.countDocuments(query);
    
    res.json({
      success: true,
      images,
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
  } catch (err) {
    console.error('Error fetching gallery images:', err);
    res.status(500).json({ error: 'Failed to fetch gallery images' });
  }
});

app.put('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, category, featured } = req.body;
    
    const galleryItem = await Gallery.findByIdAndUpdate(
      req.params.id,
      {
        name,
        description,
        category,
        featured,
        updatedAt: new Date()
      },
      { new: true }
    );
    
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    res.json({ success: true, image: galleryItem });
  } catch (err) {
    console.error('Error updating gallery item:', err);
    res.status(500).json({ error: 'Failed to update gallery item' });
  }
});

app.delete('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const galleryItem = await Gallery.findById(req.params.id);
    
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    if (fs.existsSync(path.join(__dirname, galleryItem.imageUrl))) {
      fs.unlinkSync(path.join(__dirname, galleryItem.imageUrl));
    }
    
    await galleryItem.remove();
    
    res.json({ success: true, message: 'Gallery item deleted successfully' });
  } catch (err) {
    console.error('Error deleting gallery item:', err);
    res.status(500).json({ error: 'Failed to delete gallery item' });
  }
});

// ===== SETTINGS ROUTES ===== //

app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    if (!settings) {
      return res.status(404).json({ error: 'Settings not found' });
    }
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error fetching settings:', err);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings/general', authenticateAdmin, async (req, res) => {
  try {
    const { siteName, siteDescription, contactEmail, contactPhone } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      {
        siteName,
        siteDescription,
        contactEmail,
        contactPhone
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating general settings:', err);
    res.status(500).json({ error: 'Failed to update general settings' });
  }
});

app.put('/api/admin/settings/booking', authenticateAdmin, async (req, res) => {
  try {
    const { bookingLeadTime, maxBookingsPerDay, cancellationPolicy } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      {
        bookingLeadTime,
        maxBookingsPerDay,
        cancellationPolicy
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating booking settings:', err);
    res.status(500).json({ error: 'Failed to update booking settings' });
  }
});

app.put('/api/admin/settings/email', authenticateAdmin, async (req, res) => {
  try {
    const { smtpHost, smtpPort, smtpUser, smtpPass, fromEmail } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      {
        smtpHost,
        smtpPort,
        smtpUser,
        smtpPass,
        fromEmail
      },
      { new: true, upsert: true }
    );
    
    if (smtpHost && smtpPort && smtpUser && smtpPass) {
      transporter.close();
      Object.assign(transporter, nodemailer.createTransport({
        host: smtpHost,
        port: smtpPort,
        secure: smtpPort === 465,
        auth: {
          user: smtpUser,
          pass: smtpPass
        }
      }));
    }
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating email settings:', err);
    res.status(500).json({ error: 'Failed to update email settings' });
  }
});

app.put('/api/admin/settings/payment', authenticateAdmin, async (req, res) => {
  try {
    const { currency, paymentMethods, depositPercentage } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      {
        currency,
        paymentMethods,
        depositPercentage
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating payment settings:', err);
    res.status(500).json({ error: 'Failed to update payment settings' });
  }
});

// ===== SEARCH ROUTES ===== //

app.get('/api/admin/search', authenticateAdmin, async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query || query.length < 2) {
      return res.status(400).json({ error: 'Search query must be at least 2 characters' });
    }
    
    const searchRegex = new RegExp(query, 'i');
    
    const bookingResults = await Booking.find({
      $or: [
        { customerName: searchRegex },
        { customerEmail: searchRegex },
        { package: searchRegex },
        { transactionId: searchRegex },
        { _id: searchRegex }
      ]
    }).limit(5);
    
    const messageResults = await Message.find({
      $or: [
        { userEmail: searchRegex },
        { subject: searchRegex },
        { message: searchRegex }
      ]
    }).limit(5);
    
    const galleryResults = await Gallery.find({
      $or: [
        { name: searchRegex },
        { description: searchRegex },
        { category: searchRegex }
      ]
    }).limit(5);
    
    res.json({
      success: true,
      results: {
        bookings: bookingResults,
        messages: messageResults,
        gallery: galleryResults
      }
    });
  } catch (err) {
    console.error('Error performing search:', err);
    res.status(500).json({ error: 'Failed to perform search' });
  }
});

// ===== EXISTING USER ROUTES ===== //

app.get('/api/user-data', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'Authorization header missing' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token missing' });

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = { 
      name: decoded.name || 'Customer',
      email: decoded.email 
    };

    res.json({ 
      success: true,
      user
    });
  } catch (err) {
    console.error('Error in /api/user-data:', err);
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/bookings', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const bookings = await Booking.find({ customerEmail: email })
      .sort({ createdAt: -1 });
    res.json({ success: true, bookings });
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

app.patch('/api/bookings/:id/status', async (req, res) => {
  try {
    const { status } = req.body;
    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    
    res.json({ success: true, booking });
  } catch (err) {
    console.error('Error updating booking:', err);
    res.status(500).json({ error: 'Failed to update booking' });
  }
});

app.post('/save-booking', async (req, res) => {
  console.log('Booking data received:', req.body);

  try {
    const {
      customerName,
      customerEmail,
      customerPhone,
      package,
      bookingDates,
      preWeddingDate,
      address,
      transactionId,
      userId
    } = req.body;

    const newBooking = new Booking({
      customerName,
      customerEmail,
      customerPhone,
      package,
      bookingDates,
      preWeddingDate,
      address,
      transactionId,
      paymentStatus: 'Paid',
      status: 'pending',
      userId: userId || null
    });

    await newBooking.save();

    const bookingConfirmationHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #00acc1; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
        .details { margin: 15px 0; }
        .detail-item { margin-bottom: 10px; }
        .detail-label { font-weight: bold; color: #00acc1; }
        .footer { margin-top: 20px; font-size: 12px; text-align: center; color: #777; }
        .logo { text-align: center; margin-bottom: 20px; }
        .logo img { max-width: 150px; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>Booking Details!</h1>
      </div>
      <div class="content">
        <div class="logo">
          <img src="https://jokercreation.store/logo.png" alt="Joker Creation Studio">
        </div>
        <p>Dear ${customerName},</p>
        <p>Thank you for choosing Joker Creation Studio for your photography needs. Your booking has been confirmed!</p>
        
        <div class="details">
          <div class="detail-item">
            <span class="detail-label">Booking ID:</span> ${newBooking._id}
          </div>
          <div class="detail-item">
            <span class="detail-label">Package:</span> ${package}
          </div>
          <div class="detail-item">
            <span class="detail-label">Event Dates:</span> ${bookingDates}
          </div>
          <div class="detail-item">
            <span class="detail-label">Advance Payment:</span> ₹${parseInt(package.replace(/[^0-9]/g, '')) * 0.1}
          </div>
          <div class="detail-item">
            <span class="detail-label">Transaction ID:</span> ${transactionId}
          </div>
        </div>
        
        <p>We'll contact you shortly to discuss your event details. If you have any questions, please reply to this email.</p>
        <p>Best regards,<br>The Joker Creation Studio Team</p>
      </div>
      <div class="footer">
        © 2025 Joker Creation Studio. All rights reserved.
      </div>
    </body>
    </html>
    `;

    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: customerEmail,
      subject: 'Booking Confirmation - Joker Creation Studio',
      html: bookingConfirmationHtml
    });

    const adminNotificationHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #ff5722; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
        .details { margin: 15px 0; }
        .detail-item { margin-bottom: 10px; }
        .detail-label { font-weight: bold; color: #ff5722; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>New Booking Received</h1>
      </div>
      <div class="content">
        <p>A new booking has been created:</p>
        
        <div class="details">
          <div class="detail-item">
            <span class="detail-label">Customer:</span> ${customerName}
          </div>
          <div class="detail-item">
            <span class="detail-label">Email:</span> ${customerEmail}
          </div>
          <div class="detail-item">
            <span class="detail-label">Phone:</span> ${customerPhone}
          </div>
          <div class="detail-item">
            <span class="detail-label">Package:</span> ${package}
          </div>
          <div class="detail-item">
            <span class="detail-label">Event Dates:</span> ${bookingDates}
          </div>
          <div class="detail-item">
            <span class="detail-label">Transaction ID:</span> ${transactionId}
          </div>
        </div>
      </div>
    </body>
    </html>
    `;

    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject: 'New Booking Notification',
      html: adminNotificationHtml
    });

    res.status(200).json({ 
      success: true,
      message: 'Booking saved successfully',
      booking: newBooking
    });
  } catch (err) {
    console.error('Error saving booking:', err);
    res.status(500).json({ error: 'Failed to save booking' });
  }
});

app.post('/create-order', (req, res) => {
  const { amount } = req.body;

  const options = {
    amount: amount * 100,
    currency: 'INR',
    receipt: 'receipt#1',
  };

  razorpayInstance.orders.create(options, (err, order) => {
    if (err) {
      console.error('Error creating Razorpay order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }
    res.json({ id: order.id });
  });
});

app.post('/contact-submit', (req, res) => {
  const { name, mobile, email, message } = req.body;

  const contactFormHtml = `
  <!DOCTYPE html>
  <html>
  <head>
    <style>
      body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
      .header { background-color: #6e7bff; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
      .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
      .details { margin: 15px 0; }
      .detail-item { margin-bottom: 10px; }
      .detail-label { font-weight: bold; color: #6e7bff; }
    </style>
  </head>
  <body>
    <div class="header">
      <h1>New Contact Form Submission</h1>
    </div>
    <div class="content">
      <div class="details">
        <div class="detail-item">
          <span class="detail-label">Name:</span> ${name}
        </div>
        <div class="detail-item">
          <span class="detail-label">Mobile:</span> ${mobile}
        </div>
        <div class="detail-item">
          <span class="detail-label">Email:</span> ${email}
        </div>
        <div class="detail-item">
          <span class="detail-label">Message:</span> ${message || 'No message provided'}
        </div>
      </div>
    </div>
  </body>
  </html>
  `;

  const mailOptions = {
    from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
    to: process.env.ADMIN_EMAIL,
    subject: 'New Contact Form Submission',
    html: contactFormHtml
  };

  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.log('Error sending email:', error);
      return res.status(500).json({ error: 'Failed to send email' });
    }
    console.log('Email sent:', info.response);
    return res.status(200).json({ message: 'Your message has been sent successfully!' });
  });
});

// ===== PUBLIC GALLERY ROUTES ===== //

app.get('/api/gallery', async (req, res) => {
  try {
    const { category, featured, limit = 12 } = req.query;
    let query = {};
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.featured = true;
    }
    
    const images = await Gallery.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit));
    
    res.json({ success: true, images });
  } catch (err) {
    console.error('Error fetching public gallery:', err);
    res.status(500).json({ error: 'Failed to fetch gallery images' });
  }
});

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
