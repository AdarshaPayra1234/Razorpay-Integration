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
const { ImapFlow } = require('imapflow');

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
  amount: Number,
  paymentStatus: { type: String, default: 'pending' },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'cancelled', 'completed'],
    default: 'pending' 
  },
  userId: String,
  specialRequests: String,
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
  notificationSeen: { type: Boolean, default: false }
});

// Inbox Message Schema
const inboxMessageSchema = new mongoose.Schema({
  fromEmail: { type: String, required: true },
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
  isImportant: { type: Boolean, default: false }
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Gallery Schema for Postinger integration
const gallerySchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { 
    type: String, 
    enum: ['portraits', 'events', 'products', 'weddings', 'other'],
    default: 'other'
  },
  url: { type: String, required: true },
  thumbnailUrl: String,
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
  general: {
    siteName: String,
    siteDescription: String,
    contactEmail: String,
    contactPhone: String
  },
  booking: {
    bookingLeadTime: Number,
    maxBookingsPerDay: Number,
    cancellationPolicy: String
  },
  email: {
    smtpHost: String,
    smtpPort: Number,
    smtpUser: String,
    smtpPass: String,
    fromEmail: String
  },
  payment: {
    currency: String,
    paymentMethods: [String],
    depositPercentage: Number
  }
});

const Booking = mongoose.model('Booking', bookingSchema);
const Message = mongoose.model('Message', messageSchema);
const InboxMessage = mongoose.model('InboxMessage', inboxMessageSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Gallery = mongoose.model('Gallery', gallerySchema);
const Settings = mongoose.model('Settings', settingsSchema);

app.use(cors({
  origin: ['https://jokercreation.store', 'http://localhost:3000'],
  credentials: true
}));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

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
    fileSize: 10 * 1024 * 1024 // 10MB limit per file
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


// Initialize admin account
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
  } catch (err) {
    console.error('Error initializing admin account:', err);
  }
}

// Initialize default settings
async function initializeSettings() {
  try {
    const existingSettings = await Settings.findOne();
    if (!existingSettings) {
      const defaultSettings = new Settings({
        general: {
          siteName: 'Joker Creation Studio',
          siteDescription: 'Professional Photography Services',
          contactEmail: 'contact@jokercreation.store',
          contactPhone: '+919002405641'
        },
        booking: {
          bookingLeadTime: 24,
          maxBookingsPerDay: 3,
          cancellationPolicy: 'Cancellations must be made at least 24 hours in advance for a full refund.'
        },
        email: {
          smtpHost: 'smtp.hostinger.com',
          smtpPort: 465,
          smtpUser: 'contact@jokercreation.store',
          smtpPass: process.env.EMAIL_PASS,
          fromEmail: 'contact@jokercreation.store'
        },
        payment: {
          currency: 'INR',
          paymentMethods: ['creditCard', 'razorpay'],
          depositPercentage: 30
        }
      });
      await defaultSettings.save();
      console.log('Default settings initialized');
    }
  } catch (err) {
    console.error('Error initializing settings:', err);
  }
}

initializeAdmin();
initializeSettings();

// ===== AUTHENTICATION ===== //

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

// ===== DASHBOARD ROUTES ===== //

// Get dashboard statistics
app.get('/api/admin/dashboard/stats', authenticateAdmin, async (req, res) => {
  try {
    const [bookings, users, messages, inbox] = await Promise.all([
      Booking.aggregate([
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            pending: { $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] } },
            confirmed: { $sum: { $cond: [{ $eq: ["$status", "confirmed"] }, 1, 0] } },
            cancelled: { $sum: { $cond: [{ $eq: ["$status", "cancelled"] }, 1, 0] } },
            completed: { $sum: { $cond: [{ $eq: ["$status", "completed"] }, 1, 0] } },
            revenue: { $sum: "$amount" }
          }
        }
      ]),
      Booking.aggregate([
        { $group: { _id: "$customerEmail" } },
        { $count: "total" }
      ]),
      Message.countDocuments(),
      InboxMessage.countDocuments({ isRead: false })
    ]);

    const stats = {
      bookings: bookings[0] || { total: 0, pending: 0, confirmed: 0, cancelled: 0, completed: 0, revenue: 0 },
      users: users[0]?.total || 0,
      unreadMessages: inbox || 0,
      sentMessages: messages || 0
    };

    res.json({ success: true, stats });
  } catch (err) {
    console.error('Error fetching dashboard stats:', err);
    res.status(500).json({ error: 'Failed to fetch dashboard stats' });
  }
});

// ===== BOOKING ROUTES ===== //

// Get all bookings for admin with filters
app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { status, search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (status && ['pending', 'confirmed', 'cancelled', 'completed'].includes(status)) {
      query.status = status;
    }
    
    if (search) {
      query.$or = [
        { customerName: { $regex: search, $options: 'i' } },
        { customerEmail: { $regex: search, $options: 'i' } },
        { customerPhone: { $regex: search, $options: 'i' } },
        { package: { $regex: search, $options: 'i' } },
        { transactionId: { $regex: search, $options: 'i' } }
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
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// Get booking by ID
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

// Update booking status
app.patch('/api/admin/bookings/:id/status', authenticateAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!booking) return res.status(404).json({ error: 'Booking not found' });
    
    // Send email notification to user about status change
    const statusUpdateHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #00acc1; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
        .footer { margin-top: 20px; font-size: 12px; text-align: center; color: #777; }
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
      <div class="footer">
        © 2025 Joker Creation Studio. All rights reserved.
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

// Delete booking
app.delete('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const booking = await Booking.findByIdAndDelete(req.params.id);
    if (!booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    res.json({ success: true, message: 'Booking deleted successfully' });
  } catch (err) {
    console.error('Error deleting booking:', err);
    res.status(500).json({ error: 'Failed to delete booking' });
  }
});

// ===== USER MANAGEMENT ROUTES ===== //

// Get all users (customers who have made bookings)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { customerName: { $regex: search, $options: 'i' } },
        { customerEmail: { $regex: search, $options: 'i' } },
        { customerPhone: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    const users = await Booking.aggregate([
      { $match: query },
      { 
        $group: { 
          _id: "$customerEmail",
          name: { $first: "$customerName" },
          phone: { $first: "$customerPhone" },
          bookingsCount: { $sum: 1 },
          lastBookingDate: { $max: "$createdAt" }
        } 
      },
      { $sort: { lastBookingDate: -1 } },
      { $skip: skip },
      { $limit: parseInt(limit) }
    ]);
    
    const total = (await Booking.aggregate([
      { $match: query },
      { $group: { _id: "$customerEmail" } },
      { $count: "total" }
    ]))[0]?.total || 0;
    
    res.json({ 
      success: true, 
      users,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get user details by email
app.get('/api/admin/users/:email', authenticateAdmin, async (req, res) => {
  try {
    const user = await Booking.findOne({ customerEmail: req.params.email })
      .sort({ createdAt: -1 });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userDetails = {
      email: user.customerEmail,
      name: user.customerName,
      phone: user.customerPhone,
      bookingsCount: await Booking.countDocuments({ customerEmail: req.params.email }),
      lastBookingDate: user.createdAt
    };
    
    res.json({ success: true, user: userDetails });
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Get user's bookings
app.get('/api/admin/users/:email/bookings', authenticateAdmin, async (req, res) => {
  try {
    const bookings = await Booking.find({ customerEmail: req.params.email })
      .sort({ createdAt: -1 });
    
    res.json({ success: true, bookings });
  } catch (err) {
    console.error('Error fetching user bookings:', err);
    res.status(500).json({ error: 'Failed to fetch user bookings' });
  }
});

// ===== MESSAGE ROUTES ===== //

// Send message to user with attachments and rich text support
app.post('/api/admin/messages', authenticateAdmin, upload.array('attachments', 5), async (req, res) => {
  try {
    const { userEmails, subject, message, isHtml } = req.body;
    const files = req.files || [];
    
    if (!userEmails || !subject || !message) {
      // Clean up uploaded files if validation fails
      files.forEach(file => fs.unlinkSync(file.path));
      return res.status(400).json({ error: 'User emails, subject and message are required' });
    }
    
    const emails = Array.isArray(userEmails) ? userEmails : [userEmails];
    
    // Prepare attachments for database
    const attachments = files.map(file => ({
      filename: file.originalname,
      path: file.path,
      contentType: file.mimetype,
      size: file.size
    }));

    // Save message for each recipient
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
    
    // Prepare email options
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

    // Send email
    await transporter.sendMail(mailOptions);
    
    // Clean up files after sending
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
    
    // Clean up any uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get all sent messages (admin view)
app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { userEmail: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ];
    }
    
    const skip = (page - 1) * limit;
    const messages = await Message.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Message.countDocuments(query);
    
    // Transform attachments to remove file paths
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
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get message by ID
app.get('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Transform attachments to remove file paths
    const sanitizedMessage = {
      ...message.toObject(),
      attachments: message.attachments.map(att => ({
        filename: att.filename,
        contentType: att.contentType,
        size: att.size
      }))
    };
    
    res.json({ success: true, message: sanitizedMessage });
  } catch (err) {
    console.error('Error fetching message:', err);
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

// Download attachment
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

// Delete a message
app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findById(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    // Delete associated files
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

// Fetch emails from IMAP and save to database
// Initialize IMAP client outside the function
const imapClient = new ImapFlow({
  host: 'imap.hostinger.com',
  port: 993,
  secure: true,
  auth: {
    user: 'contact@jokercreation.store',
    pass: process.env.EMAIL_PASS
  },
  logger: false
});

// Make sure the function is declared as async
// Import required modules at the top (only once)
const { ImapFlow } = require('imapflow');

// Email fetching function
const fetchEmails = async () => {
    // Create new client instance for each fetch
    const client = new ImapFlow({
        host: process.env.IMAP_HOST || 'imap.hostinger.com',
        port: parseInt(process.env.IMAP_PORT) || 993,
        secure: true,
        auth: {
            user: process.env.EMAIL_USER || 'contact@jokercreation.store',
            pass: process.env.EMAIL_PASS
        },
        logger: process.env.NODE_ENV === 'development'
    });

    try {
        // Connect to server
        await client.connect();
        console.log('IMAP connected successfully');

        // Get mailbox lock
        const lock = await client.getMailboxLock('INBOX');
        console.log('Mailbox locked successfully');

        try {
            // Fetch messages from last 7 days
            const messages = client.fetch(
                { since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) },
                { envelope: true, bodyStructure: true, source: true }
            );

            // Process messages
            let messageCount = 0;
            for await (const message of messages) {
                console.log(`New message from: ${message.envelope.from[0].address}`);
                messageCount++;
                // Add your message processing logic here
            }
            console.log(`Processed ${messageCount} messages`);
        } finally {
            // Release lock when done
            lock.release();
            console.log('Mailbox lock released');
        }

        // Logout when done
        await client.logout();
        console.log('IMAP disconnected successfully');
    } catch (err) {
        console.error('IMAP error:', err);
        try {
            // Try to logout even if there's an error
            if (client && typeof client.logout === 'function') {
                await client.logout();
            }
        } catch (logoutErr) {
            console.error('Logout error:', logoutErr);
        }
        throw err; // Re-throw for calling function to handle
    }
};

// Email fetching service with scheduling
const startEmailFetchingService = () => {
    // Initial fetch
    fetchEmails()
        .then(() => console.log('Initial email fetch completed'))
        .catch(err => console.error('Initial email fetch failed:', err));

    // Set up interval (10 minutes)
    const interval = setInterval(() => {
        fetchEmails()
            .then(() => console.log('Scheduled email fetch completed'))
            .catch(err => console.error('Scheduled email fetch failed:', err));
    }, 10 * 60 * 1000);

    // Cleanup on exit
    const cleanup = () => {
        clearInterval(interval);
        console.log('Email fetching service stopped');
    };

    process.on('SIGTERM', cleanup);
    process.on('SIGINT', cleanup);
    process.on('uncaughtException', (err) => {
        console.error('Uncaught exception:', err);
        cleanup();
    });

    return cleanup;
};

// Start the email fetching service
startEmailFetchingService();

console.log('Email fetching service started');
    
    // Select and lock the mailbox
    let lock = await imapClient.getMailboxLock('INBOX');
    try {
      // Fetch messages from the last 7 days
      let messages = await imapClient.fetch(
        { since: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }, 
        { envelope: true, bodyStructure: true, source: true }
      );
      
      for await (let message of messages) {
        // Check if message already exists in database
        const existingMessage = await InboxMessage.findOne({ 
          messageId: message.envelope.messageId 
        });
        
        if (!existingMessage) {
          // Parse message content
          let text = '';
          let html = '';
          let attachments = [];
          
          if (message.bodyStructure.type === 'text') {
            if (message.bodyStructure.subtype === 'plain') {
              text = message.source.toString();
            } else if (message.bodyStructure.subtype === 'html') {
              html = message.source.toString();
            }
          } else if (message.bodyStructure.parts) {
            for (let part of message.bodyStructure.parts) {
              if (part.type === 'text' && part.subtype === 'plain') {
                text = message.parts[part.part].toString();
              } else if (part.type === 'text' && part.subtype === 'html') {
                html = message.parts[part.part].toString();
              } else if (part.disposition === 'attachment') {
                const attachment = {
                  filename: part.dispositionParameters.filename,
                  content: message.parts[part.part],
                  contentType: part.type + '/' + part.subtype,
                  size: part.size
                };
                attachments.push(attachment);
              }
            }
          }
          
          // Save to database
          const newMessage = new InboxMessage({
            messageId: message.envelope.messageId,
            fromEmail: message.envelope.from[0].address,
            subject: message.envelope.subject || '(No Subject)',
            message: text || html,
            isHtml: !!html,
            createdAt: message.envelope.date,
            isRead: false,
            isImportant: false
          });
          
          await newMessage.save();
        }
      }
    } finally {
      // Release the lock
      lock.release();
    }
    
    await imapClient.logout();
  } catch (err) {
    console.error('Error fetching emails:', err);
  }
}

// Get inbox messages
app.get('/api/admin/inbox', authenticateAdmin, async (req, res) => {
  try {
    const { search, isRead, isImportant, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (search) {
      query.$or = [
        { fromEmail: { $regex: search, $options: 'i' } },
        { subject: { $regex: search, $options: 'i' } },
        { message: { $regex: search, $options: 'i' } }
      ];
    }
    
    if (isRead === 'true' || isRead === 'false') {
      query.isRead = isRead === 'true';
    }
    
    if (isImportant === 'true' || isImportant === 'false') {
      query.isImportant = isImportant === 'true';
    }
    
    const skip = (page - 1) * limit;
    const messages = await InboxMessage.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await InboxMessage.countDocuments(query);
    
    res.json({ 
      success: true, 
      messages,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error fetching inbox messages:', err);
    res.status(500).json({ error: 'Failed to fetch inbox messages' });
  }
});

// Get inbox message by ID
app.get('/api/admin/inbox/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await InboxMessage.findByIdAndUpdate(
      req.params.id,
      { $set: { isRead: true } },
      { new: true }
    );
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json({ success: true, message });
  } catch (err) {
    console.error('Error fetching inbox message:', err);
    res.status(500).json({ error: 'Failed to fetch inbox message' });
  }
});

// Mark message as important
app.patch('/api/admin/inbox/:id/important', authenticateAdmin, async (req, res) => {
  try {
    const { isImportant } = req.body;
    const message = await InboxMessage.findByIdAndUpdate(
      req.params.id,
      { $set: { isImportant } },
      { new: true }
    );
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json({ success: true, message });
  } catch (err) {
    console.error('Error updating message importance:', err);
    res.status(500).json({ error: 'Failed to update message importance' });
  }
});

// Delete inbox message
app.delete('/api/admin/inbox/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await InboxMessage.findByIdAndDelete(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json({ success: true, message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Error deleting inbox message:', err);
    res.status(500).json({ error: 'Failed to delete inbox message' });
  }
});

// Reply to inbox message
app.post('/api/admin/inbox/:id/reply', authenticateAdmin, upload.array('attachments', 5), async (req, res) => {
  try {
    const { subject, message, isHtml } = req.body;
    const files = req.files || [];
    
    const originalMessage = await InboxMessage.findById(req.params.id);
    if (!originalMessage) {
      return res.status(404).json({ error: 'Original message not found' });
    }
    
    // Prepare attachments for database
    const attachments = files.map(file => ({
      filename: file.originalname,
      path: file.path,
      contentType: file.mimetype,
      size: file.size
    }));

    // Save the reply as a sent message
    const newMessage = new Message({
      userEmail: originalMessage.fromEmail,
      subject: subject || `Re: ${originalMessage.subject}`,
      message,
      isHtml: isHtml === 'true',
      attachments
    });
    
    await newMessage.save();
    
    // Prepare email options
    const mailOptions = {
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: originalMessage.fromEmail,
      subject: subject || `Re: ${originalMessage.subject}`,
      html: isHtml === 'true' ? message : `<pre>${message}</pre>`,
      attachments: files.map(file => ({
        filename: file.originalname,
        path: file.path,
        contentType: file.mimetype
      }))
    };

    // Send email
    await transporter.sendMail(mailOptions);
    
    // Clean up files after sending
    files.forEach(file => fs.unlinkSync(file.path));
    
    res.json({ 
      success: true, 
      message: {
        ...newMessage.toObject(),
        attachments: attachments.map(att => ({
          filename: att.filename,
          contentType: att.contentType,
          size: att.size
        }))
      }
    });
  } catch (err) {
    console.error('Error replying to message:', err);
    
    // Clean up any uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to send reply' });
  }
});

// ===== GALLERY ROUTES (Postinger Integration) ===== //

// Upload gallery images
app.post('/api/admin/gallery', authenticateAdmin, upload.array('images', 10), async (req, res) => {
  try {
    const { name, category, featured } = req.body;
    const files = req.files || [];
    
    if (!files.length) {
      return res.status(400).json({ error: 'No images uploaded' });
    }
    
    const galleryItems = await Promise.all(files.map(async file => {
      // In a real implementation, you would upload to Postinger here
      // For now, we'll just save the local file path
      const galleryItem = new Gallery({
        name: name || file.originalname,
        category: category || 'other',
        url: `/uploads/${file.filename}`,
        featured: featured === 'true'
      });
      
      await galleryItem.save();
      return galleryItem;
    }));
    
    res.json({ success: true, items: galleryItems });
  } catch (err) {
    console.error('Error uploading gallery images:', err);
    
    // Clean up any uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to upload gallery images' });
  }
});

// Get all gallery items
app.get('/api/admin/gallery', authenticateAdmin, async (req, res) => {
  try {
    const { category, featured, search, page = 1, limit = 10 } = req.query;
    let query = {};
    
    if (category) {
      query.category = category;
    }
    
    if (featured === 'true') {
      query.featured = true;
    }
    
    if (search) {
      query.name = { $regex: search, $options: 'i' };
    }
    
    const skip = (page - 1) * limit;
    const items = await Gallery.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Gallery.countDocuments(query);
    
    res.json({ 
      success: true, 
      items,
      pagination: {
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (err) {
    console.error('Error fetching gallery items:', err);
    res.status(500).json({ error: 'Failed to fetch gallery items' });
  }
});

// Get gallery item by ID
app.get('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const item = await Gallery.findById(req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    res.json({ success: true, item });
  } catch (err) {
    console.error('Error fetching gallery item:', err);
    res.status(500).json({ error: 'Failed to fetch gallery item' });
  }
});

// Update gallery item
app.put('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const { name, category, featured } = req.body;
    const item = await Gallery.findByIdAndUpdate(
      req.params.id,
      { name, category, featured },
      { new: true }
    );
    
    if (!item) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    res.json({ success: true, item });
  } catch (err) {
    console.error('Error updating gallery item:', err);
    res.status(500).json({ error: 'Failed to update gallery item' });
  }
});

// Delete gallery item
app.delete('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const item = await Gallery.findByIdAndDelete(req.params.id);
    if (!item) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    // Delete the associated file
    if (fs.existsSync(path.join(__dirname, item.url))) {
      fs.unlinkSync(path.join(__dirname, item.url));
    }
    
    res.json({ success: true, message: 'Gallery item deleted successfully' });
  } catch (err) {
    console.error('Error deleting gallery item:', err);
    res.status(500).json({ error: 'Failed to delete gallery item' });
  }
});

// ===== SETTINGS ROUTES ===== //

// Get all settings
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

// Update general settings
app.put('/api/admin/settings/general', authenticateAdmin, async (req, res) => {
  try {
    const { siteName, siteDescription, contactEmail, contactPhone } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      { 
        $set: { 
          'general.siteName': siteName,
          'general.siteDescription': siteDescription,
          'general.contactEmail': contactEmail,
          'general.contactPhone': contactPhone
        } 
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating general settings:', err);
    res.status(500).json({ error: 'Failed to update general settings' });
  }
});

// Update booking settings
app.put('/api/admin/settings/booking', authenticateAdmin, async (req, res) => {
  try {
    const { bookingLeadTime, maxBookingsPerDay, cancellationPolicy } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      { 
        $set: { 
          'booking.bookingLeadTime': bookingLeadTime,
          'booking.maxBookingsPerDay': maxBookingsPerDay,
          'booking.cancellationPolicy': cancellationPolicy
        } 
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating booking settings:', err);
    res.status(500).json({ error: 'Failed to update booking settings' });
  }
});

// Update email settings
app.put('/api/admin/settings/email', authenticateAdmin, async (req, res) => {
  try {
    const { smtpHost, smtpPort, smtpUser, smtpPass, fromEmail } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      { 
        $set: { 
          'email.smtpHost': smtpHost,
          'email.smtpPort': smtpPort,
          'email.smtpUser': smtpUser,
          'email.smtpPass': smtpPass,
          'email.fromEmail': fromEmail
        } 
      },
      { new: true, upsert: true }
    );
    
    // Update transporter if email settings changed
    if (transporter.options.host !== smtpHost || 
        transporter.options.port !== smtpPort ||
        transporter.options.auth.user !== smtpUser ||
        transporter.options.auth.pass !== smtpPass) {
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

// Update payment settings
app.put('/api/admin/settings/payment', authenticateAdmin, async (req, res) => {
  try {
    const { currency, paymentMethods, depositPercentage } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      { 
        $set: { 
          'payment.currency': currency,
          'payment.paymentMethods': paymentMethods,
          'payment.depositPercentage': depositPercentage
        } 
      },
      { new: true, upsert: true }
    );
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating payment settings:', err);
    res.status(500).json({ error: 'Failed to update payment settings' });
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
      amount,
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
      amount,
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
            <span class="detail-label">Amount Paid:</span> ₹${amount}
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
            <span class="detail-label">Amount:</span> ₹${amount}
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

// ===== UTILITY ROUTES ===== //

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Start email fetching interval (every 10 minutes)
setInterval(fetchEmails, 10 * 60 * 1000);

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  // Initial email fetch
  fetchEmails();
});
