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

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

// Gallery Schema for photo management
const gallerySchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  category: { 
    type: String, 
    enum: ['portraits', 'events', 'products', 'weddings', 'other'],
    default: 'other'
  },
  imageUrl: { type: String, required: true },
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

// Settings Schema
const settingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'Joker Creation Studio' },
  siteDescription: { type: String, default: 'Professional Photography Services' },
  contactEmail: { type: String, default: 'contact@jokercreation.com' },
  contactPhone: { type: String, default: '+1234567890' },
  bookingLeadTime: { type: Number, default: 24 }, // hours
  maxBookingsPerDay: { type: Number, default: 3 },
  cancellationPolicy: { type: String, default: 'Cancellations must be made at least 24 hours in advance for a full refund.' },
  smtpHost: String,
  smtpPort: Number,
  smtpUser: String,
  smtpPass: String,
  fromEmail: { type: String, default: 'no-reply@jokercreation.com' },
  currency: { type: String, default: 'USD' },
  paymentMethods: { type: [String], default: ['creditCard'] },
  depositPercentage: { type: Number, default: 30 }
});

const Booking = mongoose.model('Booking', bookingSchema);
const Message = mongoose.model('Message', messageSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Gallery = mongoose.model('Gallery', gallerySchema);
const Settings = mongoose.model('Settings', settingsSchema);

const allowedOrigins = [
  'https://jokercreation.store',
  'http://localhost:3000' // Remove the trailing comma to avoid syntax issues
];

app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) === -1) {
      const msg = 'The CORS policy for this site does not allow access from the specified origin.';
      return callback(new Error(msg), false);
    }
    return callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
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
  logger: true,  // Enable detailed logging
  debug: true    // Show debug output
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

    // Initialize default settings if they don't exist
    const existingSettings = await Settings.findOne();
    if (!existingSettings) {
      const defaultSettings = new Settings();
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
      { expiresIn: '1h' }
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

// ===== BOOKING ROUTES ===== //

// Get all bookings for admin with filters
app.get('/api/admin/bookings', authenticateAdmin, async (req, res) => {
  try {
    const { status, search } = req.query;
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
        { _id: searchRegex }
      ];
    }
    
    const bookings = await Booking.find(query).sort({ createdAt: -1 });
    res.json({ success: true, bookings });
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

// Get booking statistics for dashboard
app.get('/api/admin/bookings/stats', authenticateAdmin, async (req, res) => {
  try {
    const pendingCount = await Booking.countDocuments({ status: 'pending' });
    const confirmedCount = await Booking.countDocuments({ status: 'confirmed' });
    const cancelledCount = await Booking.countDocuments({ status: 'cancelled' });
    const completedCount = await Booking.countDocuments({ status: 'completed' });
    
    // Get upcoming bookings (confirmed and date is in future)
    const upcomingCount = await Booking.countDocuments({ 
      status: 'confirmed',
      bookingDates: { $gte: new Date().toISOString() }
    });
    
    res.json({
      success: true,
      stats: {
        total: pendingCount + confirmedCount + cancelledCount + completedCount,
        pending: pendingCount,
        confirmed: confirmedCount,
        cancelled: cancelledCount,
        upcoming: upcomingCount,
        completed: completedCount
      }
    });
  } catch (err) {
    console.error('Error fetching booking stats:', err);
    res.status(500).json({ error: 'Failed to fetch booking stats' });
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

// ===== USER MANAGEMENT ROUTES ===== //

// Get all users for admin panel
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    const { filter, search } = req.query;
    let query = {};
    
    if (filter === 'admin') {
      query.isAdmin = true;
    } else if (filter === 'active') {
      query.isActive = true;
    } else if (filter === 'inactive') {
      query.isActive = false;
    } else if (filter === 'verified') {
      query.emailVerified = true;
    } else if (filter === 'unverified') {
      query.emailVerified = false;
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { phone: searchRegex }
      ];
    }
    
    // For demo purposes, we'll return users from bookings since we don't have a separate users collection
    const users = await Booking.aggregate([
      {
        $group: {
          _id: "$customerEmail",
          name: { $first: "$customerName" },
          phone: { $first: "$customerPhone" },
          bookingsCount: { $sum: 1 },
          lastBookingDate: { $max: "$createdAt" }
        }
      },
      {
        $project: {
          _id: 0,
          email: "$_id",
          name: 1,
          phone: 1,
          bookingsCount: 1,
          lastBookingDate: 1,
          isActive: { $literal: true }, // Demo value
          emailVerified: { $literal: true }, // Demo value
          isAdmin: { $literal: false } // Demo value
        }
      },
      { $sort: { lastBookingDate: -1 } }
    ]);
    
    res.json({ success: true, users });
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// Get user statistics for dashboard
app.get('/api/admin/users/stats', authenticateAdmin, async (req, res) => {
  try {
    // For demo purposes, we'll calculate stats from bookings
    const users = await Booking.aggregate([
      {
        $group: {
          _id: "$customerEmail",
          hasGoogleAuth: { $literal: false } // Demo value
        }
      },
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          googleUsers: { $sum: { $cond: [{ $eq: ["$hasGoogleAuth", true] }, 1, 0] }
        }
      }
    ]);
    
    const stats = users[0] || { totalUsers: 0, googleUsers: 0 };
    
    res.json({
      success: true,
      stats: {
        totalUsers: stats.totalUsers,
        verifiedUsers: stats.totalUsers, // Assuming all are verified for demo
        googleUsers: stats.googleUsers,
        activeUsers: stats.totalUsers // Assuming all are active for demo
      }
    });
  } catch (err) {
    console.error('Error fetching user stats:', err);
    res.status(500).json({ error: 'Failed to fetch user stats' });
  }
});

// ===== GALLERY MANAGEMENT ROUTES ===== //

// Upload gallery photos
app.post('/api/admin/gallery', authenticateAdmin, upload.array('images', 10), async (req, res) => {
  try {
    const { name, description, category, featured } = req.body;
    const files = req.files;
    
    if (!files || files.length === 0) {
      return res.status(400).json({ error: 'No images uploaded' });
    }
    
    const galleryItems = await Promise.all(files.map(async (file) => {
      // In a real app, you would upload to Postinger or another image hosting service here
      // For demo, we'll just save the file path
      const imageUrl = `/uploads/${file.filename}`;
      
      const galleryItem = new Gallery({
        name: name || file.originalname,
        description,
        category: category || 'other',
        imageUrl,
        featured: featured === 'true'
      });
      
      await galleryItem.save();
      return galleryItem;
    });
    
    res.json({ success: true, galleryItems });
  } catch (err) {
    console.error('Error uploading gallery images:', err);
    
    // Clean up any uploaded files if error occurs
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to upload gallery images' });
  }
});

// Get gallery photos with filters
app.get('/api/admin/gallery', authenticateAdmin, async (req, res) => {
  try {
    const { filter, search } = req.query;
    let query = {};
    
    if (filter && ['portraits', 'events', 'products', 'weddings', 'other'].includes(filter)) {
      query.category = filter;
    } else if (filter === 'featured') {
      query.featured = true;
    }
    
    if (search) {
      query.name = new RegExp(search, 'i');
    }
    
    const galleryItems = await Gallery.find(query).sort({ createdAt: -1 });
    res.json({ success: true, galleryItems });
  } catch (err) {
    console.error('Error fetching gallery items:', err);
    res.status(500).json({ error: 'Failed to fetch gallery items' });
  }
});

// Toggle featured status of gallery item
app.patch('/api/admin/gallery/:id/featured', authenticateAdmin, async (req, res) => {
  try {
    const { featured } = req.body;
    const galleryItem = await Gallery.findByIdAndUpdate(
      req.params.id,
      { featured },
      { new: true }
    );
    
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    res.json({ success: true, galleryItem });
  } catch (err) {
    console.error('Error updating gallery item:', err);
    res.status(500).json({ error: 'Failed to update gallery item' });
  }
});

// Delete gallery item
app.delete('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const galleryItem = await Gallery.findById(req.params.id);
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    // Delete the image file
    if (galleryItem.imageUrl && fs.existsSync(path.join(__dirname, galleryItem.imageUrl))) {
      fs.unlinkSync(path.join(__dirname, galleryItem.imageUrl));
    }
    
    await galleryItem.remove();
    
    res.json({ success: true, message: 'Gallery item deleted successfully' });
  } catch (err) {
    console.error('Error deleting gallery item:', err);
    res.status(500).json({ error: 'Failed to delete gallery item' });
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
    
    const emails = JSON.parse(userEmails);
    if (!Array.isArray(emails) || emails.length === 0) {
      files.forEach(file => fs.unlinkSync(file.path));
      return res.status(400).json({ error: 'At least one recipient email is required' });
    }
    
    // Prepare attachments for database
    const attachments = files.map(file => ({
      filename: file.originalname,
      path: file.path,
      contentType: file.mimetype,
      size: file.size
    }));

    // Save a message record for each recipient
    const messages = await Promise.all(emails.map(async (email) => {
      const newMessage = new Message({
        userEmail: email,
        subject,
        message,
        isHtml: isHtml === 'true',
        attachments
      });
      
      await newMessage.save();
      return newMessage;
    }));
    
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
      messages: messages.map(msg => ({
        ...msg.toObject(),
        attachments: attachments.map(att => ({
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
    const { filter, search } = req.query;
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
    
    const messages = await Message.find(query).sort({ createdAt: -1 });
    
    // Transform attachments to remove file paths
    const sanitizedMessages = messages.map(msg => ({
      ...msg.toObject(),
      attachments: msg.attachments.map(att => ({
        filename: att.filename,
        contentType: att.contentType,
        size: att.size
      }))
    }));
    
    res.json({ success: true, messages: sanitizedMessages });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get recent messages (for dashboard)
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

// ===== INBOX MESSAGES ROUTES ===== //

// Get inbox messages (contact form submissions)
app.get('/api/admin/inbox', authenticateAdmin, async (req, res) => {
  try {
    const { filter, search } = req.query;
    let query = {};
    
    if (filter === 'unread') {
      query.isRead = false;
    } else if (filter === 'important') {
      query.important = true;
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      query.$or = [
        { name: searchRegex },
        { email: searchRegex },
        { message: searchRegex }
      ];
    }
    
    // In a real app, you would query your contact form submissions collection
    // For demo, we'll return some mock data
    const mockInbox = [
      {
        _id: '1',
        name: 'John Doe',
        email: 'john@example.com',
        phone: '1234567890',
        message: 'I would like to book a wedding photography package',
        createdAt: new Date(),
        isRead: false,
        important: true
      },
      {
        _id: '2',
        name: 'Jane Smith',
        email: 'jane@example.com',
        phone: '9876543210',
        message: 'Inquiry about product photography rates',
        createdAt: new Date(Date.now() - 86400000),
        isRead: true,
        important: false
      }
    ];
    
    // Filter mock data based on query
    let inboxMessages = mockInbox;
    if (filter === 'unread') {
      inboxMessages = inboxMessages.filter(msg => !msg.isRead);
    } else if (filter === 'important') {
      inboxMessages = inboxMessages.filter(msg => msg.important);
    }
    
    if (search) {
      const searchRegex = new RegExp(search, 'i');
      inboxMessages = inboxMessages.filter(msg => 
        searchRegex.test(msg.name) || 
        searchRegex.test(msg.email) || 
        searchRegex.test(msg.message)
      );
    }
    
    res.json({ success: true, messages: inboxMessages });
  } catch (err) {
    console.error('Error fetching inbox messages:', err);
    res.status(500).json({ error: 'Failed to fetch inbox messages' });
  }
});

// Mark inbox message as read
app.patch('/api/admin/inbox/:id/read', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would update the message in your database
    res.json({ success: true, message: 'Message marked as read' });
  } catch (err) {
    console.error('Error marking message as read:', err);
    res.status(500).json({ error: 'Failed to update message status' });
  }
});

// Toggle important flag on inbox message
app.patch('/api/admin/inbox/:id/important', authenticateAdmin, async (req, res) => {
  try {
    const { important } = req.body;
    // In a real app, you would update the message in your database
    res.json({ success: true, important });
  } catch (err) {
    console.error('Error updating message importance:', err);
    res.status(500).json({ error: 'Failed to update message importance' });
  }
});

// Delete inbox message
app.delete('/api/admin/inbox/:id', authenticateAdmin, async (req, res) => {
  try {
    // In a real app, you would delete the message from your database
    res.json({ success: true, message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Error deleting inbox message:', err);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// ===== SETTINGS ROUTES ===== //

// Get all settings
app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    if (!settings) {
      // Create default settings if none exist
      const defaultSettings = new Settings();
      await defaultSettings.save();
      return res.json({ success: true, settings: defaultSettings });
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
    
    const settings = await Settings.findOneAndUpdate({}, {
      siteName,
      siteDescription,
      contactEmail,
      contactPhone
    }, { new: true, upsert: true });
    
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
    
    const settings = await Settings.findOneAndUpdate({}, {
      bookingLeadTime,
      maxBookingsPerDay,
      cancellationPolicy
    }, { new: true, upsert: true });
    
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
    
    const settings = await Settings.findOneAndUpdate({}, {
      smtpHost,
      smtpPort,
      smtpUser,
      smtpPass,
      fromEmail
    }, { new: true, upsert: true });
    
    // Update transporter if SMTP settings changed
    if (smtpHost && smtpPort && smtpUser && smtpPass) {
      transporter.close(); // Close existing connections
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
    
    const settings = await Settings.findOneAndUpdate({}, {
      currency,
      paymentMethods,
      depositPercentage
    }, { new: true, upsert: true });
    
    res.json({ success: true, settings });
  } catch (err) {
    console.error('Error updating payment settings:', err);
    res.status(500).json({ error: 'Failed to update payment settings' });
  }
});

// ===== EXISTING USER ROUTES (unchanged) ===== //

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
      userId,
      amount
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
