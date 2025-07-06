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

// Enhanced CORS Configuration
const corsOptions = {
  origin: ['https://jokercreation.store', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'X-CSRF-Token' // Added for additional security
  ],
  credentials: true,
  optionsSuccessStatus: 204,
  preflightContinue: false,
  maxAge: 86400 // Add caching for preflight requests (24 hours)
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Special preflight handlers for specific endpoints
app.options('*', cors(corsOptions)); // Handle all OPTIONS requests

// Specific handler for coupon endpoints
app.options('/api/coupons/*', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || 'https://jokercreation.store');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(204).end();
});

// Your existing payment endpoint handler (keep this unchanged)
app.options('/api/coupons/validate', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://jokercreation.store');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(204).end();
});

// Body parser middleware (keep this unchanged)
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Razorpay Setup
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// File Upload Configuration
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

// Email Transporter
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

// ==================== SCHEMAS ====================

// Booking Schema
const bookingSchema = new mongoose.Schema({
  customerName: String,
  customerEmail: { type: String, required: true },
  customerPhone: String,
  package: String,
  bookingDates: String,
  preWeddingDate: String,
  address: String,
  transactionId: String,
  paymentStatus: { 
    type: String, 
    enum: ['pending', 'partially_paid', 'completed', 'refunded', 'failed'],
    default: 'pending' 
  },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'cancelled', 'completed', 'rescheduled'],
    default: 'pending' 
  },
  userId: String,
  createdAt: { type: Date, default: Date.now },
  
  // Discount-related fields
  couponCode: String,
  discountType: {
    type: String,
    enum: ['percentage', 'fixed', 'special', null],
    default: null
  },
  discountValue: Number, // 10 for 10%, 2000 for ₹2000 off
  originalAmount: Number, // Amount before any discounts
  discountAmount: Number, // Calculated discount amount (₹)
  finalAmount: Number, // originalAmount - discountAmount
  
  // Detailed discount information
  discountDetails: {
    description: String, // "Summer Special 10% Off"
    terms: String, // "Valid until Dec 31, 2023"
    appliedAt: { type: Date, default: Date.now },
    validUntil: Date,
    minOrderAmount: Number, // Minimum order required for this discount
    maxDiscount: Number // Maximum discount amount if applicable
  },
  
  // Payment breakdown
  paymentBreakdown: {
    advancePaid: Number,
    remainingBalance: Number,
    dueDate: Date,
    paymentMethod: String
  },
  
  // Audit fields
  updatedAt: { type: Date, default: Date.now },
  updatedBy: String, // "system" or admin ID
  notes: String // Any special notes about this booking
}, {
  timestamps: true // Automatically adds createdAt and updatedAt
});

// Message Schema
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

// Gallery Schema
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

// Settings Schema
const settingsSchema = new mongoose.Schema({
  siteName: { type: String, default: 'Joker Creation Studio' },
  siteDescription: { type: String, default: 'Professional Photography Services' },
  contactEmail: { type: String, default: 'contact@jokercreation.com' },
  contactPhone: { type: String, default: '+1234567890' },
  bookingLeadTime: { type: Number, default: 24 },
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

// Coupon Schema
const couponSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  discountType: { type: String, enum: ['percentage', 'fixed'], required: true },
  discountValue: { type: Number, required: true },
  validFrom: { type: Date, required: true },
  validUntil: { type: Date, required: true },
  maxUses: { type: Number, default: null }, // null means unlimited
  currentUses: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, required: true },
  targetUsers: { type: [String], default: [] } // Array of user emails
});

// Coupon Banner Schema
const bannerSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: { type: String },
  imageUrl: { type: String, required: true },
  couponCode: { type: String },
  targetUsers: { type: [String], default: [] }, // Empty array means all users
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});
const Banner = mongoose.model('Banner', bannerSchema);
// Add this with your other schema definitions
const couponBannerSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: { type: String },
  imageUrl: { type: String, required: true },
  couponCode: { type: String },
  targetUsers: { type: [String], default: [] }, // Empty array means all users
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});


// Email Template Schema
const emailTemplateSchema = new mongoose.Schema({
  name: { type: String, required: true },
  subject: { type: String, required: true },
  html: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

// Create Models
const Booking = mongoose.model('Booking', bookingSchema);
const Message = mongoose.model('Message', messageSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Gallery = mongoose.model('Gallery', gallerySchema);
const Settings = mongoose.model('Settings', settingsSchema);
const GmailSync = mongoose.model('GmailSync', gmailSyncSchema);
const Coupon = mongoose.model('Coupon', couponSchema);
const CouponBanner = mongoose.model('CouponBanner', couponBannerSchema);
const EmailTemplate = mongoose.model('EmailTemplate', emailTemplateSchema);

// ==================== MIDDLEWARE ====================

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
        const refreshToken = req.cookies?.refreshToken || req.body?.refreshToken;
        
        if (!refreshToken) {
          return res.status(401).json({ 
            error: 'Token expired and no refresh token provided',
            code: 'TOKEN_EXPIRED' 
          });
        }

        try {
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

          res.set('New-Access-Token', newToken);
          req.admin = refreshDecoded;
          return next();
        } catch (refreshError) {
          console.error('Refresh token error:', refreshError);
          return res.status(401).json({ error: 'Invalid refresh token' });
        }
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

// Initialize Admin Account
async function initializeAdmin() {
  try {
    console.log('Starting admin initialization...');
    
    const adminEmail = 'jokercreationbuisness@gmail.com';
    let admin = await Admin.findOne({ email: adminEmail });
    
    if (!admin) {
      console.log('Admin account not found, creating new one...');
      const adminPassword = '9002405641';
      const hashedPassword = await bcrypt.hash(adminPassword, 10);
      
      admin = new Admin({
        email: adminEmail,
        password: hashedPassword
      });
      
      await admin.save();
      console.log('Admin account created successfully');
    }

    let settings = await Settings.findOne();
    
    if (!settings) {
      console.log('No settings found, creating default configuration...');
      
      settings = new Settings({
        imapHost: 'imap.hostinger.com',
        imapPort: 993,
        imapUser: 'contact@jokercreation.store',
        imapPass: process.env.EMAIL_PASS || '9002405641@Adarsha',
        smtpHost: 'smtp.hostinger.com',
        smtpPort: 465,
        smtpUser: 'contact@jokercreation.store',
        smtpPass: process.env.EMAIL_PASS || '9002405641@Adarsha',
        fromEmail: 'contact@jokercreation.store',
        siteName: 'Joker Creation Studio',
        contactEmail: 'contact@jokercreation.store',
        createdAt: new Date(),
        updatedAt: new Date()
      });

      await settings.save();
      console.log('Default settings initialized successfully');
    } else if (!settings.imapUser || !settings.imapPass) {
      console.log('Existing settings found but IMAP not configured, updating...');
      
      settings.imapHost = 'imap.hostinger.com';
      settings.imapPort = 993;
      settings.imapUser = 'contact@jokercreation.store';
      settings.imapPass = process.env.EMAIL_PASS || '9002405641@Adarsha';
      settings.updatedAt = new Date();
      
      await settings.save();
      console.log('IMAP settings updated successfully');
    }

    if (!process.env.EMAIL_PASS && !settings.imapPass) {
      console.warn('WARNING: Email password not set in environment variables or settings');
    }

    console.log('Admin initialization completed successfully');
    return { admin, settings };
    
  } catch (err) {
    console.error('FATAL ERROR during initialization:', err);
    throw new Error('Failed to initialize admin and settings');
  }
}

// ==================== ROUTES ====================

// Admin Login
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

// Token Refresh
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

// ===== COUPON ROUTES ===== //

app.post('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const coupon = new Coupon(req.body);
    await coupon.save();
    res.json({ success: true, coupon });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/api/admin/coupons', authenticateAdmin, async (req, res) => {
  try {
    const coupons = await Coupon.find().sort({ createdAt: -1 });
    res.json({ success: true, coupons });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/coupons/:id', authenticateAdmin, async (req, res) => {
  try {
    const coupon = await Coupon.findByIdAndUpdate(req.params.id, req.body, { new: true });
    res.json({ success: true, coupon });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/admin/coupons/:id', authenticateAdmin, async (req, res) => {
  try {
    await Coupon.findByIdAndDelete(req.params.id);
    res.json({ success: true, message: 'Coupon deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Coupon Banner Routes
app.post('/api/admin/coupon-banners', authenticateAdmin, upload.single('bannerImage'), async (req, res) => {
  try {
    const bannerData = {
      ...req.body,
      imageUrl: `/uploads/${req.file.filename}`,
      targetUsers: req.body.targetUsers ? JSON.parse(req.body.targetUsers) : []
    };
    const banner = new CouponBanner(bannerData);
    await banner.save();
    
    await sendCouponBannerEmails(banner);
    
    res.json({ success: true, banner });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});
// Coupon Validation Endpoint
// On your backend server (Node.js/Express)
// In your backend routes (where you have the coupon validation endpoint)
app.post('/api/coupons/validate', async (req, res) => {
  try {
    const { code } = req.body;
    
    // Find the coupon with additional checks
    const coupon = await Coupon.findOne({
      code,
      isActive: true,
      validFrom: { $lte: new Date() },
      validUntil: { $gte: new Date() },
      $or: [
        { maxUses: null }, // Unlimited uses
        { maxUses: { $gt: { $ifNull: ["$currentUses", 0] } } // Still has remaining uses
      ]
    });

    if (!coupon) {
      return res.status(404).json({ 
        valid: false, 
        error: 'Invalid, expired, or fully redeemed coupon code' 
      });
    }

    res.json({
      valid: true,
      coupon: {
        code: coupon.code,
        discountType: coupon.discountType,
        discountValue: coupon.discountValue,
        minOrderAmount: coupon.minOrderAmount || 0
      }
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});
// Add to your server routes
app.get('/api/coupons/debug/:code', async (req, res) => {
  const coupon = await Coupon.findOne({ code: req.params.code });
  res.json({
    exists: !!coupon,
    currentTime: new Date(),
    coupon,
    validityCheck: {
      isActive: coupon?.isActive,
      validFrom: coupon?.validFrom,
      validUntil: coupon?.validUntil,
      isCurrentlyValid: coupon ? 
        (new Date() >= new Date(coupon.validFrom) && 
         new Date() <= new Date(coupon.validUntil)) : null
    }
  });
});

// Public API for coupon validation
app.get('/api/coupons/validate/:code', async (req, res) => {
  try {
    const coupon = await Coupon.findOne({ 
      code: req.params.code,
      isActive: true,
      validFrom: { $lte: new Date() },
      validUntil: { $gte: new Date() },
      $or: [
        { maxUses: null },
        { maxUses: { $gt: { $ifNull: ["$currentUses", 0] } } }
      ]
    });

    if (!coupon) {
      return res.status(404).json({ error: 'Invalid or expired coupon code' });
    }

    res.json({ 
      success: true, 
      coupon: {
        code: coupon.code,
        discountType: coupon.discountType,
        discountValue: coupon.discountValue,
        minOrderAmount: coupon.minOrderAmount
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Apply coupon to booking
app.post('/api/bookings/:id/apply-coupon', async (req, res) => {
  try {
    const { couponCode } = req.body;
    const { id } = req.params;

    // Validate booking ID
    if (!id || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ 
        error: 'Invalid booking ID',
        code: 'INVALID_BOOKING_ID'
      });
    }

    // Validate coupon code presence
    if (!couponCode || typeof couponCode !== 'string') {
      return res.status(400).json({ 
        error: 'Valid coupon code is required',
        code: 'MISSING_COUPON_CODE'
      });
    }

    // Transaction for atomic operations
    const session = await mongoose.startSession();
    session.startTransaction();

    try {
      const booking = await Booking.findById(id).session(session);
      if (!booking) {
        await session.abortTransaction();
        return res.status(404).json({ 
          error: 'Booking not found',
          code: 'BOOKING_NOT_FOUND'
        });
      }

      // Check if coupon was already applied
      if (booking.couponCode) {
        await session.abortTransaction();
        return res.status(400).json({ 
          error: 'A coupon has already been applied to this booking',
          code: 'COUPON_ALREADY_APPLIED'
        });
      }

      // Find and validate coupon with lock to prevent race conditions
      const coupon = await Coupon.findOneAndUpdate(
        { 
          code: couponCode,
          isActive: true,
          validFrom: { $lte: new Date() },
          validUntil: { $gte: new Date() },
          $or: [
            { maxUses: null },
            { 
              maxUses: { $gt: { $ifNull: ["$currentUses", 0] } },
              $expr: { $lt: ["$currentUses", "$maxUses"] }
            }
          ]
        },
        { $inc: { currentUses: 1 } },
        { new: true, session }
      );

      if (!coupon) {
        await session.abortTransaction();
        return res.status(400).json({ 
          error: 'Invalid, expired, or fully redeemed coupon code',
          code: 'INVALID_COUPON'
        });
      }

      // Calculate package price safely
      const packagePrice = booking.package 
        ? parseInt(booking.package.replace(/[^0-9]/g, '')) || 0 
        : 0;

      // Validate minimum order amount
      if (coupon.minOrderAmount && packagePrice < coupon.minOrderAmount) {
        await session.abortTransaction();
        return res.status(400).json({ 
          error: `Minimum order amount of ₹${coupon.minOrderAmount} required for this coupon`,
          code: 'MIN_ORDER_NOT_MET',
          requiredAmount: coupon.minOrderAmount,
          currentAmount: packagePrice
        });
      }

      // Calculate discount
      let discountAmount = coupon.discountType === 'percentage'
        ? packagePrice * (coupon.discountValue / 100)
        : coupon.discountValue;

      // Apply maximum discount if specified
      if (coupon.maxDiscount) {
        discountAmount = Math.min(discountAmount, coupon.maxDiscount);
      }

      discountAmount = Math.min(discountAmount, packagePrice);
      const finalAmount = packagePrice - discountAmount;

      // Update booking with coupon details
      const updatedBooking = await Booking.findByIdAndUpdate(
        id,
        { 
          couponCode: coupon.code,
          discountType: coupon.discountType,
          discountValue: coupon.discountValue,
          discountAmount,
          finalAmount,
          originalAmount: packagePrice,
          discountDetails: {
            description: coupon.description,
            terms: coupon.terms,
            appliedAt: new Date(),
            validUntil: coupon.validUntil,
            minOrderAmount: coupon.minOrderAmount,
            maxDiscount: coupon.maxDiscount
          }
        },
        { new: true, session }
      );

      // Deactivate coupon if max uses reached
      if (coupon.maxUses && coupon.currentUses >= coupon.maxUses) {
        await Coupon.findByIdAndUpdate(
          coupon._id,
          { isActive: false },
          { session }
        );
      }

      await session.commitTransaction();

      res.json({ 
        success: true,
        booking: updatedBooking,
        discount: {
          amount: discountAmount,
          type: coupon.discountType,
          value: coupon.discountValue,
          code: coupon.code
        },
        finalAmount,
        couponStatus: {
          currentUses: coupon.currentUses,
          maxUses: coupon.maxUses,
          isActive: coupon.isActive && 
                  (!coupon.maxUses || coupon.currentUses < coupon.maxUses),
          remainingUses: coupon.maxUses 
            ? coupon.maxUses - coupon.currentUses 
            : 'Unlimited'
        }
      });

    } catch (err) {
      await session.abortTransaction();
      throw err;
    } finally {
      session.endSession();
    }

  } catch (err) {
    console.error('Error applying coupon:', err);
    res.status(500).json({ 
      error: 'Failed to apply coupon',
      code: 'COUPON_APPLICATION_ERROR',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

app.get('/api/coupons/status/:code', async (req, res) => {
  try {
    const coupon = await Coupon.findOne({ code: req.params.code });
    
    if (!coupon) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    const now = new Date();
    const isValid = coupon.isActive && 
                   new Date(coupon.validFrom) <= now && 
                   new Date(coupon.validUntil) >= now &&
                   (!coupon.maxUses || coupon.currentUses < coupon.maxUses);

    res.json({
      code: coupon.code,
      isActive: coupon.isActive,
      currentUses: coupon.currentUses,
      maxUses: coupon.maxUses,
      validFrom: coupon.validFrom,
      validUntil: coupon.validUntil,
      isValid,
      remainingUses: coupon.maxUses ? coupon.maxUses - coupon.currentUses : 'Unlimited'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

couponSchema.pre('save', function(next) {
  if (this.maxUses && this.currentUses >= this.maxUses) {
    this.isActive = false;
  }
  next();
});

const cron = require('node-cron');

// Run every day at midnight
cron.schedule('0 0 * * *', async () => {
  try {
    // Deactivate expired coupons
    await Coupon.updateMany(
      { 
        validUntil: { $lt: new Date() },
        isActive: true 
      },
      { isActive: false }
    );

    // Deactivate coupons that reached max uses
    await Coupon.updateMany(
      {
        isActive: true,
        maxUses: { $ne: null },
        $expr: { $gte: [ "$currentUses", "$maxUses" ] }
      },
      { isActive: false }
    );

    console.log('Coupon maintenance completed');
  } catch (err) {
    console.error('Error in coupon maintenance:', err);
  }
});


// In your backend code (Node.js/Express)

// Get coupon usage details
// Add this with your other routes
app.get('/api/admin/coupons/:id/usage', authenticateAdmin, async (req, res) => {
  try {
    const couponId = req.params.id;
    
    // 1. Find the coupon
    const coupon = await Coupon.findById(couponId);
    if (!coupon) {
      return res.status(404).json({ error: 'Coupon not found' });
    }

    // 2. Get all bookings using this coupon
    const bookings = await Booking.find({ couponCode: coupon.code })
      .select('customerName customerEmail createdAt originalAmount discountAmount finalAmount')
      .sort({ createdAt: -1 });

    // 3. Update the coupon's currentUses count (real-time sync)
    const currentUses = bookings.length;
    await Coupon.findByIdAndUpdate(couponId, { 
      $set: { currentUses } 
    });

    res.json({
      success: true,
      coupon: {
        _id: coupon._id,
        code: coupon.code,
        discountType: coupon.discountType,
        discountValue: coupon.discountValue,
        currentUses, // Send updated count
        maxUses: coupon.maxUses,
        validFrom: coupon.validFrom,
        validUntil: coupon.validUntil
      },
      bookings: bookings,
      usageStats: {
        current: currentUses,
        remaining: coupon.maxUses > 0 ? coupon.maxUses - currentUses : 'Unlimited',
        percentageUsed: coupon.maxUses > 0 ? 
          Math.round((currentUses / coupon.maxUses) * 100) : 0
      }
    });

  } catch (err) {
    console.error('Error in coupon usage endpoint:', err);
    res.status(500).json({ 
      error: 'Server error',
      message: err.message 
    });
  }
});

// Record a payment for a booking
app.post('/api/admin/bookings/:id/payment', authenticateAdmin, async (req, res) => {
  try {
    const { amount, method, date } = req.body;
    const bookingId = req.params.id;
    
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    // Initialize payment breakdown if not exists
    if (!booking.paymentBreakdown) {
      booking.paymentBreakdown = {
        advancePaid: 0,
        remainingBalance: booking.finalAmount || 0,
        payments: []
      };
    }
    
    // Update payment details
    booking.paymentBreakdown.advancePaid += amount;
    booking.paymentBreakdown.remainingBalance -= amount;
    
    // Add payment record
    booking.paymentBreakdown.payments.push({
      amount,
      method,
      date: new Date(date),
      recordedAt: new Date()
    });
    
    // Update payment status if fully paid
    if (booking.paymentBreakdown.remainingBalance <= 0) {
      booking.paymentStatus = 'completed';
    } else {
      booking.paymentStatus = 'partially_paid';
    }
    
    await booking.save();
    
    res.json({ 
      success: true,
      booking: {
        _id: booking._id,
        paymentStatus: booking.paymentStatus,
        advancePaid: booking.paymentBreakdown.advancePaid,
        remainingBalance: booking.paymentBreakdown.remainingBalance
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
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
    
    const responseData = {
      ...booking.toObject(),
      amount: booking.package ? booking.package.replace(/[^0-9]/g, '') : '0',
      bookingDates: booking.bookingDates || 'Not specified',
      createdAt: booking.createdAt.toLocaleString()
    };
    
    res.json({ success: true, booking: responseData });
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

    const newMessage = new Message({
      userEmail: emails.join(','),
      subject,
      message,
      isHtml: isHtml === 'true',
      attachments
    });
    
    await newMessage.save();

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
      message: {
        ...newMessage.toObject(),
        _id: newMessage._id,
        attachments: newMessage.attachments.map(att => ({
          filename: att.filename,
          contentType: att.contentType,
          size: att.size
        }))
      }
    });
  } catch (err) {
    console.error('Error sending message:', err);
    
    if (req.files) {
      req.files.forEach(file => fs.unlinkSync(file.path));
    }
    
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Email Template Routes
app.get('/api/admin/email-templates', authenticateAdmin, async (req, res) => {
  try {
    const templates = await EmailTemplate.find().sort({ name: 1 });
    res.json({ success: true, templates });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch templates' });
  }
});

app.post('/api/admin/email-templates', authenticateAdmin, async (req, res) => {
  try {
    const { name, subject, html } = req.body;
    const template = new EmailTemplate({ name, subject, html });
    await template.save();
    res.json({ success: true, template });
  } catch (err) {
    res.status(500).json({ error: 'Failed to create template' });
  }
});

app.get('/api/admin/email-templates/:id', authenticateAdmin, async (req, res) => {
  try {
    const template = await EmailTemplate.findById(req.params.id);
    if (!template) return res.status(404).json({ error: 'Template not found' });
    res.json({ success: true, template });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch template' });
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

// IMAP Email Fetching
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

          const searchCriteria = ['UNSEEN'];
          const fetchOptions = {
            bodies: ['HEADER', 'TEXT'],
            struct: true,
            markSeen: false
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

// Email Sync Endpoint
app.post('/api/admin/inbox/sync', authenticateAdmin, async (req, res) => {
  try {
    console.log('[SYNC] Starting email synchronization process...');
    
    const settings = await Settings.findOne();
    if (!settings || !settings.imapUser || !settings.imapPass) {
      return res.status(400).json({
        success: false,
        error: 'IMAP settings not configured',
        message: 'Please configure your IMAP settings in the admin panel'
      });
    }

    console.log('[SYNC] Fetching emails from IMAP server...');
    const emails = await fetchEmailsFromIMAP();
    console.log(`[SYNC] Found ${emails.length} emails in IMAP inbox`);
    
    const savedMessages = [];
    let skippedCount = 0;
    let errorCount = 0;

    for (const [index, email] of emails.entries()) {
      try {
        console.log(`[SYNC] Processing email ${index + 1}/${emails.length}`);
        
        const parsed = await simpleParser(email.text);
        
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

        console.log('[SYNC] Saving message to database...');
        await newMessage.save();
        savedMessages.push(newMessage);
        console.log(`[SYNC] Message saved successfully (ID: ${newMessage._id})`);

      } catch (emailError) {
        console.error(`[SYNC] Error processing email ${index + 1}:`, emailError);
        errorCount++;
      }
    }

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

// Inbox Fetching
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
      })),
      total,
      totalPages: Math.ceil(total / limit),
      currentPage: parseInt(page)
    });
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

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public/admin.html'));
});

app.get('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json(settings || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/settings', authenticateAdmin, async (req, res) => {
  try {
    const { imapHost, imapPort, imapUser, imapPass } = req.body;
    
    const settings = await Settings.findOneAndUpdate(
      {},
      { 
        imapHost: imapHost || 'imap.hostinger.com',
        imapPort: imapPort || 993,
        imapUser,
        imapPass
      },
      { new: true, upsert: true }
    );
    
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: err.message });
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

// ===== USER ROUTES ===== //

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
    // Validate required fields
    if (!req.body.customerName || !req.body.customerEmail || !req.body.customerPhone || 
        !req.body.package || !req.body.bookingDates || !req.body.address || !req.body.transactionId) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

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
      couponCode,
      discountAmount = 0,
      amountPaid, // The actual amount paid in advance
      originalAmount,
      paymentMethod
    } = req.body;

    // Calculate amounts
    const packagePrice = originalAmount || parseInt(package.toString().replace(/[^0-9]/g, '')) || 0;
    const finalAmountAfterDiscount = packagePrice - (parseInt(discountAmount) || 0);
    
    // Payment calculations (10% advance standard)
    const advancePercentage = 0.10; // 10% advance
    const calculatedAdvancePaid = amountPaid || Math.round(finalAmountAfterDiscount * advancePercentage);
    const remainingBalance = finalAmountAfterDiscount - calculatedAdvancePaid;
    
    // Determine payment status
    const paymentStatus = remainingBalance <= 0 ? 'completed' : 'partially_paid';

    const newBooking = new Booking({
      customerName: customerName.trim(),
      customerEmail: customerEmail.trim(),
      customerPhone: customerPhone.trim(),
      package,
      bookingDates,
      preWeddingDate: preWeddingDate || undefined,
      address: address.trim(),
      transactionId,
      paymentStatus,
      status: 'pending',
      userId: userId || null,
      couponCode: couponCode || undefined,
      discountAmount: parseInt(discountAmount) || 0,
      finalAmount: finalAmountAfterDiscount,
      originalAmount: packagePrice,
      paymentBreakdown: {
        advancePaid: calculatedAdvancePaid,
        remainingBalance: remainingBalance,
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        paymentMethod: paymentMethod || 'online'
      }
    });

    await newBooking.save();

    // Customer Email Template
    const bookingConfirmationHtml = `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { 
      font-family: 'Arial', sans-serif; 
      line-height: 1.6; 
      color: #333; 
      max-width: 600px; 
      margin: 0 auto; 
      padding: 20px; 
    }
    .header { 
      background-color: #00acc1; 
      color: white; 
      padding: 20px; 
      text-align: center; 
      border-radius: 5px 5px 0 0; 
    }
    .content { 
      padding: 20px; 
      background-color: #f9f9f9; 
      border-radius: 0 0 5px 5px; 
    }
    .section {
      margin: 20px 0;
      padding: 15px;
      background-color: white;
      border-radius: 5px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .detail-row {
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      padding-bottom: 8px;
      border-bottom: 1px solid #eee;
    }
    .detail-label {
      font-weight: bold;
      color: #555;
    }
    .detail-value {
      text-align: right;
    }
    .total-row {
      font-weight: bold;
      font-size: 1.1em;
      margin-top: 10px;
      color: #00acc1;
    }
    .payment-button {
      display: inline-block;
      background-color: #00acc1;
      color: white;
      padding: 12px 25px;
      text-decoration: none;
      border-radius: 5px;
      margin-top: 15px;
      font-weight: bold;
    }
    .logo {
      text-align: center;
      margin-bottom: 20px;
    }
    .logo img {
      max-width: 180px;
    }
    .highlight {
      background-color: #fff8e1;
      padding: 10px;
      border-radius: 5px;
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>Booking Confirmation</h1>
  </div>
  <div class="content">
    <div class="logo">
      <img src="https://jokercreation.store/logo.png" alt="Joker Creation Studio">
    </div>
    
    <p>Dear ${customerName},</p>
    <p>Thank you for choosing Joker Creation Studio! Your booking has been confirmed.</p>
    
    <div class="section">
      <h3>Booking Details</h3>
      <div class="detail-row">
        <span class="detail-label">Booking ID:</span>
        <span class="detail-value">${newBooking._id}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Package:</span>
        <span class="detail-value">${package}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Event Date:</span>
        <span class="detail-value">${bookingDates}</span>
      </div>
      ${preWeddingDate ? `
      <div class="detail-row">
        <span class="detail-label">Pre-Wedding Date:</span>
        <span class="detail-value">${preWeddingDate}</span>
      </div>` : ''}
    </div>

    <div class="section highlight">
      <h3>Payment Summary</h3>
      
      <div class="detail-row">
        <span class="detail-label">Package Price:</span>
        <span class="detail-value">₹${packagePrice}</span>
      </div>

      ${couponCode ? `
      <div class="detail-row">
        <span class="detail-label">Discount (${couponCode}):</span>
        <span class="detail-value">- ₹${discountAmount}</span>
      </div>` : ''}

      <div class="detail-row total-row">
        <span class="detail-label">Final Amount:</span>
        <span class="detail-value">₹${finalAmountAfterDiscount}</span>
      </div>

      <div class="detail-row">
        <span class="detail-label">Advance Paid (${(advancePercentage * 100)}%):</span>
        <span class="detail-value">₹${calculatedAdvancePaid}</span>
      </div>

      <div class="detail-row total-row">
        <span class="detail-label">Remaining Balance:</span>
        <span class="detail-value">₹${remainingBalance}</span>
      </div>

      ${remainingBalance > 0 ? `
      <div style="text-align: center; margin-top: 20px;">
        <a href="https://jokercreation.store/payment?bookingId=${newBooking._id}" 
           class="payment-button">
          Pay Remaining ₹${remainingBalance}
        </a>
      </div>` : ''}
    </div>

    <p>We'll contact you soon to discuss your event details. For any questions, reply to this email.</p>
    <p>Best regards,<br>The Joker Creation Studio Team</p>
  </div>
</body>
</html>
`;

    // Admin Email Template
    const adminNotificationHtml = `
<!DOCTYPE html>
<html>
<head>
  <style>
    /* Similar styles as customer email but with admin colors */
    .header { background-color: #ff5722; }
    .total-row { color: #ff5722; }
    .highlight { background-color: #ffebee; }
  </style>
</head>
<body>
  <div class="header">
    <h1>New Booking Notification</h1>
  </div>
  <div class="content">
    <div class="logo">
      <img src="https://jokercreation.store/logo.png" alt="Joker Creation Studio">
    </div>
    
    <p>A new booking has been created:</p>
    
    <div class="section">
      <h3>Customer Details</h3>
      <div class="detail-row">
        <span class="detail-label">Name:</span>
        <span class="detail-value">${customerName}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Email:</span>
        <span class="detail-value">${customerEmail}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Phone:</span>
        <span class="detail-value">${customerPhone}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Address:</span>
        <span class="detail-value">${address}</span>
      </div>
    </div>

    <div class="section">
      <h3>Booking Details</h3>
      <div class="detail-row">
        <span class="detail-label">Booking ID:</span>
        <span class="detail-value">${newBooking._id}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Package:</span>
        <span class="detail-value">${package}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Event Date:</span>
        <span class="detail-value">${bookingDates}</span>
      </div>
      ${preWeddingDate ? `
      <div class="detail-row">
        <span class="detail-label">Pre-Wedding Date:</span>
        <span class="detail-value">${preWeddingDate}</span>
      </div>` : ''}
    </div>

    <div class="section highlight">
      <h3>Payment Information</h3>
      
      <div class="detail-row">
        <span class="detail-label">Package Price:</span>
        <span class="detail-value">₹${packagePrice}</span>
      </div>

      ${couponCode ? `
      <div class="detail-row">
        <span class="detail-label">Discount (${couponCode}):</span>
        <span class="detail-value">- ₹${discountAmount}</span>
      </div>` : ''}

      <div class="detail-row total-row">
        <span class="detail-label">Final Amount:</span>
        <span class="detail-value">₹${finalAmountAfterDiscount}</span>
      </div>

      <div class="detail-row">
        <span class="detail-label">Advance Paid:</span>
        <span class="detail-value">₹${calculatedAdvancePaid}</span>
      </div>

      <div class="detail-row">
        <span class="detail-label">Payment Method:</span>
        <span class="detail-value">${paymentMethod || 'online'}</span>
      </div>

      <div class="detail-row total-row">
        <span class="detail-label">Remaining Balance:</span>
        <span class="detail-value">₹${remainingBalance}</span>
      </div>

      <div class="detail-row">
        <span class="detail-label">Transaction ID:</span>
        <span class="detail-value">${transactionId}</span>
      </div>
    </div>

    <p>Please review this booking in the admin panel.</p>
  </div>
</body>
</html>
`;

    // Send emails
    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: customerEmail,
      subject: 'Booking Confirmation - Joker Creation Studio',
      html: bookingConfirmationHtml
    });

    await transporter.sendMail({
      from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL,
      subject: `New Booking: ${customerName} - ${package}`,
      html: adminNotificationHtml
    });

    res.status(200).json({ 
      success: true,
      message: 'Booking saved and confirmation emails sent successfully',
      booking: {
        id: newBooking._id,
        finalAmount: finalAmountAfterDiscount,
        advancePaid: calculatedAdvancePaid,
        remainingBalance: remainingBalance,
        paymentStatus: paymentStatus
      }
    });

  } catch (err) {
    console.error('Error saving booking:', err);
    res.status(500).json({ 
      error: 'Failed to save booking',
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
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

// Initialize admin and start server
initializeAdmin().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize admin:', err);
  process.exit(1);
});
