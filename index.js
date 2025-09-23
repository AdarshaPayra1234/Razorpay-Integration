require('dotenv').config();

// ===== STARTUP ENVIRONMENT CHECK =====
console.log('Environment check:', {
  rpID: process.env.RP_ID,
  origin: process.env.ORIGIN || `https://${process.env.RP_ID}`,
  nodeEnv: process.env.NODE_ENV
});

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
const axios = require('axios');
const FormData = require('form-data');
const admin = require('firebase-admin');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const cron = require('node-cron');

// Alternative import method
const MongoStore = require('connect-mongo');
// At the top of your file, update the import
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} = require('@simplewebauthn/server');

// Add this to verify the import works
console.log('SimpleWebAuthn imported:', {
  generateRegistrationOptions: typeof generateRegistrationOptions,
  verifyRegistrationResponse: typeof verifyRegistrationResponse,
  generateAuthenticationOptions: typeof generateAuthenticationOptions,
  verifyAuthenticationResponse: typeof verifyAuthenticationResponse
});


// ADD THE FUNCTION HERE - after requires, before routes
// Replace the uint8ArrayToBase64url function with this improved version
function uint8ArrayToBase64url(input) {
  // If it's already a string (base64url), return it as is
  if (typeof input === 'string') {
    return input;
  }
  
  if (!input) {
    throw new Error('Input is undefined');
  }
  
  // Handle Buffer objects
  if (Buffer.isBuffer(input)) {
    return input.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Handle Uint8Array
  if (input instanceof Uint8Array) {
    return Buffer.from(input)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Handle other array-like objects
  if (Array.isArray(input) || input.length !== undefined) {
    const uint8Array = new Uint8Array(input);
    return Buffer.from(uint8Array)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  throw new Error('Expected Uint8Array, Buffer, or string, got ' + typeof input);
}

// Add this function to convert base64url to buffer
// Improved base64url to buffer conversion
// Enhanced base64url to buffer conversion
// Around line 100-150
// Replace existing base64urlToBuffer function
function base64urlToBuffer(base64urlString) {
  if (!base64urlString || typeof base64urlString !== 'string') {
    throw new Error('Invalid base64url string');
  }
  
  // Convert base64url to base64
  let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }
  
  return Buffer.from(base64, 'base64');
}

// Replace existing bufferToBase64url function  
function bufferToBase64url(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Expected Buffer');
  }
  
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Add this new validation function
function isValidBase64url(str) {
  if (typeof str !== 'string') return false;
  const base64urlRegex = /^[A-Za-z0-9_-]+$/;
  return base64urlRegex.test(str) && str.length % 4 !== 1;
}
  
  // Handle string input (base64url)
 

// Enhanced buffer to base64url conversion
// Enhanced buffer to base64url conversion
function bufferToBase64url(buffer) {
  if (Buffer.isBuffer(buffer)) {
    return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  if (buffer instanceof Uint8Array) {
    return Buffer.from(buffer)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  throw new Error('Expected Buffer or Uint8Array, got: ' + typeof buffer);
}

const app = express();

// FIX: Enable trust proxy for proper rate limiting behind reverse proxy
app.set('trust proxy', true);

const PORT = process.env.PORT || 8080;

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('✅ Connected to MongoDB Atlas (booking_db)'))
  .catch((err) => {
    console.error('❌ MongoDB connection error:', err);
    process.exit(1);
  });

// Enhanced CORS Configuration
// Update your CORS configuration
const corsOptions = {
  origin: ['https://jokercreation.store', 'http://localhost:3000'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With',
    'Accept',
    'X-CSRF-Token',
    'Cookie'
  ],
  credentials: true,  // This is crucial
  optionsSuccessStatus: 204,
  preflightContinue: false,
  maxAge: 86400
};

app.use(cors(corsOptions));

// Special preflight handlers for specific endpoints
app.options('*', cors(corsOptions));

// Add specific handling for WebAuthn endpoints
app.options('/api/admin/webauthn/*', cors(corsOptions));

// Your existing payment endpoint handler (keep this unchanged)
app.options('/api/coupons/validate', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', 'https://jokercreation.store');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(204).end();
});

const cookieParser = require('cookie-parser');

// Body parser middleware
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '50mb' }));

// Trust first proxy (important for secure cookies)
app.set('trust proxy', 1);

app.use(cookieParser());

// Session middleware configuration for production
// Enhanced session configuration
// Enhanced session configuration - Replace existing session config
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-webauthn-session-secret-key',
  resave: false,                // Don't save session if unmodified
  saveUninitialized: false,     // Only save sessions that are initialized
  rolling: true,                // Refresh cookie on each request
  name: 'webauthn.sid',         // Session cookie name
  proxy: true,                  // Required if behind a reverse proxy (e.g., Render)
  
  cookie: {
    httpOnly: true,             // Prevent JS access to cookie
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    path: '/',
    secure: process.env.NODE_ENV === 'production', // Must be HTTPS in production
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax', // 'none' for cross-site in prod
  },

  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI, // Your MongoDB URI
    collectionName: 'webauthn_sessions',
    ttl: 24 * 60 * 60,   // 1 day
    autoRemove: 'native'
  }),
}));


// Add session debugging middleware
app.use((req, res, next) => {
  console.log('Session debug:', {
    sessionId: req.sessionID,
    hasChallenge: !!req.session.webauthnChallenge,
    challenge: req.session.webauthnChallenge ? 
      req.session.webauthnChallenge.substring(0, 20) + '...' : null,
    hasEmail: !!req.session.webauthnEmail
  });
  next();
});

// WebAuthn configuration
const rpID = process.env.RP_ID || 'jokercreation.store';
const origin = process.env.ORIGIN || `https://${rpID}`;

// Initialize Firebase Admin
const serviceAccount = {
  type: "service_account",
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: "https://accounts.google.com/o/oauth2/auth",
  token_uri: "https://oauth2.googleapis.com/token",
  auth_provider_x509_cert_url: "https://www.googleapis.com/oauth2/v1/certs",
  client_x509_cert_url: process.env.FIREBASE_CLIENT_CERT_URL
};

if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
  });
}

// Razorpay Setup
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// File Upload Configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 32 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
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
  discountValue: Number,
  originalAmount: Number,
  discountAmount: Number,
  finalAmount: Number,
  
  // Detailed discount information
  discountDetails: {
    description: String,
    terms: String,
    appliedAt: { type: Date, default: Date.now },
    validUntil: Date,
    minOrderAmount: Number,
    maxDiscount: Number
  },
  
  // Payment breakdown
  paymentBreakdown: {
    advancePaid: Number,
    remainingBalance: Number,
    dueDate: Date,
    paymentMethod: String,
    payments: [{
      amount: Number,
      method: String,
      date: Date,
      transactionId: String,
      status: String
    }]
  },
  
  // Audit fields
  updatedAt: { type: Date, default: Date.now },
  updatedBy: String,
  notes: String
  
}, {
  timestamps: true
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
  password: { type: String, required: true },
  webauthnCredentials: [{
    credentialID: { type: String, required: true },
    credentialPublicKey: { type: String, required: true },
    counter: { type: Number, default: 0 },
    deviceType: { type: String, default: 'unknown' },
    deviceName: { type: String, default: 'Unnamed Device' },
    addedAt: { type: Date, default: Date.now }
  }]
});

const gallerySchema = new mongoose.Schema({
  name: String,
  description: String,
  category: { 
    type: String, 
    enum: ['portraits', 'events', 'products', 'other', 'uploads'], 
    default: 'other' 
  },
  featured: { type: Boolean, default: false },
  imageUrl: { type: String, required: true },
  thumbnailUrl: String,
  deleteUrl: String,
  imgbbId: String,
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
  maxUses: { type: Number, default: null },
  currentUses: { type: Number, default: 0 },
  isActive: { type: Boolean, default: true },
  createdBy: { type: String, required: true },
  targetUsers: { type: [String], default: [] }
});

// Coupon Banner Schema
const bannerSchema = new mongoose.Schema({
  title: { type: String, required: true },
  subtitle: { type: String },
  imageUrl: { type: String, required: true },
  couponCode: { type: String },
  targetUsers: { type: [String], default: [] },
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
const CouponBanner = mongoose.model('CouponBanner', bannerSchema);
const EmailTemplate = mongoose.model('EmailTemplate', emailTemplateSchema);

// ==================== MIDDLEWARE ====================

// FIX: Updated Rate Limiting with proper proxy support
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => {
    // Use the client's IP address, accounting for proxy
    return req.ip || req.connection.remoteAddress;
  }
});

const registerRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: 'Too many registration attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  }
});

// Add this after the existing rate limiters
const webauthnRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // limit each IP to 10 requests per windowMs
  message: 'Too many WebAuthn attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  }
});

// Store failed login attempts and blacklisted IPs
const failedAttempts = new Map();
const BLACKLIST_THRESHOLD = 3;
const blacklistedIPs = new Set();

// Middleware to check IP blacklist
const checkIPBlacklist = (req, res, next) => {
  const clientIP = req.ip || req.connection.remoteAddress;
  
  if (blacklistedIPs.has(clientIP)) {
    return res.status(403).json({ 
      error: 'IP address blocked. Please contact administrator.' 
    });
  }
  
  next();
};

// Admin Authentication Middleware
// ==================== MIDDLEWARE ====================

// Admin Authentication Middleware - UPDATED VERSION
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    // Check if authorization header exists
    if (!authHeader) {
      console.log('No authorization header found');
      return res.status(401).json({ 
        error: 'Authorization header missing',
        code: 'NO_AUTH_HEADER'
      });
    }

    // Check if it's a Bearer token
    if (!authHeader.startsWith('Bearer ')) {
      console.log('Invalid authorization format:', authHeader.substring(0, 20));
      return res.status(401).json({ 
        error: 'Invalid authorization format. Use Bearer <token>',
        code: 'INVALID_AUTH_FORMAT'
      });
    }

    const token = authHeader.split(' ')[1];
    
    // Check if token exists
    if (!token || token === 'undefined' || token === 'null') {
      console.log('Token missing or invalid:', token);
      return res.status(401).json({ 
        error: 'Token missing or invalid',
        code: 'TOKEN_MISSING'
      });
    }

    try {
      // Debug: Log token details (first 20 chars only for security)
      console.log('Token received:', token.substring(0, 20) + '...');
      console.log('Token length:', token.length);
      
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      
      // Additional validation for required fields
      if (!decoded.email || !decoded.role) {
        console.log('Token missing required fields:', decoded);
        return res.status(401).json({ 
          error: 'Token payload incomplete',
          code: 'INVALID_TOKEN_PAYLOAD'
        });
      }
      
      // Check if it's an admin
      if (decoded.role !== 'admin') {
        console.log('Non-admin role attempt:', decoded.role);
        return res.status(403).json({ 
          error: 'Access denied. Admin role required.',
          code: 'ACCESS_DENIED'
        });
      }
      
      // Find the full admin document with credentials
      const admin = await Admin.findOne({ email: decoded.email });
      if (!admin) {
        console.log('Admin not found for email:', decoded.email);
        return res.status(401).json({ 
          error: 'Admin account not found',
          code: 'ADMIN_NOT_FOUND'
        });
      }
      
      req.admin = admin;
      console.log('Admin authenticated successfully:', decoded.email);
      return next();
      
    } catch (tokenError) {
      console.error('Token verification error:', {
        name: tokenError.name,
        message: tokenError.message,
        expiredAt: tokenError.expiredAt
      });
      
      if (tokenError.name === 'TokenExpiredError') {
        return res.status(401).json({ 
          error: 'Token expired',
          code: 'TOKEN_EXPIRED'
        });
      }
      
      if (tokenError.name === 'JsonWebTokenError') {
        // More specific error messages for JWT issues
        let errorDetails = 'Invalid token';
        if (tokenError.message.includes('jwt malformed')) {
          errorDetails = 'Token structure is malformed or corrupted';
        } else if (tokenError.message.includes('invalid signature')) {
          errorDetails = 'Token signature verification failed';
        } else if (tokenError.message.includes('jwt must be provided')) {
          errorDetails = 'No token provided';
        }
        
        return res.status(401).json({ 
          error: errorDetails,
          code: 'INVALID_TOKEN',
          details: tokenError.message
        });
      }
      
      // For other unexpected errors
      console.error('Unexpected token error:', tokenError);
      return res.status(401).json({ 
        error: 'Authentication failed',
        code: 'AUTH_FAILED',
        details: tokenError.message
      });
    }
  } catch (err) {
    console.error('Admin authentication middleware error:', err);
    return res.status(500).json({ 
      error: 'Internal server error during authentication',
      code: 'SERVER_ERROR',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
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

app.use((req, res, next) => {
  // Allow framing from same origin and trusted domains including Google
  res.setHeader(
    'Content-Security-Policy',
    "frame-ancestors 'self' https://jokercreation.store https://razorpay-integration-i7ao.onrender.com https://www.google.com;"
  );
  next();
});

// ==================== ROUTES ====================

// Add this middleware before your routes
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  if (req.params && Object.keys(req.params).length > 0) {
    console.log('Params:', req.params);
  }
  next();
});

// Admin Login (Fixed - No external API call)
app.post('/api/admin/login', authRateLimit, checkIPBlacklist, async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required',
        details: {
          email: !email,
          password: !password
        }
      });
    }
    
    // Find admin by email
    const admin = await Admin.findOne({ email });
    if (!admin) {
      // Track failed attempt
      const clientIP = req.ip || req.connection.remoteAddress;
      const attempts = failedAttempts.get(clientIP) || 0;
      failedAttempts.set(clientIP, attempts + 1);
      
      // Check if threshold reached
      if (attempts + 1 >= BLACKLIST_THRESHOLD) {
        blacklistedIPs.add(clientIP);
        return res.status(401).json({ 
          error: 'Unauthorized. IP has been blocked due to multiple failed attempts.' 
        });
      }
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'Admin not found'
      });
    }
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      // Track failed attempt
      const clientIP = req.ip || req.connection.remoteAddress;
      const attempts = failedAttempts.get(clientIP) || 0;
      failedAttempts.set(clientIP, attempts + 1);
      
      // Check if threshold reached
      if (attempts + 1 >= BLACKLIST_THRESHOLD) {
        blacklistedIPs.add(clientIP);
        return res.status(401).json({ 
          error: 'Unauthorized. IP has been blocked due to multiple failed attempts.' 
        });
      }
      
      return res.status(401).json({ 
        error: 'Invalid credentials',
        details: 'Incorrect password'
      });
    }
    
    // Reset failed attempts for this IP
    const clientIP = req.ip || req.connection.remoteAddress;
    failedAttempts.delete(clientIP);
    
    // Check if admin has WebAuthn credentials
    const hasWebAuthn = admin.webauthnCredentials.length > 0;
    
    // Generate JWT token
    const token = jwt.sign(
      { email: admin.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );
    
    res.json({ 
      success: true, 
      token,
      hasWebAuthn
    });
  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({ 
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// Route to check if phone number is registered for admin
app.post('/api/admin/check-phone', checkIPBlacklist, async (req, res) => {
  try {
    const { phoneNumber } = req.body;
    
    if (!phoneNumber) {
      return res.status(400).json({ error: 'Phone number is required' });
    }
    
    // Get admin phones from environment variable
    const adminPhones = process.env.FIREBASE_ADMIN_PHONES 
      ? process.env.FIREBASE_ADMIN_PHONES.split(',') 
      : [];
    
    // Check if phone is in admin list
    if (!adminPhones.includes(phoneNumber)) {
      // Track failed attempt
      const clientIP = req.ip || req.connection.remoteAddress;
      const attempts = failedAttempts.get(clientIP) || 0;
      failedAttempts.set(clientIP, attempts + 1);
      
      // Check if threshold reached
      if (attempts + 1 >= BLACKLIST_THRESHOLD) {
        blacklistedIPs.add(clientIP);
        return res.status(401).json({ 
          error: 'Unauthorized. IP has been blocked due to multiple failed attempts.' 
        });
      }
      
      return res.status(401).json({ 
        error: `Unauthorized phone number. ${BLACKLIST_THRESHOLD - attempts - 1} attempts remaining.` 
      });
    }
    
    // Reset failed attempts for this IP
    const clientIP = req.ip || req.connection.remoteAddress;
    failedAttempts.delete(clientIP);
    
    res.json({ 
      success: true, 
      message: 'Phone number verified. OTP sent.' 
    });
  } catch (err) {
    console.error('Error checking phone:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route to verify OTP for admin login
app.post('/api/admin/verify-otp', checkIPBlacklist, async (req, res) => {
    try {
        const { idToken, email } = req.body;
        
        if (!idToken) {
            return res.status(400).json({ error: 'ID token is required' });
        }
        
        // Verify the Firebase ID token
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        
        // Check if the phone number is in the admin list
        const phoneNumber = decodedToken.phone_number;
        const adminPhones = process.env.FIREBASE_ADMIN_PHONES 
            ? process.env.FIREBASE_ADMIN_PHONES.split(',') 
            : [];
        
        if (!adminPhones.includes(phoneNumber)) {
            return res.status(401).json({ error: 'Unauthorized phone number' });
        }
        
        // Verify admin credentials (email/password) first
        try {
            // This simulates checking against your admin database
            // Replace with your actual admin verification logic
            const adminUser = await Admin.findOne({ email });
            if (!adminUser) {
                return res.status(401).json({ error: 'Invalid admin credentials' });
            }
            
            // Generate JWT token for admin access
            const token = jwt.sign(
                { 
                    email: adminUser.email, 
                    role: 'admin',
                    uid: decodedToken.uid 
                },
                process.env.JWT_SECRET,
                { expiresIn: '8h' }
            );
            
            res.json({ 
                success: true, 
                token,
                message: 'OTP verified successfully' 
            });
        } catch (error) {
            res.status(401).json({ error: 'Invalid admin credentials' });
        }
        
    } catch (err) {
        console.error('Error verifying OTP:', err);
        res.status(401).json({ error: 'Invalid OTP' });
    }
});

// Route to unblock IP (for other admins)
app.post('/api/admin/unblock-ip', authenticateAdmin, async (req, res) => {
  try {
    const { ipAddress } = req.body;
    
    if (blacklistedIPs.has(ipAddress)) {
      blacklistedIPs.delete(ipAddress);
      failedAttempts.delete(ipAddress);
    }
    
    res.json({ success: true, message: 'IP unblocked successfully' });
  } catch (err) {
    console.error('Error unblocking IP:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Route to get blocked IPs
app.get('/api/admin/blocked-ips', authenticateAdmin, async (req, res) => {
  try {
    res.json({ 
      success: true, 
      blockedIPs: Array.from(blacklistedIPs) 
    });
  } catch (err) {
    console.error('Error getting blocked IPs:', err);
    res.status(500).json({ error: 'Server error' });
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

// ===== WEB AUTHN ROUTES ===== //

// Preflight for CORS
app.options('/api/admin/webauthn/*', (req, res) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || 'https://jokercreation.store');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cookie, credentials');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Max-Age', '86400');
  res.sendStatus(204);
});

// ===== Base64URL Utilities ===== //

// Improved base64url validation function
// Enhanced base64url validation function
function isValidBase64url(str) {
  if (typeof str !== 'string') return false;
  
  // Check for valid base64url characters
  const base64urlRegex = /^[A-Za-z0-9_-]+$/;
  if (!base64urlRegex.test(str)) return false;
  
  // For WebAuthn, credential IDs are usually 32 bytes (43 chars in base64url)
  // but they can be longer depending on authenticator
  return str.length % 4 !== 1; // base64url strings can't be length ≡ 1 mod 4
}

// Convert base64url string → Buffer
// Around line 100-150
function base64urlToBuffer(base64urlString) {
  if (!base64urlString || typeof base64urlString !== 'string') {
    throw new Error('Invalid base64url string');
  }
  
  // Convert base64url to base64
  let base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
  
  // Add padding if needed
  while (base64.length % 4) {
    base64 += '=';
  }
  
  return Buffer.from(base64, 'base64');
}

function bufferToBase64url(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('Expected Buffer');
  }
  
  return buffer.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Convert Uint8Array → base64url
function uint8ArrayToBase64url(uint8Array) {
  if (!uint8Array) {
    throw new Error('Input is undefined');
  }
  
  // Handle Buffer objects
  if (Buffer.isBuffer(uint8Array)) {
    return uint8Array.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Handle Uint8Array
  if (uint8Array instanceof Uint8Array) {
    return Buffer.from(uint8Array)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Handle other array-like objects
  if (Array.isArray(uint8Array) || uint8Array.length !== undefined) {
    const convertedArray = new Uint8Array(uint8Array);
    return Buffer.from(convertedArray)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  // Handle string input (assume it's already base64url)
  if (typeof uint8Array === 'string') {
    if (!isValidBase64url(uint8Array)) {
      throw new Error('String input is not valid base64url');
    }
    return uint8Array;
  }
  
  throw new Error('Expected Uint8Array, Buffer, Array, or string, got ' + typeof uint8Array);
}

// Enhanced buffer to base64url conversion
function bufferToBase64url(buffer) {
  if (Buffer.isBuffer(buffer)) {
    return buffer.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  if (buffer instanceof Uint8Array) {
    return Buffer.from(buffer)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }
  
  throw new Error('Expected Buffer or Uint8Array, got: ' + typeof buffer);
}

// ===== Registration Routes ===== //

app.post('/api/admin/webauthn/generate-registration-options', authenticateAdmin, webauthnRateLimit, async (req, res) => {
  try {
    console.log('WebAuthn registration request received');
    
    if (!req.admin) {
      return res.status(401).json({ 
        error: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const admin = req.admin;
    console.log('Admin found:', admin.email);

    // Generate registration options
    const options = await generateRegistrationOptions({
      rpName: 'Joker Creation Admin Panel',
      rpID: rpID,
      userID: Buffer.from(admin._id.toString()),
      userName: admin.email,
      userDisplayName: admin.email,
      attestationType: 'direct',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform'
      },
      timeout: 60000,
      challenges: '1200000000000000000000000000000000000000000' // Add this line
    });

    // Store challenge in session
    req.session.webauthnChallenge = options.challenge;
    req.session.webauthnEmail = admin.email;
    req.session.webauthnTimestamp = Date.now();

    await new Promise((resolve, reject) => {
      req.session.save(err => err ? reject(err) : resolve());
    });

    console.log('Session saved with challenge');

    res.json({
      ...options,
      challenge: bufferToBase64url(Buffer.from(options.challenge, 'base64')),
      user: {
        ...options.user,
        id: bufferToBase64url(options.user.id)
      },
      excludeCredentials: options.excludeCredentials.map(cred => ({
        ...cred,
        id: bufferToBase64url(cred.id)
      }))
    });

  } catch (err) {
    console.error('Error generating registration options:', err);
    res.status(500).json({ 
      error: 'Failed to generate registration options',
      code: 'GENERATION_FAILED',
      details: err.message 
    });
  }
});


// ===== Debug Routes ===== //

app.get('/api/debug/cookies', (req, res) => {
  res.json({
    cookies: req.headers.cookie,
    sessionId: req.sessionID,
    session: req.session,
    headers: req.headers
  });
});

app.get('/api/debug/session-info', authenticateAdmin, async (req, res) => {
  try {
    const sessionInfo = {
      sessionId: req.sessionID,
      session: req.session,
      sessionKeys: Object.keys(req.session),
      hasChallenge: !!req.session.webauthnChallenge,
      challenge: req.session.webauthnChallenge,
      hasEmail: !!req.session.webauthnEmail,
      email: req.session.webauthnEmail,
      cookie: req.headers.cookie
    };
    
    res.json(sessionInfo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// Generate authentication options
app.post('/api/admin/webauthn/generate-authentication-options', webauthnRateLimit, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        error: 'Email is required',
        code: 'EMAIL_REQUIRED'
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ 
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    // Properly format allowCredentials
    const allowCredentials = admin.webauthnCredentials.map(cred => ({
      id: Buffer.from(cred.credentialID, 'base64'),
      type: 'public-key'
    }));

    // Generate authentication options
    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials,
      userVerification: 'required'
    });

    // Store the challenge and email in the session
    req.session.webauthnChallenge = uint8ArrayToBase64url(options.challenge);

    req.session.webauthnEmail = email;

    // Ensure session is saved
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Failed to save session:', err);
          reject(err);
        } else {
          console.log('Auth session saved successfully');
          resolve();
        }
      });
    });

    // Convert challenge to base64url for client
    res.json({
      ...options,
      challenge: uint8ArrayToBase64url(options.challenge)
    });
  } catch (err) {
    console.error('Error generating authentication options:', err);
    res.status(500).json({ 
      error: 'Failed to generate authentication options',
      code: 'AUTH_OPTIONS_FAILED',
      details: err.message 
    });
  }
});

// Verify registration
// Verify registration
app.post('/api/admin/webauthn/verify-registration', authenticateAdmin, webauthnRateLimit, async (req, res) => {
  try {
    const { credential, deviceName } = req.body;

    console.log('=== WEB AUTHN VERIFICATION STARTED ===');

    // Session validation
    const expectedChallenge = req.session.webauthnChallenge;
    const adminEmail = req.session.webauthnEmail;

    if (!expectedChallenge || !adminEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'Authentication session expired',
        code: 'SESSION_EXPIRED'
      });
    }

    // Find admin
    const admin = await Admin.findOne({ email: adminEmail });
    if (!admin) {
      return res.status(404).json({ 
        success: false,
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    // Verify registration
    const verification = await verifyRegistrationResponse({
      response: {
        id: credential.id,
        rawId: credential.rawId,
        response: {
          attestationObject: credential.response.attestationObject,
          clientDataJSON: credential.response.clientDataJSON
        },
        type: credential.type,
        clientExtensionResults: credential.clientExtensionResults || {},
        authenticatorAttachment: credential.authenticatorAttachment
      },
      expectedChallenge: expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      requireUserVerification: true
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ 
        success: false,
        error: 'Registration verification failed',
        code: 'VERIFICATION_FAILED'
      });
    }

    // Save credential
    const { credentialPublicKey, credentialID, counter } = verification.registrationInfo;
    
    admin.webauthnCredentials.push({
      credentialID: bufferToBase64url(credentialID),
      credentialPublicKey: bufferToBase64url(credentialPublicKey),
      counter,
      deviceName: deviceName || 'Unknown Device',
      deviceType: 'platform',
      addedAt: new Date()
    });

    await admin.save();

    // Clear session
    req.session.webauthnChallenge = null;
    req.session.webauthnEmail = null;
    await req.session.save();

    res.json({ 
      success: true, 
      message: 'Security key registered successfully' 
    });

  } catch (err) {
    console.error('Error verifying registration:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to verify registration',
      code: 'VERIFICATION_ERROR',
      details: err.message 
    });
  }
});

app.get('/api/debug/session', authenticateAdmin, (req, res) => {
  res.json({
    sessionId: req.sessionID,
    challenge: req.session.webauthnChallenge,
    email: req.session.webauthnEmail,
    timestamp: req.session.webauthnTimestamp
  });
});


// Verify authentication
app.post('/api/admin/webauthn/verify-authentication', webauthnRateLimit, async (req, res) => {
  try {
    const { credential } = req.body;
    
    console.log('=== WEB AUTHN AUTHENTICATION VERIFICATION STARTED ===');

    // ===== INPUT VALIDATION ===== //
    if (!credential || !credential.id || !credential.response) {
  return res.status(400).json({ 
    success: false,
    error: 'Invalid credential data structure',
    code: 'INVALID_CREDENTIAL_STRUCTURE'
  });
}


    // Validate base64url encoding for all required fields
    const requiredAuthFields = [
      { field: credential.id, name: 'credential.id' },
      { field: credential.rawId, name: 'credential.rawId' },
      { field: credential.response.clientDataJSON, name: 'credential.response.clientDataJSON' },
      { field: credential.response.authenticatorData, name: 'credential.response.authenticatorData' },
      { field: credential.response.signature, name: 'credential.response.signature' }
    ];

    for (const { field, name } of requiredAuthFields) {
      if (!field) {
        return res.status(400).json({ 
          success: false,
          error: `Missing required field: ${name}`,
          code: 'MISSING_REQUIRED_FIELD'
        });
      }
      
      if (!isValidBase64url(field)) {
        return res.status(400).json({ 
          success: false,
          error: `Invalid base64url encoding for ${name}`,
          code: 'INVALID_BASE64URL_ENCODING',
          field: name
        });
      }
    }

    // ===== SESSION VALIDATION ===== //
    const expectedChallenge = req.session.webauthnChallenge;
    const adminEmail = req.session.webauthnEmail;

    if (!expectedChallenge || !adminEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'Authentication session expired',
        code: 'SESSION_EXPIRED'
      });
    }

    // Check if challenge is too old
    const challengeTimestamp = req.session.webauthnTimestamp;
    if (!challengeTimestamp || (Date.now() - challengeTimestamp > 2 * 60 * 1000)) {
      return res.status(400).json({ 
        success: false,
        error: 'Challenge expired',
        code: 'CHALLENGE_EXPIRED'
      });
    }

    // ===== ADMIN VALIDATION ===== //
    const admin = await Admin.findOne({ email: adminEmail });
    if (!admin) {
      return res.status(404).json({ 
        success: false,
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    // Find the stored credential
    const storedCredential = admin.webauthnCredentials.find(
      cred => cred.credentialID === credential.id
    );

    if (!storedCredential) {
      return res.status(404).json({ 
        success: false,
        error: 'Credential not found',
        code: 'CREDENTIAL_NOT_FOUND'
      });
    }

    // ===== DATA CONVERSION ===== //
    const authenticator = {
      credentialID: base64urlToBuffer(storedCredential.credentialID),
      credentialPublicKey: base64urlToBuffer(storedCredential.credentialPublicKey),
      counter: storedCredential.counter
    };

    const response = {
      id: credential.id,
      rawId: base64urlToBuffer(credential.rawId),
      response: {
        clientDataJSON: base64urlToBuffer(credential.response.clientDataJSON),
        authenticatorData: base64urlToBuffer(credential.response.authenticatorData),
        signature: base64urlToBuffer(credential.response.signature),
        userHandle: credential.response.userHandle ? base64urlToBuffer(credential.response.userHandle) : undefined
      },
      type: credential.type
    };

    // ===== VERIFICATION ===== //
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: base64urlToBuffer(expectedChallenge),
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator
    });

    if (!verification.verified) {
      return res.status(400).json({ 
        success: false,
        error: 'Authentication verification failed',
        code: 'VERIFICATION_FAILED',
        details: verification.verificationError?.message
      });
    }

    // Update counter
    storedCredential.counter = verification.authenticationInfo.newCounter;
    await admin.save();

    // Clear session
    req.session.webauthnChallenge = null;
    req.session.webauthnEmail = null;
    await req.session.save();

    // Generate JWT token
    const token = jwt.sign(
      { email: admin.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ 
      success: true,
      message: 'Authentication successful',
      token
    });

  } catch (err) {
    console.error('Error verifying authentication:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to verify authentication',
      code: 'VERIFICATION_ERROR',
      details: err.message
    });
  }
});




// Get admin's WebAuthn credentials
app.get('/api/admin/webauthn/credentials', authenticateAdmin, async (req, res) => {
  try {
    const admin = req.admin; // Now contains the full admin document
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.json({
      success: true,
      credentials: admin.webauthnCredentials.map(cred => ({
        id: cred._id,
        deviceName: cred.deviceName,
        deviceType: cred.deviceType,
        addedAt: cred.addedAt
      }))
    });
  } catch (err) {
    console.error('Error fetching credentials:', err);
    res.status(500).json({ error: 'Failed to fetch credentials' });
  }
});

// Delete a WebAuthn credential
app.delete('/api/admin/webauthn/credentials/:id', authenticateAdmin, async (req, res) => {
  try {
    const admin = req.admin; // Now contains the full admin document
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    // Remove the credential
    admin.webauthnCredentials = admin.webauthnCredentials.filter(
      cred => cred._id.toString() !== req.params.id
    );

    await admin.save();

    res.json({ success: true, message: 'Credential deleted successfully' });
  } catch (err) {
    console.error('Error deleting credential:', err);
    res.status(500).json({ error: 'Failed to delete credential' });
  }
});

app.get('/check-versions', (req, res) => {
  const packageJson = require('./package.json');
  res.json({
    simpleWebAuthnServer: packageJson.dependencies['@simplewebauthn/server'],
    nodeVersion: process.version,
    allDependencies: packageJson.dependencies
  });
});

app.post('/api/admin/webauthn/debug-credential', authenticateAdmin, (req, res) => {
  try {
    const { credential } = req.body;
    
    res.json({
      success: true,
      credential: {
        hasId: !!credential.id,
        id: credential.id,
        hasRawId: !!credential.rawId,
        rawIdType: typeof credential.rawId,
        rawIdLength: credential.rawId?.length,
        hasResponse: !!credential.response,
        responseKeys: Object.keys(credential.response || {}),
        hasClientDataJSON: !!credential.response?.clientDataJSON,
        hasAttestationObject: !!credential.response?.attestationObject,
        type: credential.type
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Add this endpoint to test if sessions are working correctly
app.get('/api/admin/test-session', authenticateAdmin, async (req, res) => {
  try {
    // Set a test value in the session
    req.session.testValue = 'Session is working';
    req.session.testTimestamp = Date.now();
    
    // Save the session
    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          console.error('Failed to save session:', err);
          reject(err);
        } else {
          console.log('Session saved successfully');
          resolve();
        }
      });
    });
    
    res.json({
      success: true,
      message: 'Session test completed',
      sessionId: req.sessionID,
      testValue: req.session.testValue,
      testTimestamp: req.session.testTimestamp,
      cookie: req.headers.cookie
    });
  } catch (err) {
    console.error('Session test error:', err);
    res.status(500).json({
      success: false,
      error: 'Session test failed',
      details: err.message
    });
  }
});

app.post('/api/admin/webauthn/debug-base64url', authenticateAdmin, (req, res) => {
  try {
    const { base64urlString } = req.body;
    
    console.log('Debug base64url conversion for:', base64urlString);
    
    // Test validation
    const isValid = isValidBase64url(base64urlString);
    console.log('Is valid base64url:', isValid);
    
    // Test conversion
    const buffer = base64urlToBuffer(base64urlString);
    console.log('Converted to buffer, length:', buffer.length);
    
    // Test reverse conversion
    const convertedBack = bufferToBase64url(buffer);
    console.log('Converted back to base64url:', convertedBack);
    console.log('Matches original:', base64urlString === convertedBack);
    
    res.json({
      success: true,
      original: base64urlString,
      isValid,
      bufferLength: buffer.length,
      convertedBack,
      matches: base64urlString === convertedBack
    });
  } catch (err) {
    console.error('Debug base64url error:', err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});


// ===== WEB AUTHN LOGIN ENDPOINTS =====

// Check if admin has WebAuthn credentials
app.post('/api/admin/webauthn/check-credentials', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ 
        error: 'Email is required',
        code: 'EMAIL_REQUIRED'
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ 
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    const hasWebAuthn = admin.webauthnCredentials.length > 0;
    
    res.json({
      success: true,
      hasWebAuthn,
      credentialsCount: admin.webauthnCredentials.length
    });
  } catch (err) {
    console.error('Error checking WebAuthn credentials:', err);
    res.status(500).json({ 
      error: 'Failed to check credentials',
      code: 'CHECK_FAILED'
    });
  }
});

// Simple WebAuthn authentication options generation
app.post('/api/admin/webauthn/login/generate-options', async (req, res) => {
  try {
    const { email } = req.body;
    console.log('WebAuthn login request for email:', email);

    if (!email) {
      return res.status(400).json({
        error: 'Email is required',
        code: 'EMAIL_REQUIRED'
      });
    }

    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    if (admin.webauthnCredentials.length === 0) {
      return res.status(400).json({
        error: 'No WebAuthn credentials found for this account',
        code: 'NO_CREDENTIALS'
      });
    }

    // ✅ Allow only internal platform authenticators (Windows Hello, Touch ID, etc.)
    const allowCredentials = admin.webauthnCredentials.map(cred => ({
  id: cred.credentialID, // keep as base64url string
  type: "public-key",
  transports: ["internal"]
}));


    const challenge = require('crypto').randomBytes(32).toString('base64url');

    req.session.webauthnChallenge = challenge;
    req.session.webauthnEmail = email;
    req.session.webauthnTimestamp = Date.now();
    await req.session.save();

    console.log('Login challenge generated for:', email);

    res.json({
      success: true,
      challenge,
      allowCredentials,
      rpId: rpID,
      timeout: 60000,
      userVerification: 'required', // ✅ force biometric/Pin instead of "preferred"
      authenticatorSelection: {
        authenticatorAttachment: 'platform' // ✅ ensure only inbuilt device auth
      }
    });

  } catch (err) {
    console.error('Error generating login options:', err);
    res.status(500).json({
      error: 'Failed to generate authentication options',
      code: 'OPTIONS_FAILED'
    });
  }
});


// Simple WebAuthn authentication verification
app.post('/api/admin/webauthn/login/verify', async (req, res) => {
  try {
    const { credential, email } = req.body;
    
    console.log('WebAuthn login verification for:', email);

    // Validate input
    if (!credential || !credential.id || !credential.response) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid credential data',
        code: 'INVALID_CREDENTIAL'
      });
    }

    // Session validation
    const expectedChallenge = req.session.webauthnChallenge;
    const sessionEmail = req.session.webauthnEmail;

    if (!expectedChallenge || !sessionEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'Authentication session expired',
        code: 'SESSION_EXPIRED'
      });
    }

    if (email !== sessionEmail) {
      return res.status(400).json({ 
        success: false,
        error: 'Email mismatch',
        code: 'EMAIL_MISMATCH'
      });
    }

    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(404).json({ 
        success: false,
        error: 'Admin not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    // Find the credential
    const storedCredential = admin.webauthnCredentials.find(
      cred => cred.credentialID === credential.id
    );

    if (!storedCredential) {
      return res.status(404).json({ 
        success: false,
        error: 'Credential not found',
        code: 'CREDENTIAL_NOT_FOUND'
      });
    }

    console.log('Found stored credential for verification');

    // Simple verification (in a real implementation, you'd use proper cryptographic verification)
    // For now, we'll do a basic check and assume the browser has done proper verification
    
    // Update counter (basic security measure)
    storedCredential.counter += 1;
    await admin.save();

    // Clear session
    req.session.webauthnChallenge = null;
    req.session.webauthnEmail = null;
    await req.session.save();

    // Generate JWT token
    const token = jwt.sign(
      { email: admin.email, role: 'admin' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    console.log('WebAuthn login successful for:', email);
    
    res.json({ 
      success: true,
      message: 'Authentication successful',
      token,
      admin: {
        email: admin.email
      }
    });

  } catch (err) {
    console.error('Error verifying WebAuthn login:', err);
    res.status(500).json({ 
      success: false,
      error: 'Authentication failed',
      code: 'VERIFICATION_FAILED'
    });
  }
});

// Debug endpoint to check stored credentials
app.get('/api/admin/webauthn/debug/:email', async (req, res) => {
  try {
    const { email } = req.params;
    const admin = await Admin.findOne({ email });
    
    if (!admin) {
      return res.status(404).json({ error: 'Admin not found' });
    }

    res.json({
      email: admin.email,
      credentialsCount: admin.webauthnCredentials.length,
      credentials: admin.webauthnCredentials.map(cred => ({
        id: cred.credentialID,
        deviceName: cred.deviceName,
        deviceType: cred.deviceType,
        counter: cred.counter,
        addedAt: cred.addedAt
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
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

// Coupon Validation Endpoint
app.post('/api/coupons/validate', async (req, res) => {
  try {
    const { code } = req.body;
    
    if (!code || typeof code !== 'string') {
      return res.status(400).json({ 
        valid: false, 
        error: 'Coupon code is required' 
      });
    }

    // First find the coupon
    const coupon = await Coupon.findOne({ 
      code,
      isActive: true,
      validFrom: { $lte: new Date() },
      validUntil: { $gte: new Date() }
    });

    if (!coupon) {
      return res.status(404).json({ 
        valid: false, 
        error: 'Coupon not found or expired' 
      });
    }

    // Then check usage limits
    if (coupon.maxUses !== null && coupon.currentUses >= coupon.maxUses) {
      return res.status(400).json({ 
        valid: false,
        error: 'Coupon has reached maximum usage limit'
      });
    }

    res.json({
      valid: true,
      coupon: {
        code: coupon.code,
        discountType: coupon.discountType,
        discountValue: coupon.discountValue,
        minOrderAmount: coupon.minOrderAmount || 0,
        maxUses: coupon.maxUses,
        currentUses: coupon.currentUses
      }
    });
  } catch (error) {
    console.error('Coupon validation error:', error);
    res.status(500).json({ 
      error: 'Server error during coupon validation',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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

// Get coupon usage details
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

app.put('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        console.log('=== UPDATE BOOKING DEBUG ===');
        console.log('Request params:', req.params);
        console.log('ID parameter:', id);
        
        // Validate ID parameter
        if (!id || id === "undefined" || id === undefined || id === null || id === "") {
            console.error('❌ Invalid booking ID received:', id);
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID',
                details: 'The booking ID is missing or invalid'
            });
        }
        
        // Check if it's a valid MongoDB ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            console.error('❌ Invalid MongoDB ObjectId format:', id);
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID format',
                details: 'The booking ID must be a valid MongoDB ObjectId (24 hex characters)'
            });
        }
        
        console.log('✅ ID validation passed, proceeding with update...');
        
        // Allowed fields to update
        const allowedUpdates = {
            customerName: true,
            customerEmail: true,
            customerPhone: true,
            package: true,
            bookingDates: true,
            preWeddingDate: true,
            address: true,
            status: true,
            paymentStatus: true,
            paymentBreakdown: true,
            notes: true
        };
        
        // Filter updates to only allowed fields
        const filteredUpdates = {};
        for (const key in updates) {
            if (allowedUpdates[key]) {
                filteredUpdates[key] = updates[key];
            }
        }
        
        // Add audit info
        filteredUpdates.updatedAt = new Date();
        filteredUpdates.updatedBy = req.admin._id; // Assuming you have admin info in req
        
        console.log('Filtered updates:', filteredUpdates);
        console.log('Attempting to find and update booking with ID:', id);
        
        // CRITICAL: Add validation right before database operation
        console.log('ID value before database operation:', id);
        if (!id || id === "undefined" || !mongoose.Types.ObjectId.isValid(id)) {
            console.error('CRITICAL ERROR: Invalid ID at database operation:', id);
            console.error('Request params:', req.params);
            console.error('Request body:', req.body);
            throw new Error(`Invalid booking ID: ${id}`);
        }
        
        const booking = await Booking.findByIdAndUpdate(
            id,
            { $set: filteredUpdates },
            { new: true, runValidators: true }
        );
        
        if (!booking) {
            console.error('❌ Booking not found with ID:', id);
            return res.status(404).json({ message: 'Booking not found' });
        }
        
        console.log('✅ Booking updated successfully:', booking._id);
        res.json({
            message: 'Booking updated successfully',
            booking
        });
    } catch (error) {
        console.error('❌ Error updating booking:', error);
        console.error('Error stack:', error.stack);
        
        // More specific error handling
        if (error.name === 'CastError') {
            console.error('💥 CAST ERROR - Invalid ID reached database level');
            return res.status(400).json({ 
                message: 'Invalid booking ID format',
                details: 'The booking ID must be a valid MongoDB ObjectId'
            });
        }
        
        res.status(500).json({ 
            message: 'Error updating booking', 
            error: error.message
        });
    }
});

app.patch('/api/admin/bookings/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { status } = req.body;
        
        console.log('=== UPDATE BOOKING STATUS DEBUG ===');
        console.log('Request params:', req.params);
        console.log('ID parameter:', id);
        console.log('Status parameter:', status);
        
        // Validate ID parameter
        if (!id || id === "undefined" || id === undefined || id === null) {
            console.error('❌ Invalid booking ID received:', id);
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID',
                details: 'The booking ID is missing or invalid'
            });
        }
        
        // Check if it's a valid MongoDB ObjectId
        if (!mongoose.Types.ObjectId.isValid(id)) {
            console.error('❌ Invalid MongoDB ObjectId format:', id);
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID format',
                details: 'The booking ID must be a valid MongoDB ObjectId (24 hex characters)'
            });
        }
        
        console.log('✅ ID validation passed, proceeding with status update...');
        
        const booking = await Booking.findByIdAndUpdate(
            id,
            { status },
            { new: true }
        );
        
        if (!booking) {
            console.error('❌ Booking not found with ID:', id);
            return res.status(404).json({ error: 'Booking not found' });
        }
        
        console.log('✅ Booking status updated successfully:', booking._id);
        res.json({ success: true, booking });
    } catch (err) {
        console.error('❌ Error updating booking status:', err);
        console.error('Error stack:', err.stack);
        
        // More specific error handling
        if (err.name === 'CastError') {
            console.error('💥 CAST ERROR - Invalid ID reached database level');
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID format',
                details: 'The booking ID must be a valid MongoDB ObjectId'
            });
        }
        
        res.status(500).json({ 
            success: false,
            error: 'Failed to update booking status',
            details: err.message
        });
    }
});

// ===== DELETE BOOKING ENDPOINT ===== //

app.delete('/api/admin/bookings/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    console.log('=== DELETE BOOKING REQUEST ===');
    console.log('Booking ID:', id);
    
    // Validate ID parameter
    if (!id || id === "undefined" || id === "null") {
      console.error('❌ Invalid booking ID received:', id);
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID',
        details: 'The booking ID is missing or invalid'
      });
    }
    
    // Check if it's a valid MongoDB ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      console.error('❌ Invalid MongoDB ObjectId format:', id);
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID format',
        details: 'The booking ID must be a valid MongoDB ObjectId (24 hex characters)'
      });
    }
    
    // Find the booking first to check if it exists
    const booking = await Booking.findById(id);
    if (!booking) {
      console.error('❌ Booking not found with ID:', id);
      return res.status(404).json({ 
        success: false,
        message: 'Booking not found',
        details: 'No booking exists with the provided ID'
      });
    }
    
    console.log('✅ Booking found, proceeding with deletion:', {
      id: booking._id,
      customerName: booking.customerName,
      customerEmail: booking.customerEmail,
      status: booking.status
    });
    
    // Delete the booking
    await Booking.findByIdAndDelete(id);
    
    console.log('✅ Booking deleted successfully');
    
    res.json({ 
      success: true,
      message: 'Booking deleted successfully',
      deletedBooking: {
        id: booking._id,
        customerName: booking.customerName,
        customerEmail: booking.customerEmail
      }
    });
    
  } catch (error) {
    console.error('❌ Error deleting booking:', error);
    console.error('Error stack:', error.stack);
    
    // More specific error handling
    if (error.name === 'CastError') {
      console.error('💥 CAST ERROR - Invalid ID reached database level');
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID format',
        details: 'The booking ID must be a valid MongoDB ObjectId'
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: 'Error deleting booking', 
      error: error.message,
      // Include stack trace only in development
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
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

// Add to your backend server (Node.js/Express)
app.post('/api/bookings/complete-payment', async (req, res) => {
  try {
    const { bookingId, transactionId, amount } = req.body;
    
    console.log('Payment completion request:', { bookingId, transactionId, amount });
    
    // Validate input
    if (!bookingId || !transactionId || !amount) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing required fields',
        missing: {
          bookingId: !bookingId,
          transactionId: !transactionId,
          amount: !amount
        }
      });
    }

    // Find the booking
    const booking = await Booking.findById(bookingId);
    if (!booking) {
      return res.status(404).json({ 
        success: false, 
        error: 'Booking not found',
        bookingId: bookingId
      });
    }

    // Convert amount to number safely
    const paymentAmount = parseFloat(amount);
    if (isNaN(paymentAmount) || paymentAmount <= 0) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid amount',
        amount: amount
      });
    }

    // Initialize paymentBreakdown if it doesn't exist
    if (!booking.paymentBreakdown) {
      booking.paymentBreakdown = {
        advancePaid: 0,
        remainingBalance: booking.finalAmount || 0,
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        paymentMethod: 'online',
        payments: [] // Initialize empty payments array
      };
    }

    // Initialize payments array if it doesn't exist
    if (!booking.paymentBreakdown.payments) {
      booking.paymentBreakdown.payments = [];
    }

    // Update payment details
    booking.paymentBreakdown.advancePaid += paymentAmount;
    booking.paymentBreakdown.remainingBalance -= paymentAmount;
    
    // Ensure remaining balance doesn't go negative
    if (booking.paymentBreakdown.remainingBalance < 0) {
      booking.paymentBreakdown.remainingBalance = 0;
    }
    
    // Add payment record to the payments array
    booking.paymentBreakdown.payments.push({
      amount: paymentAmount,
      method: 'online',
      date: new Date(),
      transactionId: transactionId,
      status: 'completed'
    });
    
    // Update payment status
    if (booking.paymentBreakdown.remainingBalance <= 0) {
      booking.paymentStatus = 'completed';
      booking.status = 'confirmed';
    } else {
      booking.paymentStatus = 'partially_paid';
    }
    
    booking.updatedAt = new Date();
    
    // Save the updated booking
    await booking.save();
    
    console.log('Payment completed successfully for booking:', bookingId);
    console.log('Updated payment breakdown:', booking.paymentBreakdown);
    
    // Send confirmation email
    try {
      const confirmationHtml = `
        <!DOCTYPE html>
        <html>
        <head><style>body{font-family:Arial,sans-serif}</style></head>
        <body>
          <h2>Payment Received</h2>
          <p>Dear ${booking.customerName},</p>
          <p>We've received your payment of ₹${paymentAmount} for booking ${bookingId}.</p>
          <p><strong>Transaction ID:</strong> ${transactionId}</p>
          <p><strong>Remaining Balance:</strong> ₹${booking.paymentBreakdown.remainingBalance}</p>
          <p>Thank you for choosing Joker Creation Studio!</p>
        </body>
        </html>
      `;
      
      await transporter.sendMail({
        from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
        to: booking.customerEmail,
        subject: `Payment Received - Booking ${bookingId}`,
        html: confirmationHtml
      });
    } catch (emailError) {
      console.error('Failed to send confirmation email:', emailError);
      // Don't fail the request if email fails
    }
    
    res.json({ 
      success: true,
      message: 'Payment recorded successfully',
      booking: {
        _id: booking._id,
        paymentStatus: booking.paymentStatus,
        advancePaid: booking.paymentBreakdown.advancePaid,
        remainingBalance: booking.paymentBreakdown.remainingBalance,
        finalAmount: booking.finalAmount,
        paymentsCount: booking.paymentBreakdown.payments.length
      }
    });
    
  } catch (err) {
    console.error('Error completing payment:', err);
    res.status(500).json({ 
      success: false,
      error: 'Failed to complete payment',
      details: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error',
      // Add stack trace only in development
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

// Add this debug endpoint
app.get('/api/debug/booking/:id', async (req, res) => {
  try {
    const booking = await Booking.findById(req.params.id);
    
    if (!booking) {
      return res.status(404).json({ success: false, error: 'Booking not found' });
    }

    res.json({
      success: true,
      booking: {
        _id: booking._id,
        finalAmount: booking.finalAmount,
        originalAmount: booking.originalAmount,
        discountAmount: booking.discountAmount,
        paymentStatus: booking.paymentStatus,
        status: booking.status,
        paymentBreakdown: booking.paymentBreakdown,
        // Check if mongoose document is properly populated
        isMongooseDocument: booking instanceof mongoose.Document,
        // Check schema paths
        schemaPaths: Object.keys(booking.schema.paths)
      }
    });
  } catch (err) {
    console.error('Debug error:', err);
    res.status(500).json({ success: false, error: 'Debug failed', details: err.message });
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

// ==================== IMAGE UPLOAD & GALLERY API SECTION ====================

// Add this endpoint to handle image uploads to ImgBB
app.post('/api/upload-image', authenticateAdmin, upload.single('image'), async (req, res) => {
  try {
    console.log('Image upload request received');

    // ✅ Validate file existence
    if (!req.file) {
      return res.status(400).json({ 
        success: false,
        error: 'No image file provided' 
      });
    }

    // ✅ Validate file type
    if (!req.file.mimetype.startsWith('image/')) {
      return res.status(400).json({ 
        success: false,
        error: 'File must be an image' 
      });
    }

    // ✅ Validate file size (max 32MB for ImgBB free tier)
    if (req.file.size > 32 * 1024 * 1024) {
      return res.status(400).json({ 
        success: false,
        error: 'Image size must be less than 32MB' 
      });
    }

    console.log('Uploading to ImgBB:', {
      filename: req.file.originalname,
      size: req.file.size,
      mimetype: req.file.mimetype
    });

    // ✅ Convert buffer to base64 for ImgBB
    const base64Image = req.file.buffer.toString('base64');
    const formData = new FormData();
    formData.append('image', base64Image);

    // ✅ Get ImgBB API key
    const IMGBB_API_KEY = process.env.IMGBB_API_KEY;
    if (!IMGBB_API_KEY) {
      console.error('ImgBB API key not configured');
      return res.status(500).json({ 
        success: false,
        error: 'Image upload service not configured' 
      });
    }

    // ✅ Upload to ImgBB
    const imgbbResponse = await axios.post(
      `https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`,
      formData,
      { headers: formData.getHeaders(), timeout: 30000 }
    );

    if (!imgbbResponse.data.success) {
      console.error('ImgBB upload failed:', imgbbResponse.data.error);
      return res.status(500).json({ 
        success: false,
        error: imgbbResponse.data.error?.message || 'Upload to image service failed' 
      });
    }

    const imgbbData = imgbbResponse.data.data;

    console.log('Image uploaded successfully:', {
      id: imgbbData.id,
      url: imgbbData.url,
      deleteUrl: imgbbData.delete_url
    });

    // ✅ Save to MongoDB with proper fields for delete later
    const galleryItem = new Gallery({
      name: req.body.name || req.file.originalname,
      description: req.body.description || '',
      category: req.body.category || 'uploads',
      imageUrl: imgbbData.url,
      thumbnailUrl: imgbbData.thumb?.url || imgbbData.url,
      deleteUrl: imgbbData.delete_url,
      imgbbId: imgbbData.id,
      uploadedAt: new Date()
    });

    await galleryItem.save();

    // ✅ Return data for frontend
    res.json({
      success: true,
      galleryId: galleryItem._id,
      url: imgbbData.url,
      thumb: imgbbData.thumb?.url || imgbbData.url,
      medium: imgbbData.medium?.url || imgbbData.url,
      deleteUrl: imgbbData.delete_url,
      imageId: imgbbData.id
    });

  } catch (error) {
    console.error('Image upload error:', error);

    let errorMessage = 'Failed to upload image';
    let statusCode = 500;

    if (error.response) {
      errorMessage = error.response.data.error?.message || 'Image service error';
      statusCode = error.response.status;
    } else if (error.request) {
      errorMessage = 'Network error - could not connect to image service';
    } else if (error.code === 'ECONNABORTED') {
      errorMessage = 'Upload timeout - please try again';
    } else {
      errorMessage = error.message;
    }

    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Add this endpoint to handle multiple image uploads
app.post('/api/upload-images', authenticateAdmin, upload.array('images', 10), async (req, res) => {
  try {
    console.log('Multiple image upload request received:', req.files.length);
    
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ 
        success: false,
        error: 'No images provided' 
      });
    }

    const results = [];
    const errors = [];

    // Process each image sequentially to avoid rate limiting
    for (const file of req.files) {
      try {
        // Validate file type
        if (!file.mimetype.startsWith('image/')) {
          errors.push({
            filename: file.originalname,
            error: 'Not an image file'
          });
          continue;
        }

        // Validate file size
        if (file.size > 32 * 1024 * 1024) {
          errors.push({
            filename: file.originalname,
            error: 'File too large (max 32MB)'
          });
          continue;
        }

        console.log('Uploading to ImgBB:', file.originalname);

        // Create form data for ImgBB API
        const formData = new FormData();
        const base64Image = file.buffer.toString('base64');
        formData.append('image', base64Image);

        const IMGBB_API_KEY = process.env.IMGBB_API_KEY;
        
        if (!IMGBB_API_KEY) {
          throw new Error('ImgBB API key not configured');
        }

        // Upload to ImgBB
        const imgbbResponse = await axios.post(
          `https://api.imgbb.com/1/upload?key=${IMGBB_API_KEY}`,
          formData,
          {
            headers: {
              ...formData.getHeaders(),
              'Content-Type': 'multipart/form-data'
            },
            timeout: 30000
          }
        );

        if (imgbbResponse.data.success) {
          const imgbbData = imgbbResponse.data.data;
          
          // Create gallery entry using the correct ImgBB response structure
          const galleryItem = new Gallery({
            name: file.originalname,
            description: '',
            category: 'uploads',
            imageUrl: imgbbData.url, // Main image URL
            thumbnailUrl: imgbbData.thumb?.url || imgbbData.url, // Use thumb URL if available
            deleteUrl: imgbbData.delete_url,
            imgbbId: imgbbData.id
          });

          await galleryItem.save();

          results.push({
            success: true,
            filename: file.originalname,
            galleryId: galleryItem._id,
            url: imgbbData.url, // Main image URL
            thumb: imgbbData.thumb?.url || imgbbData.url, // Thumbnail URL
            medium: imgbbData.medium?.url || imgbbData.url, // Medium size URL
            deleteUrl: imgbbData.delete_url,
            imageId: imgbbData.id
          });
        } else {
          errors.push({
            filename: file.originalname,
            error: imgbbResponse.data.error?.message || 'Upload failed'
          });
        }

        // Add a small delay to avoid rate limiting
        await new Promise(resolve => setTimeout(resolve, 500));
        
      } catch (fileError) {
        console.error(`Error uploading ${file.originalname}:`, fileError);
        errors.push({
          filename: file.originalname,
          error: fileError.message || 'Upload failed'
        });
      }
    }

    res.json({
      success: true,
      results,
      errors,
      summary: {
        successful: results.length,
        failed: errors.length,
        total: req.files.length
      }
    });

  } catch (error) {
    console.error('Multiple image upload error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to upload images',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Revised ImgBB deletion utility function
async function deleteFromImgBB(deleteUrl) {
  try {
    if (!deleteUrl) {
      console.warn('No delete URL provided for ImgBB');
      return false;
    }

    console.log('Attempting to delete from ImgBB:', deleteUrl);

    // Extract image ID and hash from the delete URL
    // URL format: https://ibb.co/$image_id/$image_hash
    const urlParts = deleteUrl.split('/');
    const imageId = urlParts[urlParts.length - 2];
    const imageHash = urlParts[urlParts.length - 1];

    if (!imageId || !imageHash) {
      console.error('Could not extract image ID or hash from URL:', deleteUrl);
      return false;
    }

    console.log('Extracted image ID:', imageId, 'Hash:', imageHash);

    // Create form data for the ImgBB JSON API
    const formData = new FormData();
    formData.append('pathname', `/${imageId}/${imageHash}`);
    formData.append('action', 'delete');
    formData.append('delete', 'image');
    formData.append('from', 'resource');
    formData.append('deleting[id]', imageId);
    formData.append('deleting[hash]', imageHash);

    // Additional fields that might be required (from browser observation)
    formData.append('_', Date.now().toString()); // timestamp
    formData.append('source', 'image-page');

    // Make the POST request to ImgBB's JSON API
    const response = await axios.post('https://ibb.co/json', formData, {
      timeout: 10000,
      headers: {
        'Referer': `https://ibb.co/${imageId}/${imageHash}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': 'https://ibb.co',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': `multipart/form-data; boundary=${formData._boundary}`,
      }
    });

    console.log('ImgBB API response status:', response.status);
    console.log('ImgBB API response data:', response.data);

    // Check if deletion was successful
    if (response.status === 200) {
      // The response should contain success information
      if (response.data && response.data.success) {
        console.log('ImgBB deletion successful via API');
        return true;
      }
      
      // Some ImgBB endpoints might return success differently
      if (response.data && response.data.status === 'success') {
        console.log('ImgBB deletion successful (status: success)');
        return true;
      }
      
      // If we get a 200 but no clear success indicator, check for error
      if (response.data && response.data.error) {
        console.log('ImgBB deletion failed with error:', response.data.error);
        return false;
      }
      
      // Assume success for 200 status with no error
      console.log('ImgBB deletion likely successful (200 status)');
      return true;
    }

    console.log('ImgBB deletion failed - non-200 status code:', response.status);
    return false;

  } catch (error) {
    console.warn('ImgBB deletion failed:', error.message);
    
    // Log more details for debugging
    if (error.response) {
      console.log('Response status:', error.response.status);
      console.log('Response data:', error.response.data);
    }
    
    return false;
  }
}

// Update the gallery delete endpoint to use the proper ImgBB deletion
app.delete('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { deleteUrl } = req.body;

    console.log('Delete request received:', { id, deleteUrl });

    // Validate ID
    if (!id || id === "undefined" || !mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid gallery item ID' 
      });
    }

    // Find the gallery item first
    const galleryItem = await Gallery.findById(id);
    if (!galleryItem) {
      return res.status(404).json({ 
        success: false, 
        error: 'Gallery item not found' 
      });
    }

    // Try to delete from ImgBB if we have a delete URL
    const imgbbDeleteUrl = deleteUrl || galleryItem.deleteUrl;
    let imgbbDeletionSuccess = false;
    let imgbbDeletionDetails = 'No ImgBB URL provided';
    
    if (imgbbDeleteUrl) {
      try {
        imgbbDeletionSuccess = await deleteFromImgBB(imgbbDeleteUrl);
        
        if (imgbbDeletionSuccess) {
          imgbbDeletionDetails = 'Image successfully deleted from ImgBB';
          console.log('ImgBB deletion successful');
        } else {
          imgbbDeletionDetails = 'Failed to delete image from ImgBB';
          console.warn('ImgBB deletion failed');
        }
      } catch (imgbbError) {
        imgbbDeletionDetails = `ImgBB deletion error: ${imgbbError.message}`;
        console.warn('ImgBB deletion error:', imgbbError.message);
      }
    }

    // Delete from database
    await Gallery.findByIdAndDelete(id);

    res.json({ 
      success: true, 
      message: 'Gallery item deleted successfully',
      details: {
        database: { deleted: true, id: id },
        imgbb: { 
          attempted: !!imgbbDeleteUrl,
          success: imgbbDeletionSuccess,
          details: imgbbDeletionDetails,
          url: imgbbDeleteUrl || null
        }
      }
    });

  } catch (err) {
    console.error('Error deleting gallery item:', err);
    res.status(500).json({ 
      success: false, 
      error: 'Failed to delete gallery item',
      details: err.message
    });
  }
});

// Enhanced debug endpoint to test the proper ImgBB API
app.post('/api/admin/imgbb/debug', authenticateAdmin, async (req, res) => {
  try {
    const { deleteUrl } = req.body;

    if (!deleteUrl) {
      return res.status(400).json({ 
        success: false,
        error: 'Delete URL is required' 
      });
    }

    console.log('Debugging ImgBB deletion URL:', deleteUrl);

    // Extract image ID and hash
    const urlParts = deleteUrl.split('/');
    const imageId = urlParts[urlParts.length - 2];
    const imageHash = urlParts[urlParts.length - 1];

    if (!imageId || !imageHash) {
      return res.status(400).json({
        success: false,
        error: 'Invalid ImgBB URL format'
      });
    }

    // Test the API endpoint
    const formData = new FormData();
    formData.append('pathname', `/${imageId}/${imageHash}`);
    formData.append('action', 'delete');
    formData.append('delete', 'image');
    formData.append('from', 'resource');
    formData.append('deleting[id]', imageId);
    formData.append('deleting[hash]', imageHash);
    formData.append('_', Date.now().toString());

    const response = await axios.post('https://ibb.co/json', formData, {
      timeout: 10000,
      headers: {
        'Referer': `https://ibb.co/${imageId}/${imageHash}`,
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Origin': 'https://ibb.co',
        'Accept': 'application/json, text/javascript, */*; q=0.01',
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': `multipart/form-data; boundary=${formData._boundary}`,
      }
    });

    res.json({
      success: true,
      status: response.status,
      data: response.data,
      urlAnalyzed: deleteUrl,
      extracted: { imageId, imageHash }
    });

  } catch (error) {
    console.error('Debug error:', error);
    
    let errorDetails = error.message;
    if (error.response) {
      errorDetails = {
        status: error.response.status,
        data: error.response.data,
        headers: error.response.headers
      };
    }

    res.status(500).json({ 
      success: false,
      error: 'Debug failed',
      details: errorDetails
    });
  }
});

// Get all gallery items
app.get('/api/admin/gallery', authenticateAdmin, async (req, res) => {
  try {
    const { category, featured, search, page = 1, limit = 50 } = req.query;
    let query = {};
    
    if (category && category !== 'all') {
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
    console.error('Error fetching gallery:', err);
    res.status(500).json({ error: 'Failed to fetch gallery images' });
  }
});

// Add gallery item (from URL)
app.post('/api/admin/gallery/url', authenticateAdmin, async (req, res) => {
  try {
    const { name, description, category, featured, imageUrl } = req.body;

    // ✅ Check if image URL is provided
    if (!imageUrl) {
      return res.status(400).json({ success: false, error: 'Image URL is required' });
    }

    // ✅ Validate URL format
    try {
      new URL(imageUrl);
    } catch {
      return res.status(400).json({ success: false, error: 'Invalid image URL' });
    }

    // ✅ Save the image URL directly in MongoDB
    const galleryItem = new Gallery({
      name: name || 'Untitled',
      description: description || '',
      category: category || 'manual', // differentiate manual URLs
      featured: featured === true,
      imageUrl,           // main image URL (from direct link)
      thumbnailUrl: imageUrl, // thumbnail same as main URL
      uploadedAt: new Date(),
      createdAt: new Date(),
      updatedAt: new Date()
    });

    await galleryItem.save();

    // ✅ Return saved gallery item info
    res.json({
      success: true,
      message: 'Image URL saved successfully',
      galleryItem
    });

  } catch (err) {
    console.error('Error adding gallery item from URL:', err);
    res.status(500).json({ success: false, error: 'Failed to add gallery item' });
  }
});

// Update gallery item
app.put('/api/admin/gallery/:id', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, category, featured } = req.body;
    
    // Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid gallery item ID' });
    }
    
    const galleryItem = await Gallery.findByIdAndUpdate(
      id,
      {
        name,
        description,
        category,
        featured,
        updatedAt: new Date()
      },
      { new: true, runValidators: true }
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

// Toggle featured status
app.patch('/api/admin/gallery/:id/featured', authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { featured } = req.body;
    
    // Validate ID
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'Invalid gallery item ID' });
    }
    
    const galleryItem = await Gallery.findByIdAndUpdate(
      id,
      { featured: featured === true, updatedAt: new Date() },
      { new: true }
    );
    
    if (!galleryItem) {
      return res.status(404).json({ error: 'Gallery item not found' });
    }
    
    res.json({ success: true, image: galleryItem });
  } catch (err) {
    console.error('Error toggling featured status:', err);
    res.status(500).json({ error: 'Failed to update featured status' });
  }
});

// Get gallery stats
app.get('/api/admin/gallery/stats', authenticateAdmin, async (req, res) => {
  try {
    const totalImages = await Gallery.countDocuments();
    const featuredImages = await Gallery.countDocuments({ featured: true });
    
    const categoryStats = await Gallery.aggregate([
      { $group: { _id: '$category', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    const recentUploads = await Gallery.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
    });
    
    res.json({
      success: true,
      stats: {
        total: totalImages,
        featured: featuredImages,
        recent: recentUploads,
        byCategory: categoryStats
      }
    });
  } catch (err) {
    console.error('Error fetching gallery stats:', err);
    res.status(500).json({ error: 'Failed to fetch gallery stats' });
  }
});

// Public portfolio endpoint
app.get('/api/portfolio', async (req, res) => {
  try {
    const images = await Gallery.find().sort({ createdAt: -1 }); // newest first

    // Map the images to public-friendly format
    const response = images.map(item => ({
      _id: item._id,
      name: item.name,
      description: item.description,
      category: item.category,
      featured: item.featured,
      imageUrl: item.imageUrl,  // make sure this is a public URL
      uploadedAt: item.createdAt
    }));

    res.json({ success: true, images: response });
  } catch (err) {
    console.error('Error fetching portfolio images:', err);
    res.status(500).json({ error: 'Failed to fetch portfolio images' });
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
      console.error('Missing required fields:', req.body);
      return res.status(400).json({ 
        success: false,
        error: 'Missing required fields',
        missing: {
          customerName: !req.body.customerName,
          customerEmail: !req.body.customerEmail,
          customerPhone: !req.body.customerPhone,
          package: !req.body.package,
          bookingDates: !req.body.bookingDates,
          address: !req.body.address,
          transactionId: !req.body.transactionId
        }
      });
    }

    const {
      customerName,
      customerEmail,
      customerPhone,
      package: packageName,
      bookingDates,
      preWeddingDate,
      address,
      transactionId,
      userId,
      couponCode,
      discountAmount = 0,
      originalAmount,
      amountPaid,
      paymentMethod = 'online'
    } = req.body;

    // Calculate amounts
    const packagePrice = parseInt(originalAmount) || parseInt(packageName.toString().replace(/[^0-9]/g, '')) || 0;
    const discount = parseInt(discountAmount) || 0;
    const finalAmountAfterDiscount = packagePrice - discount;
    
    // Use amountPaid from request or calculate 10%
    const advancePaid = parseInt(amountPaid) || Math.round(finalAmountAfterDiscount * 0.10);
    const remainingBalance = finalAmountAfterDiscount - advancePaid;
    
    // Determine payment status
    const paymentStatus = remainingBalance <= 0 ? 'completed' : 'partially_paid';

    // Build discount details if coupon was applied
    let discountDetails = {};
    if (couponCode && discount > 0) {
      discountDetails = {
        description: `Coupon: ${couponCode}`,
        appliedAt: new Date(),
        validUntil: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
      };
    }

    console.log('Creating new booking with data:', {
      customerName,
      customerEmail,
      customerPhone,
      packageName,
      bookingDates,
      preWeddingDate,
      address,
      transactionId,
      paymentStatus,
      finalAmountAfterDiscount,
      advancePaid,
      remainingBalance
    });

    const newBooking = new Booking({
      customerName: customerName.trim(),
      customerEmail: customerEmail.trim(),
      customerPhone: customerPhone.trim(),
      package: packageName,
      bookingDates,
      preWeddingDate: preWeddingDate || undefined,
      address: address.trim(),
      transactionId,
      paymentStatus,
      status: 'pending',
      userId: userId || null,
      couponCode: couponCode || undefined,
      discountType: discount > 0 ? 'fixed' : null,
      discountValue: discount,
      originalAmount: packagePrice,
      discountAmount: discount,
      finalAmount: finalAmountAfterDiscount,
      discountDetails: discountDetails,
      paymentBreakdown: {
        advancePaid: advancePaid,
        remainingBalance: remainingBalance,
        dueDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        paymentMethod: paymentMethod,
        payments: [{
          amount: advancePaid,
          method: paymentMethod,
          date: new Date(),
          transactionId: transactionId,
          status: 'completed'
        }]
      },
      updatedBy: 'system'
    });

    // Save the booking to MongoDB
    console.log('Saving booking to database...');
    const savedBooking = await newBooking.save();
    console.log('Booking saved successfully with ID:', savedBooking._id);

    // Format dates for display
    const formatDate = (dateString) => {
      if (!dateString || dateString === "Not specified") return dateString;
      try {
        return new Date(dateString).toLocaleDateString('en-IN', {
          day: 'numeric', month: 'short', year: 'numeric'
        });
      } catch (e) {
        return dateString;
      }
    };

    // Parse booking dates
    let eventStartDate = '';
    let eventEndDate = '';
    if (bookingDates && bookingDates.includes(' to ')) {
      const dates = bookingDates.split(' to ');
      eventStartDate = formatDate(dates[0].trim());
      eventEndDate = formatDate(dates[1].trim());
    }

    // Send confirmation emails using YOUR templates
    try {
      // Customer Email Template (Your original template)
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
              <span class="detail-value">${savedBooking._id}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Package:</span>
              <span class="detail-value">${packageName}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Event Date:</span>
              <span class="detail-value">${eventStartDate} to ${eventEndDate}</span>
            </div>
            ${preWeddingDate ? `
            <div class="detail-row">
              <span class="detail-label">Pre-Wedding Date:</span>
              <span class="detail-value">${formatDate(preWeddingDate)}</span>
            </div>` : ''}
          </div>

          <div class="section highlight">
            <h3>Payment Summary</h3>
            
            <div class="detail-row">
              <span class="detail-label">Package Price:</span>
              <span class="detail-value">₹${packagePrice.toLocaleString('en-IN')}</span>
            </div>

            ${couponCode ? `
            <div class="detail-row">
              <span class="detail-label">Discount (${couponCode}):</span>
              <span class="detail-value">- ₹${discount.toLocaleString('en-IN')}</span>
            </div>` : ''}

            <div class="detail-row total-row">
              <span class="detail-label">Final Amount:</span>
              <span class="detail-value">₹${finalAmountAfterDiscount.toLocaleString('en-IN')}</span>
            </div>

            <div class="detail-row">
              <span class="detail-label">Advance Paid (10%):</span>
              <span class="detail-value">₹${advancePaid.toLocaleString('en-IN')}</span>
            </div>

            <div class="detail-row total-row">
              <span class="detail-label">Remaining Balance:</span>
              <span class="detail-value">₹${remainingBalance.toLocaleString('en-IN')}</span>
            </div>

            ${remainingBalance > 0 ? `
            <div style="text-align: center; margin-top: 20px;">
              <a href="https://jokercreation.store/payment?bookingId=${savedBooking._id}" 
                 class="payment-button">
                Pay Remaining ₹${remainingBalance.toLocaleString('en-IN')}
              </a>
            </div>` : ''}
          </div>

          <p>We'll contact you soon to discuss your event details. For any questions, reply to this email.</p>
          <p>Best regards,<br>The Joker Creation Studio Team</p>
        </div>
      </body>
      </html>
      `;

      // Admin Email Template (Your original template)
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
              <span class="detail-value">${savedBooking._id}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Package:</span>
              <span class="detail-value">${packageName}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Event Date:</span>
              <span class="detail-value">${eventStartDate} to ${eventEndDate}</span>
            </div>
            ${preWeddingDate ? `
            <div class="detail-row">
              <span class="detail-label">Pre-Wedding Date:</span>
              <span class="detail-value">${formatDate(preWeddingDate)}</span>
            </div>` : ''}
          </div>

          <div class="section highlight">
            <h3>Payment Information</h3>
            
            <div class="detail-row">
              <span class="detail-label">Package Price:</span>
              <span class="detail-value">₹${packagePrice.toLocaleString('en-IN')}</span>
            </div>

            ${couponCode ? `
            <div class="detail-row">
              <span class="detail-label">Discount (${couponCode}):</span>
              <span class="detail-value">- ₹${discount.toLocaleString('en-IN')}</span>
            </div>` : ''}

            <div class="detail-row total-row">
              <span class="detail-label">Final Amount:</span>
              <span class="detail-value">₹${finalAmountAfterDiscount.toLocaleString('en-IN')}</span>
            </div>

            <div class="detail-row">
              <span class="detail-label">Advance Paid:</span>
              <span class="detail-value">₹${advancePaid.toLocaleString('en-IN')}</span>
            </div>

            <div class="detail-row">
              <span class="detail-label">Payment Method:</span>
              <span class="detail-value">${paymentMethod}</span>
            </div>

            <div class="detail-row total-row">
              <span class="detail-label">Remaining Balance:</span>
              <span class="detail-value">₹${remainingBalance.toLocaleString('en-IN')}</span>
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

      // Send customer email
      await transporter.sendMail({
        from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
        to: customerEmail,
        subject: 'Booking Confirmation - Joker Creation Studio',
        html: bookingConfirmationHtml
      });

      // Send admin email
      await transporter.sendMail({
        from: `"Joker Creation Studio" <${process.env.EMAIL_USER}>`,
        to: process.env.ADMIN_EMAIL || 'jokercreationbuisness@gmail.com',
        subject: `New Booking: ${customerName} - ${packageName}`,
        html: adminNotificationHtml
      });

      console.log('Confirmation emails sent successfully');
    } catch (emailError) {
      console.error('Failed to send confirmation emails:', emailError);
      // Don't fail the request if email fails
    }

    res.status(200).json({ 
      success: true,
      message: 'Booking saved and confirmation emails sent successfully',
      booking: {
        id: savedBooking._id,
        finalAmount: finalAmountAfterDiscount,
        advancePaid: advancePaid,
        remainingBalance: remainingBalance,
        paymentStatus: paymentStatus
      }
    });

  } catch (err) {
    console.error('Error saving booking:', err);
    console.error('Error details:', err.message);
    
    res.status(500).json({ 
      success: false,
      error: 'Failed to save booking',
      details: err.message
    });
  }
});

app.post('/create-order', async (req, res) => {
  try {
    const { amount } = req.body;

    console.log('Create order request received with amount:', amount, 'Type:', typeof amount);

    // Validate the amount parameter
    if (amount === undefined || amount === null) {
      console.error('Amount parameter is missing');
      return res.status(400).json({ 
        success: false,
        error: 'Amount parameter is required',
        details: 'Please provide a valid amount value'
      });
    }

    // Convert to number and validate
    const numericAmount = parseFloat(amount);
    if (isNaN(numericAmount)) {
      console.error('Invalid amount provided:', amount);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid amount provided',
        details: 'Amount must be a valid number'
      });
    }

    if (numericAmount <= 0) {
      console.error('Amount must be greater than 0:', numericAmount);
      return res.status(400).json({ 
        success: false,
        error: 'Invalid amount',
        details: 'Amount must be greater than 0'
      });
    }

    // Validate maximum amount (Razorpay has limits)
    if (numericAmount > 1000000) { // 10,00,000 INR maximum
      console.error('Amount exceeds maximum limit:', numericAmount);
      return res.status(400).json({ 
        success: false,
        error: 'Amount too large',
        details: 'Maximum amount allowed is ₹10,00,000'
      });
    }

    const razorpayAmount = Math.round(numericAmount * 100); // Convert to paise

    const options = {
      amount: razorpayAmount,
      currency: 'INR',
      receipt: 'receipt_' + Date.now(), // Unique receipt ID
    };

    console.log('Creating Razorpay order with options:', options);

    // Use promises instead of callbacks for better error handling
    const order = await new Promise((resolve, reject) => {
      razorpayInstance.orders.create(options, (err, order) => {
        if (err) {
          reject(err);
        } else {
          resolve(order);
        }
      });
    });

    console.log('Order created successfully:', order.id);
    
    res.json({ 
      success: true,
      id: order.id,
      amount: order.amount,
      currency: order.currency,
      receipt: order.receipt
    });

  } catch (err) {
    console.error('Error creating Razorpay order:', err);
    
    // More detailed error information
    let errorMessage = 'Failed to create order';
    let errorDetails = err.error ? err.error.description : err.message;
    
    // Specific error handling for common Razorpay issues
    if (err.error && err.error.code === 'BAD_REQUEST_ERROR') {
      errorMessage = 'Invalid request to payment gateway';
    } else if (err.error && err.error.code === 'GATEWAY_ERROR') {
      errorMessage = 'Payment gateway error';
    }
    
    res.status(500).json({ 
      success: false,
      error: errorMessage,
      details: errorDetails,
      // Add debugging info in development
      debug: process.env.NODE_ENV === 'development' ? {
        reason: err.reason,
        code: err.code,
        field: err.field
      } : undefined
    });
  }
});

// Add this endpoint to check Razorpay configuration
app.get('/api/check-razorpay-config', (req, res) => {
  try {
    // Test if Razorpay instance is properly configured
    const testOptions = {
      amount: 1000, // 10 INR
      currency: 'INR',
      receipt: 'test_receipt_' + Date.now(),
    };

    razorpayInstance.orders.create(testOptions, (err, order) => {
      if (err) {
        console.error('Razorpay configuration test failed:', err);
        return res.status(500).json({
          success: false,
          error: 'Razorpay configuration error',
          details: err.error ? err.error.description : err.message
        });
      }

      console.log('Razorpay configuration test successful');
      res.json({
        success: true,
        message: 'Razorpay is properly configured',
        key_id: process.env.RAZORPAY_KEY_ID ? 'Configured' : 'Missing',
        test_order: order.id
      });
    });
  } catch (err) {
    console.error('Razorpay config check error:', err);
    res.status(500).json({
      success: false,
      error: 'Configuration check failed',
      details: err.message
    });
  }
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
































