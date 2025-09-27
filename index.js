require('dotenv').config();

// ===== STARTUP ENVIRONMENT CHECK =====
console.log('Environment check:', {
  rpID: process.env.RP_ID,
  origin: process.env.ORIGIN || `https://${process.env.RP_ID}`,
  nodeEnv: process.env.NODE_ENV,
  adminEmails: process.env.ADMIN_EMAILS ? process.env.ADMIN_EMAILS.split(',') : []
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
// Enhanced session configuration for mobile support
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-webauthn-session-secret-key',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  name: 'webauthn.sid',
  proxy: true,
  
  cookie: {
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },

  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI,
    collectionName: 'webauthn_sessions',
    ttl: 24 * 60 * 60,
    autoRemove: 'native'
  }),

  // Mobile-specific session handling
  genid: (req) => {
    // Check if it's a mobile request
    const isMobile = req.headers['user-agent']?.includes('Android') || 
                    req.headers['x-mobile-app'] === 'true';
    
    if (isMobile) {
      // Generate session ID with mobile prefix for tracking
      return 'mobile_' + require('crypto').randomBytes(16).toString('hex');
    }
    
    return require('crypto').randomBytes(16).toString('hex');
  }
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
  mediumUrl: String,
  deleteUrl: String, // Freeimage.host deletion URL
  imgbbId: String,
  imageSize: Number,
  imageWidth: Number,
  imageHeight: Number,
  freeimageHostData: { // Store Freeimage.host specific data
    imageId: String,
    filename: String,
    url_viewer: String,
    original_filename: String,
    delete_token: String // If provided in response
  },
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
const Gallery = mongoose.model('Gallery', gallerySchema);
const Settings = mongoose.model('Settings', settingsSchema);
const GmailSync = mongoose.model('GmailSync', gmailSyncSchema);
const Coupon = mongoose.model('Coupon', couponSchema);
const CouponBanner = mongoose.model('CouponBanner', bannerSchema);
const EmailTemplate = mongoose.model('EmailTemplate', emailTemplateSchema);

// ==================== ENHANCED RBAC SCHEMAS ====================

// Admin Schema with enhanced RBAC
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { 
    type: String, 
    required: true, 
    enum: ['super_admin', 'admin', 'booking_manager', 'viewer'],
    default: 'viewer' 
  },
  name: { type: String, required: true },
  isActive: { type: Boolean, default: true },
  lastLogin: Date,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  permissions: [{
    resource: String,
    actions: [String],
    grantedAt: { type: Date, default: Date.now },
    grantedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
  }],
  webauthnCredentials: [{
    credentialID: { type: String, required: true },
    credentialPublicKey: { type: String, required: true },
    counter: { type: Number, default: 0 },
    deviceType: { type: String, default: 'unknown' },
    deviceName: { type: String, default: 'Unnamed Device' },
    addedAt: { type: Date, default: Date.now }
  }]
}, {
  timestamps: true
});

// Audit Log Schema
const auditLogSchema = new mongoose.Schema({
  action: { type: String, required: true },
  resource: { type: String, required: true },
  resourceId: String,
  description: String,
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
  adminEmail: String,
  adminRole: String,
  ipAddress: String,
  userAgent: String,
  oldData: mongoose.Schema.Types.Mixed,
  newData: mongoose.Schema.Types.Mixed,
  timestamp: { type: Date, default: Date.now }
});

// System Analytics Schema
const analyticsSchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  logins: { type: Number, default: 0 },
  failedLogins: { type: Number, default: 0 },
  bookingsCreated: { type: Number, default: 0 },
  bookingsModified: { type: Number, default: 0 },
  imagesUploaded: { type: Number, default: 0 },
  messagesSent: { type: Number, default: 0 },
  adminActivities: { type: Number, default: 0 },
  uniqueVisitors: { type: Number, default: 0 }
});

const Admin = mongoose.model('Admin', adminSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);
const Analytics = mongoose.model('Analytics', analyticsSchema);

// ==================== RBAC PERMISSIONS CONFIGURATION ====================

const rolePermissions = {
  super_admin: {
    permissions: {
      bookings: ['create', 'read', 'update', 'delete', 'manage'],
      users: ['create', 'read', 'update', 'delete', 'manage'],
      gallery: ['create', 'read', 'update', 'delete', 'manage'],
      messages: ['create', 'read', 'update', 'delete', 'manage'],
      settings: ['create', 'read', 'update', 'delete', 'manage'],
      coupons: ['create', 'read', 'update', 'delete', 'manage'],
      analytics: ['create', 'read', 'update', 'delete', 'manage'],
      system: ['create', 'read', 'update', 'delete', 'manage'],
      admin_management: ['create', 'read', 'update', 'delete', 'manage'],
      audit_logs: ['read', 'manage']
    },
    description: 'Full system access with unlimited privileges'
  },
  admin: {
    permissions: {
      bookings: ['create', 'read', 'update', 'delete', 'manage'],
      users: ['read', 'update'],
      gallery: ['create', 'read', 'update', 'delete'],
      messages: ['create', 'read', 'update', 'delete'],
      settings: ['read', 'update'],
      coupons: ['create', 'read', 'update', 'delete'],
      analytics: ['read']
    },
    description: 'Administrative access with most privileges'
  },
  booking_manager: {
    permissions: {
      bookings: ['create', 'read', 'update', 'manage'],
      users: ['read'],
      messages: ['read', 'update'],
      coupons: ['read']
    },
    description: 'Booking management privileges'
  },
  viewer: {
    permissions: {
      bookings: ['read'],
      gallery: ['read'],
      analytics: ['read']
    },
    description: 'Read-only access for viewing data'
  }
};

// ==================== MIDDLEWARE ====================

// Rate Limiting
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
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

const webauthnRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
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

// Enhanced Admin Authentication with RBAC
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'Authorization header missing or invalid',
        code: 'INVALID_AUTH_HEADER'
      });
    }

    const token = authHeader.split(' ')[1];
    
    if (!token || token === 'undefined' || token === 'null') {
      return res.status(401).json({ 
        error: 'Token missing or invalid',
        code: 'TOKEN_MISSING'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    if (!decoded.email || !decoded.role) {
      return res.status(401).json({ 
        error: 'Token payload incomplete',
        code: 'INVALID_TOKEN_PAYLOAD'
      });
    }

    const admin = await Admin.findOne({ email: decoded.email });
    if (!admin) {
      return res.status(401).json({ 
        error: 'Admin account not found',
        code: 'ADMIN_NOT_FOUND'
      });
    }

    if (!admin.isActive) {
      return res.status(403).json({ 
        error: 'Admin account is deactivated',
        code: 'ACCOUNT_DEACTIVATED'
      });
    }

    req.admin = admin;
    next();
    
  } catch (err) {
    console.error('Admin authentication error:', err);
    
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Token expired', code: 'TOKEN_EXPIRED' });
    }
    if (err.name === 'JsonWebTokenError') {
      return res.status(401).json({ error: 'Invalid token', code: 'INVALID_TOKEN' });
    }
    
    res.status(500).json({ 
      error: 'Authentication failed', 
      code: 'AUTH_FAILED' 
    });
  }
};

// RBAC Permission Check Middleware
const checkPermission = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.admin) {
        return res.status(401).json({ 
          error: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const adminRole = req.admin.role;
      
      // Super admin has all permissions
      if (adminRole === 'super_admin') {
        return next();
      }

      // Check if role exists in permissions configuration
      if (!rolePermissions[adminRole]) {
        return res.status(403).json({ 
          error: 'Role configuration not found',
          code: 'ROLE_NOT_FOUND'
        });
      }

      // Check if resource exists in role permissions
      const resourcePermissions = rolePermissions[adminRole].permissions[resource];
      
      if (!resourcePermissions || !resourcePermissions.includes(action)) {
        return res.status(403).json({ 
          error: `Insufficient permissions. Required: ${action} on ${resource}`,
          code: 'INSUFFICIENT_PERMISSIONS',
          required: `${action}:${resource}`,
          currentRole: adminRole
        });
      }

      next();
    } catch (err) {
      console.error('Permission check error:', err);
      res.status(500).json({ 
        error: 'Permission verification failed',
        code: 'PERMISSION_CHECK_FAILED'
      });
    }
  };
};

// Audit Logging Middleware
const auditLog = (action, resource, getResourceId = null) => {
  return async (req, res, next) => {
    const originalSend = res.send;
    const startTime = Date.now();
    
    res.send = function(data) {
      const duration = Date.now() - startTime;
      
      // Log the action asynchronously (don't block response)
      if (req.admin) {
        const resourceId = getResourceId ? getResourceId(req, JSON.parse(data)) : req.params.id;
        
        const auditRecord = new AuditLog({
          action,
          resource,
          resourceId,
          description: `${action} operation on ${resource}`,
          adminId: req.admin._id,
          adminEmail: req.admin.email,
          adminRole: req.admin.role,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          oldData: req.oldData,
          newData: req.body,
          timestamp: new Date()
        });
        
        auditRecord.save().catch(err => 
          console.error('Audit log save error:', err)
        );

        // Update analytics
        updateAnalytics(action, resource, req.admin._id).catch(err =>
          console.error('Analytics update error:', err)
        );
      }
      
      originalSend.call(this, data);
    };
    
    next();
  };
};

// Analytics update function
async function updateAnalytics(action, resource, adminId) {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    await Analytics.findOneAndUpdate(
      { date: today },
      { 
        $inc: { 
          adminActivities: 1,
          ...(action === 'login' && { logins: 1 }),
          ...(action === 'login_failed' && { failedLogins: 1 }),
          ...(resource === 'bookings' && action === 'create' && { bookingsCreated: 1 }),
          ...(resource === 'bookings' && action === 'update' && { bookingsModified: 1 }),
          ...(resource === 'gallery' && action === 'create' && { imagesUploaded: 1 }),
          ...(resource === 'messages' && action === 'create' && { messagesSent: 1 })
        }
      },
      { upsert: true, new: true }
    );
  } catch (err) {
    console.error('Analytics update error:', err);
  }
}

// ==================== ADMIN INITIALIZATION ====================

async function initializeAdmins() {
  try {
    console.log('Starting admin initialization...');
    
    // Get admin emails from environment variable
    const adminEmails = process.env.ADMIN_EMAILS ? 
      process.env.ADMIN_EMAILS.split(',').map(email => email.trim()) : [];
    
    // Default super admin
    const superAdminEmail = 'jokercreationbuisness@gmail.com';
    if (!adminEmails.includes(superAdminEmail)) {
      adminEmails.push(superAdminEmail);
    }
    
    console.log('Admin emails to initialize:', adminEmails);
    
    // Initialize settings
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
    }

    // Initialize admins
    for (const email of adminEmails) {
      let admin = await Admin.findOne({ email });
      
      if (!admin) {
        console.log(`Creating new admin account for: ${email}`);
        
        // Determine role based on email
        let role = 'viewer';
        let name = 'Admin User';
        
        if (email === superAdminEmail) {
          role = 'super_admin';
          name = 'Super Administrator';
        } else if (email.includes('manager')) {
          role = 'booking_manager';
          name = 'Booking Manager';
        } else if (email.includes('admin')) {
          role = 'admin';
          name = 'Administrator';
        }
        
        const adminPassword = '9002405641'; // Default password
        const hashedPassword = await bcrypt.hash(adminPassword, 10);
        
        admin = new Admin({
          email,
          password: hashedPassword,
          role,
          name,
          isActive: true
        });
        
        await admin.save();
        console.log(`✅ ${role} account created for: ${email}`);
      } else {
        // Ensure super admin retains super_admin role
        if (email === superAdminEmail && admin.role !== 'super_admin') {
          admin.role = 'super_admin';
          await admin.save();
          console.log(`✅ Upgraded ${email} to super_admin role`);
        }
        console.log(`✅ Admin account already exists: ${email} (${admin.role})`);
      }
    }

    console.log('Admin initialization completed successfully');
    return { settings };
    
  } catch (err) {
    console.error('FATAL ERROR during admin initialization:', err);
    throw new Error('Failed to initialize admin system');
  }
}

// Freeimage.host deletion utility function
async function deleteFromFreeimageHost(deleteUrl, imageId) {
  try {
    if (!deleteUrl) {
      console.warn('No delete URL provided for Freeimage.host');
      return false;
    }

    console.log('Attempting to delete from Freeimage.host:', {
      deleteUrl: deleteUrl,
      imageId: imageId
    });

    // Freeimage.host deletion typically requires visiting the delete URL
    // or making a POST request to it. The exact method depends on their implementation.
    
    // Method 1: Direct URL visit (if that's how it works)
    try {
      const response = await axios.get(deleteUrl, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
      });

      console.log('Freeimage.host deletion response status:', response.status);
      
      // Check if deletion was successful based on response
      if (response.status === 200) {
        // Look for success indicators in the response
        if (response.data.includes('deleted') || response.data.includes('success')) {
          console.log('Freeimage.host deletion successful via URL visit');
          return true;
        }
      }
    } catch (urlError) {
      console.log('URL visit method failed, trying POST method...');
    }

    // Method 2: POST request to delete URL (if that's how it works)
    try {
      const formData = new FormData();
      formData.append('delete', 'true');
      
      const response = await axios.post(deleteUrl, formData, {
        timeout: 10000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'application/json, text/html, application/xhtml+xml',
          ...formData.getHeaders()
        }
      });

      console.log('Freeimage.host POST deletion response:', response.status);
      
      if (response.status === 200) {
        console.log('Freeimage.host deletion successful via POST');
        return true;
      }
    } catch (postError) {
      console.log('POST method also failed:', postError.message);
    }

    // Method 3: If they provide a specific API endpoint for deletion
    // This would require the actual deletion endpoint format
    try {
      const FREEIMAGE_HOST_API_KEY = process.env.FREEIMAGE_HOST_API_KEY;
      if (imageId && FREEIMAGE_HOST_API_KEY) {
        const response = await axios.post(
          'https://freeimage.host/api/1/delete',
          {
            key: FREEIMAGE_HOST_API_KEY,
            action: 'delete',
            image: imageId
          },
          {
            timeout: 10000,
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded'
            }
          }
        );

        if (response.data && response.data.success) {
          console.log('Freeimage.host deletion successful via API');
          return true;
        }
      }
    } catch (apiError) {
      console.log('API deletion method failed:', apiError.message);
    }

    console.warn('All deletion methods failed for Freeimage.host');
    return false;

  } catch (error) {
    console.error('Freeimage.host deletion error:', error.message);
    
    if (error.response) {
      console.log('Response status:', error.response.status);
      console.log('Response data:', error.response.data);
    }
    
    return false;
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

// ==================== NEW RBAC ROUTES ====================

// Get current admin's role and permissions
app.get('/api/admin/my-role', authenticateAdmin, async (req, res) => {
  try {
    const admin = req.admin;
    const permissions = rolePermissions[admin.role] || rolePermissions.viewer;
    
    res.json({
      success: true,
      admin: {
        email: admin.email,
        name: admin.name,
        role: admin.role,
        isActive: admin.isActive,
        lastLogin: admin.lastLogin
      },
      permissions: permissions.permissions,
      description: permissions.description
    });
  } catch (err) {
    console.error('Error fetching admin role:', err);
    res.status(500).json({ error: 'Failed to fetch admin role' });
  }
});

// Get all admins (super_admin only)
app.get('/api/admin/management/admins', 
  authenticateAdmin,
  checkPermission('admin_management', 'read'),
  auditLog('read', 'admin_management'),
  async (req, res) => {
    try {
      const admins = await Admin.find()
        .select('-password -webauthnCredentials')
        .sort({ createdAt: -1 });
      
      res.json({ 
        success: true, 
        admins: admins.map(admin => ({
          _id: admin._id,
          email: admin.email,
          name: admin.name,
          role: admin.role,
          isActive: admin.isActive,
          lastLogin: admin.lastLogin,
          createdAt: admin.createdAt,
          loginAttempts: admin.loginAttempts
        }))
      });
    } catch (err) {
      console.error('Error fetching admins:', err);
      res.status(500).json({ error: 'Failed to fetch admins' });
    }
  }
);

// Create new admin (super_admin only)
app.post('/api/admin/management/admins',
  authenticateAdmin,
  checkPermission('admin_management', 'create'),
  auditLog('create', 'admin_management', (req, data) => data.admin._id),
  async (req, res) => {
    try {
      const { email, password, name, role } = req.body;

      if (!email || !password || !name || !role) {
        return res.status(400).json({ 
          error: 'Email, password, name, and role are required' 
        });
      }

      if (!rolePermissions[role]) {
        return res.status(400).json({ 
          error: 'Invalid role specified' 
        });
      }

      const existingAdmin = await Admin.findOne({ email });
      if (existingAdmin) {
        return res.status(400).json({ 
          error: 'Admin with this email already exists' 
        });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newAdmin = new Admin({
        email,
        password: hashedPassword,
        name,
        role,
        isActive: true,
        createdBy: req.admin._id
      });

      await newAdmin.save();

      // Return without password
      const adminResponse = await Admin.findById(newAdmin._id)
        .select('-password -webauthnCredentials');

      res.json({ 
        success: true, 
        message: 'Admin created successfully',
        admin: adminResponse 
      });
    } catch (err) {
      console.error('Error creating admin:', err);
      res.status(500).json({ error: 'Failed to create admin' });
    }
  }
);

// Update admin role (super_admin only)
app.put('/api/admin/management/admins/:id/role',
  authenticateAdmin,
  checkPermission('admin_management', 'update'),
  auditLog('update', 'admin_management', (req, data) => req.params.id),
  async (req, res) => {
    try {
      const { role } = req.body;
      const adminId = req.params.id;

      if (!role || !rolePermissions[role]) {
        return res.status(400).json({ 
          error: 'Valid role is required' 
        });
      }

      // Prevent self-demotion from super_admin
      if (adminId === req.admin._id.toString() && role !== 'super_admin') {
        return res.status(400).json({ 
          error: 'Cannot remove your own super_admin role' 
        });
      }

      const updatedAdmin = await Admin.findByIdAndUpdate(
        adminId,
        { role },
        { new: true }
      ).select('-password -webauthnCredentials');

      if (!updatedAdmin) {
        return res.status(404).json({ 
          error: 'Admin not found' 
        });
      }

      res.json({ 
        success: true, 
        message: 'Admin role updated successfully',
        admin: updatedAdmin 
      });
    } catch (err) {
      console.error('Error updating admin role:', err);
      res.status(500).json({ error: 'Failed to update admin role' });
    }
  }
);

// Toggle admin active status (super_admin only)
app.patch('/api/admin/management/admins/:id/status',
  authenticateAdmin,
  checkPermission('admin_management', 'update'),
  auditLog('update', 'admin_management', (req, data) => req.params.id),
  async (req, res) => {
    try {
      const { isActive } = req.body;
      const adminId = req.params.id;

      // Prevent self-deactivation
      if (adminId === req.admin._id.toString() && isActive === false) {
        return res.status(400).json({ 
          error: 'Cannot deactivate your own account' 
        });
      }

      const updatedAdmin = await Admin.findByIdAndUpdate(
        adminId,
        { isActive },
        { new: true }
      ).select('-password -webauthnCredentials');

      if (!updatedAdmin) {
        return res.status(404).json({ 
          error: 'Admin not found' 
        });
      }

      res.json({ 
        success: true, 
        message: `Admin ${isActive ? 'activated' : 'deactivated'} successfully`,
        admin: updatedAdmin 
      });
    } catch (err) {
      console.error('Error updating admin status:', err);
      res.status(500).json({ error: 'Failed to update admin status' });
    }
  }
);

// Get audit logs (super_admin only)
app.get('/api/admin/management/audit-logs',
  authenticateAdmin,
  checkPermission('audit_logs', 'read'),
  async (req, res) => {
    try {
      const { page = 1, limit = 50, action, resource, startDate, endDate, adminEmail } = req.query;
      
      let query = {};
      
      if (action) query.action = action;
      if (resource) query.resource = resource;
      if (adminEmail) query.adminEmail = new RegExp(adminEmail, 'i');
      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) query.timestamp.$gte = new Date(startDate);
        if (endDate) query.timestamp.$lte = new Date(endDate);
      }

      const skip = (page - 1) * limit;
      const logs = await AuditLog.find(query)
        .populate('adminId', 'email name role')
        .sort({ timestamp: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await AuditLog.countDocuments(query);

      res.json({
        success: true,
        logs,
        total,
        totalPages: Math.ceil(total / limit),
        currentPage: parseInt(page)
      });
    } catch (err) {
      console.error('Error fetching audit logs:', err);
      res.status(500).json({ error: 'Failed to fetch audit logs' });
    }
  }
);

// Get system analytics (admin roles with analytics read permission)
app.get('/api/admin/analytics/dashboard',
  authenticateAdmin,
  checkPermission('analytics', 'read'),
  async (req, res) => {
    try {
      const { period = '7d' } = req.query; // 7d, 30d, 90d
      
      const endDate = new Date();
      const startDate = new Date();
      
      switch (period) {
        case '30d':
          startDate.setDate(startDate.getDate() - 30);
          break;
        case '90d':
          startDate.setDate(startDate.getDate() - 90);
          break;
        default: // 7d
          startDate.setDate(startDate.getDate() - 7);
      }

      // Get analytics data
      const analyticsData = await Analytics.find({
        date: { $gte: startDate, $lte: endDate }
      }).sort({ date: 1 });

      // Get recent activities
      const recentActivities = await AuditLog.find()
        .populate('adminId', 'email name role')
        .sort({ timestamp: -1 })
        .limit(10);

      // Get admin statistics
      const adminStats = await Admin.aggregate([
        { $group: { _id: '$role', count: { $sum: 1 } } }
      ]);

      // Get booking statistics
      const bookingStats = await Booking.aggregate([
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ]);

      res.json({
        success: true,
        analytics: {
          period: { start: startDate, end: endDate },
          data: analyticsData,
          summary: {
            totalLogins: analyticsData.reduce((sum, day) => sum + day.logins, 0),
            totalBookings: analyticsData.reduce((sum, day) => sum + day.bookingsCreated, 0),
            totalActivities: analyticsData.reduce((sum, day) => sum + day.adminActivities, 0),
            avgDailyLogins: (analyticsData.reduce((sum, day) => sum + day.logins, 0) / analyticsData.length) || 0
          }
        },
        recentActivities,
        adminStats,
        bookingStats
      });
    } catch (err) {
      console.error('Error fetching analytics:', err);
      res.status(500).json({ error: 'Failed to fetch analytics data' });
    }
  }
);

// ==================== EXISTING ROUTES (UPDATED WITH RBAC) ====================

// Admin Login (Updated with RBAC)
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
      const clientIP = req.ip || req.connection.remoteAddress;
      const attempts = failedAttempts.get(clientIP) || 0;
      failedAttempts.set(clientIP, attempts + 1);

      if (attempts + 1 >= BLACKLIST_THRESHOLD) {
        blacklistedIPs.add(clientIP);
        return res.status(401).json({ error: 'Unauthorized. IP blocked due to multiple failed attempts.' });
      }

      return res.status(401).json({ error: 'Invalid credentials', details: 'Admin not found' });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      const clientIP = req.ip || req.connection.remoteAddress;
      const attempts = failedAttempts.get(clientIP) || 0;
      failedAttempts.set(clientIP, attempts + 1);

      if (attempts + 1 >= BLACKLIST_THRESHOLD) {
        blacklistedIPs.add(clientIP);
        return res.status(401).json({ error: 'Unauthorized. IP blocked due to multiple failed attempts.' });
      }

      return res.status(401).json({ error: 'Invalid credentials', details: 'Incorrect password' });
    }

    // Reset failed attempts
    const clientIP = req.ip || req.connection.remoteAddress;
    failedAttempts.delete(clientIP);

    // Update last login
    admin.lastLogin = new Date();
    admin.loginAttempts = 0;
    await admin.save();

    // Determine 2FA options
    const hasWebAuthn = admin.webauthnCredentials.length > 0;

    // Generate JWT token with role information
    const token = jwt.sign(
      { 
        email: admin.email, 
        role: admin.role,
        name: admin.name
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      admin: {
        email: admin.email,
        name: admin.name,
        role: admin.role,
        hasWebAuthn
      }
    });

  } catch (err) {
    console.error('Admin login error:', err);
    res.status(500).json({
      error: 'Internal server error',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
  }
});

// ==================== BOOKING ROUTES WITH RBAC ====================

app.get('/api/admin/bookings', 
  authenticateAdmin,
  checkPermission('bookings', 'read'),
  auditLog('read', 'bookings'),
  async (req, res) => {
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

app.put('/api/admin/bookings/:id',
  authenticateAdmin,
  checkPermission('bookings', 'update'),
  auditLog('update', 'bookings', (req, data) => req.params.id),
  async (req, res) => {
    try {
        const { id } = req.params;
        const updates = req.body;
        
        // Validate ID parameter
        if (!id || id === "undefined" || id === undefined || id === null || id === "") {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID'
            });
        }
        
        if (!mongoose.Types.ObjectId.isValid(id)) {
            return res.status(400).json({ 
                success: false,
                message: 'Invalid booking ID format'
            });
        }
        
        // Store old data for audit log
        const oldBooking = await Booking.findById(id);
        req.oldData = oldBooking ? oldBooking.toObject() : null;
        
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
        filteredUpdates.updatedBy = req.admin._id;
        
        const booking = await Booking.findByIdAndUpdate(
            id,
            { $set: filteredUpdates },
            { new: true, runValidators: true }
        );
        
        if (!booking) {
            return res.status(404).json({ message: 'Booking not found' });
        }
        
        res.json({
            message: 'Booking updated successfully',
            booking
        });
    } catch (error) {
        console.error('Error updating booking:', error);
        
        if (error.name === 'CastError') {
            return res.status(400).json({ 
                message: 'Invalid booking ID format'
            });
        }
        
        res.status(500).json({ 
            message: 'Error updating booking', 
            error: error.message
        });
    }
});

app.delete('/api/admin/bookings/:id',
  authenticateAdmin,
  checkPermission('bookings', 'delete'),
  auditLog('delete', 'bookings', (req, data) => req.params.id),
  async (req, res) => {
  try {
    const { id } = req.params;
    
    if (!id || id === "undefined" || id === "null") {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID'
      });
    }
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID format'
      });
    }
    
    const booking = await Booking.findById(id);
    if (!booking) {
      return res.status(404).json({ 
        success: false,
        message: 'Booking not found'
      });
    }
    
    await Booking.findByIdAndDelete(id);
    
    res.json({ 
      success: true,
      message: 'Booking deleted successfully'
    });
    
  } catch (error) {
    console.error('Error deleting booking:', error);
    
    if (error.name === 'CastError') {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid booking ID format'
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: 'Error deleting booking'
    });
  }
});

// ==================== GALLERY ROUTES WITH RBAC ====================

app.post('/api/admin/gallery',
  authenticateAdmin,
  checkPermission('gallery', 'create'),
  auditLog('create', 'gallery'),
  upload.array('images', 10),
  async (req, res) => {
  try {
    // ... existing gallery upload code ...
    // (Keep your existing gallery upload implementation)
  } catch (err) {
    console.error('Error uploading gallery images:', err);
    res.status(500).json({ error: 'Failed to upload images' });
  }
});

app.delete('/api/admin/gallery/:id',
  authenticateAdmin,
  checkPermission('gallery', 'delete'),
  auditLog('delete', 'gallery', (req, data) => req.params.id),
  async (req, res) => {
  try {
    // ... existing gallery delete code ...
    // (Keep your existing gallery delete implementation)
  } catch (err) {
    console.error('Error deleting gallery item:', err);
    res.status(500).json({ error: 'Failed to delete gallery item' });
  }
});

// ==================== MESSAGE ROUTES WITH RBAC ====================

app.post('/api/admin/messages',
  authenticateAdmin,
  checkPermission('messages', 'create'),
  auditLog('create', 'messages'),
  upload.array('attachments', 5),
  async (req, res) => {
  try {
    // ... existing message sending code ...
    // (Keep your existing message implementation)
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// ==================== SETTINGS ROUTES WITH RBAC ====================

app.get('/api/admin/settings',
  authenticateAdmin,
  checkPermission('settings', 'read'),
  async (req, res) => {
  try {
    const settings = await Settings.findOne();
    res.json(settings || {});
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/admin/settings',
  authenticateAdmin,
  checkPermission('settings', 'update'),
  auditLog('update', 'settings'),
  async (req, res) => {
  try {
    // ... existing settings update code ...
    // (Keep your existing settings implementation)
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== EXISTING ROUTES (KEEP ALL YOUR EXISTING CODE) ====================

// ... (Keep all your existing routes for WebAuthn, coupons, payments, etc.)
// This includes all the routes you already have for:
// - WebAuthn endpoints
// - Coupon management
// - Payment processing
// - Image uploads
// - User bookings
// - Contact forms
// - etc.

// ==================== SERVER STARTUP ====================

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Static files and server start
app.use(express.static('public'));

// Create uploads directory if it doesn't exist
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Initialize admins and start server
initializeAdmins().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`RBAC System initialized with role-based permissions`);
  });
}).catch(err => {
  console.error('Failed to initialize admins:', err);
  process.exit(1);
});
