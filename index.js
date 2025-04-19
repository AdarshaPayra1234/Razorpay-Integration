require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

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

// Message Schema
const messageSchema = new mongoose.Schema({
  userEmail: { type: String, required: true },
  message: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  isRead: { type: Boolean, default: false },
  notificationSeen: { type: Boolean, default: false } // New field for notification tracking
});

// Admin Schema
const adminSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const Booking = mongoose.model('Booking', bookingSchema);
const Message = mongoose.model('Message', messageSchema);
const Admin = mongoose.model('Admin', adminSchema);

app.use(cors({
  origin: 'https://jokercreation.store',
  credentials: true
}));
app.use(bodyParser.json());

// Razorpay Setup
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Email Transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false
  }
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

initializeAdmin();

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
    const { status } = req.query;
    let query = {};
    
    if (status && ['pending', 'confirmed', 'cancelled', 'completed'].includes(status)) {
      query.status = status;
    }
    
    const bookings = await Booking.find(query).sort({ createdAt: -1 });
    res.json({ success: true, bookings });
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// Get booking statistics for dashboard
app.get('/api/admin/bookings/stats', authenticateAdmin, async (req, res) => {
  try {
    const pendingCount = await Booking.countDocuments({ status: 'pending' });
    const confirmedCount = await Booking.countDocuments({ status: 'confirmed' });
    const cancelledCount = await Booking.countDocuments({ status: 'cancelled' });
    const completedCount = await Booking.countDocuments({ status: 'completed' });
    
    res.json({
      success: true,
      stats: {
        total: pendingCount + confirmedCount + cancelledCount + completedCount,
        pending: pendingCount,
        confirmed: confirmedCount,
        cancelled: cancelledCount,
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

// ===== MESSAGE ROUTES ===== //

// Send message to user
app.post('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { userEmail, message } = req.body;
    
    if (!userEmail || !message) {
      return res.status(400).json({ error: 'User email and message are required' });
    }
    
    const newMessage = new Message({
      userEmail,
      message
    });
    
    await newMessage.save();
    
    // Send email notification to user about new message
    const newMessageHtml = `
    <!DOCTYPE html>
    <html>
    <head>
      <style>
        body { font-family: 'Arial', sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #00acc1; color: white; padding: 20px; text-align: center; border-radius: 5px 5px 0 0; }
        .content { padding: 20px; background-color: #f9f9f9; border-radius: 0 0 5px 5px; }
        .message { background-color: #fff; border: 1px solid #ddd; padding: 15px; margin: 15px 0; }
        .footer { margin-top: 20px; font-size: 12px; text-align: center; color: #777; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>New Message from Joker Creation Studio</h1>
      </div>
      <div class="content">
        <p>You have received a new message from our team:</p>
        <div class="message">
          ${message}
        </div>
        <p>Please login to your account to view and respond to this message.</p>
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
      to: userEmail,
      subject: 'New Message from Joker Creation Studio',
      html: newMessageHtml
    });
    
    res.json({ success: true, message: newMessage });
  } catch (err) {
    console.error('Error sending message:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// Get all messages (admin view)
app.get('/api/admin/messages', authenticateAdmin, async (req, res) => {
  try {
    const { filter } = req.query;
    let query = {};
    
    // Apply filters based on frontend requirements
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
    
    const messages = await Message.find(query).sort({ createdAt: -1 });
    res.json({ success: true, messages });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get all users who have received messages (for admin panel)
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
  try {
    // Get distinct user emails from messages
    const usersWithMessages = await Message.aggregate([
      {
        $group: {
          _id: "$userEmail",
          lastMessageDate: { $max: "$createdAt" },
          messageCount: { $sum: 1 }
        }
      },
      {
        $project: {
          email: "$_id",
          lastMessageDate: 1,
          messageCount: 1,
          _id: 0
        }
      },
      { $sort: { lastMessageDate: -1 } }
    ]);

    res.json({ success: true, users: usersWithMessages });
  } catch (err) {
    console.error('Error fetching users with messages:', err);
    res.status(500).json({ error: 'Failed to fetch users with messages' });
  }
});

// Delete a message
app.delete('/api/admin/messages/:id', authenticateAdmin, async (req, res) => {
  try {
    const message = await Message.findByIdAndDelete(req.params.id);
    
    if (!message) {
      return res.status(404).json({ error: 'Message not found' });
    }
    
    res.json({ success: true, message: 'Message deleted successfully' });
  } catch (err) {
    console.error('Error deleting message:', err);
    res.status(500).json({ error: 'Failed to delete message' });
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

// ===== USER MESSAGE NOTIFICATION ROUTES ===== //

// Get messages for a user with notification status
app.get('/api/messages', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const messages = await Message.find({ userEmail: email })
      .sort({ createdAt: -1 });
    
    // Mark messages as read but keep notification unseen until user views them
    await Message.updateMany(
      { userEmail: email, isRead: false },
      { $set: { isRead: true } }
    );
    
    res.json({ success: true, messages });
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

// Get unread message count for notification badge
app.get('/api/messages/unread-count', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const count = await Message.countDocuments({ 
      userEmail: email,
      notificationSeen: false 
    });
    
    res.json({ success: true, count });
  } catch (err) {
    console.error('Error fetching unread message count:', err);
    res.status(500).json({ error: 'Failed to fetch unread message count' });
  }
});

// Mark notifications as seen
app.patch('/api/messages/mark-seen', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    await Message.updateMany(
      { userEmail: email, notificationSeen: false },
      { $set: { notificationSeen: true } }
    );
    
    res.json({ success: true, message: 'Notifications marked as seen' });
  } catch (err) {
    console.error('Error marking notifications as seen:', err);
    res.status(500).json({ error: 'Failed to update notifications' });
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

// Static files and server start
app.use(express.static('public'));
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
