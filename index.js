require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

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
  customerEmail: { type: String, required: true },  // Now required for user matching
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
  userId: String,  // Optional field if you want to store user IDs
  createdAt: { type: Date, default: Date.now }
});

const Booking = mongoose.model('Booking', bookingSchema);

app.use(cors());
app.use(bodyParser.json());

// Razorpay Setup (Unchanged)
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// ===== NEW ENDPOINTS ===== //

// Get bookings by email
app.get('/api/bookings', async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: 'Email is required' });

    const bookings = await Booking.find({ customerEmail: email })
      .sort({ createdAt: -1 });  // Newest first
    res.json({ success: true, bookings });
  } catch (err) {
    console.error('Error fetching bookings:', err);
    res.status(500).json({ error: 'Failed to fetch bookings' });
  }
});

// Admin endpoint to update booking status
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

// ===== EXISTING ENDPOINTS (UPDATED) ===== //

// Updated save-booking endpoint
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
      userId  // Optional
    } = req.body;

    const newBooking = new Booking({
      customerName,
      customerEmail,  // Now required
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

    // Send confirmation email (unchanged template)
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: 'Booking Confirmation - Joker Creation Studio',
      html: `
        <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
          <!-- Your existing email template -->
        </div>
      `,
    };

    await transporter.sendMail(mailOptions);
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

// ===== EXISTING ENDPOINTS (UNCHANGED) ===== //

// Razorpay order creation (unchanged)
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

// Contact form (unchanged)
app.post('/contact-submit', (req, res) => {
  const { name, mobile, email } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_TO,
    subject: 'New Contact Form Submission',
    text: `Name: ${name}\nMobile: ${mobile}\nEmail: ${email}`,
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

// Email Transporter (unchanged)
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

// Static files and server start (unchanged)
app.use(express.static('public'));
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
