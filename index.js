require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 8080;

// Connect to MongoDB Atlas
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB Atlas (booking_db)'))
.catch((err) => console.error('MongoDB connection error:', err));

// Enhanced Booking Schema with more fields
const bookingSchema = new mongoose.Schema({
  customerName: { type: String, required: true },
  customerEmail: { type: String, required: true },
  customerPhone: { type: String, required: true },
  package: { type: String, required: true },
  bookingDates: { type: String, required: true },
  preWeddingDate: String,
  address: { type: String, required: true },
  transactionId: { type: String, required: true },
  paymentStatus: { type: String, default: 'Paid' },
  bookingStatus: { type: String, default: 'Confirmed' },
  amountPaid: { type: Number, required: true },
  bookingId: { type: String, unique: true },
  createdAt: { type: Date, default: Date.now },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' } // Reference to user account
});

const Booking = mongoose.model('Booking', bookingSchema);

// User Schema for account integration
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String },
  bookings: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Booking' }],
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

app.use(cors());
app.use(bodyParser.json());

// Razorpay configuration
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Email Transporter Setup
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

// Generate unique booking ID
function generateBookingId() {
  return 'JC-' + Math.random().toString(36).substr(2, 8).toUpperCase();
}

// Create Razorpay order
app.post('/create-order', (req, res) => {
  const { amount, userId } = req.body;

  const options = {
    amount: amount * 100,
    currency: 'INR',
    receipt: generateBookingId(),
  };

  razorpayInstance.orders.create(options, (err, order) => {
    if (err) {
      console.error('Error creating Razorpay order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    res.json({
      id: order.id,
      receipt: order.receipt
    });
  });
});

// Save booking and send confirmation
app.post('/save-booking', async (req, res) => {
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
      amountPaid,
      userId,
      razorpayOrderId
    } = req.body;

    // Find user if userId is provided
    let user = null;
    if (userId) {
      user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }
    }

    // Create new booking
    const newBooking = new Booking({
      customerName,
      customerEmail,
      customerPhone,
      package,
      bookingDates,
      preWeddingDate,
      address,
      transactionId,
      amountPaid,
      bookingId: razorpayOrderId,
      userId: user ? user._id : null
    });

    // Save booking
    const savedBooking = await newBooking.save();

    // Update user's bookings if user exists
    if (user) {
      user.bookings.push(savedBooking._id);
      await user.save();
    }

    // Send confirmation email
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: customerEmail,
      subject: 'Booking Confirmation - Joker Creation Studio',
      html: generateConfirmationEmail(savedBooking)
    };

    await transporter.sendMail(mailOptions);

    // Return booking details including ID for account page reference
    res.status(200).json({
      success: true,
      message: 'Booking confirmed successfully',
      booking: {
        id: savedBooking._id,
        bookingId: savedBooking.bookingId,
        package: savedBooking.package,
        dates: savedBooking.bookingDates,
        status: savedBooking.bookingStatus,
        amount: savedBooking.amountPaid,
        transactionId: savedBooking.transactionId
      }
    });

  } catch (error) {
    console.error('Error saving booking:', error);
    res.status(500).json({ 
      success: false,
      message: 'Failed to process booking',
      error: error.message
    });
  }
});

// Generate email HTML
function generateConfirmationEmail(booking) {
  return `
    <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
      <div style="max-width: 600px; margin: auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);">
        <h2 style="color: #2c3e50; text-align: center;">Booking Confirmation</h2>
        <p style="font-size: 16px; color: #34495e;">Hello ${booking.customerName},</p>
        <p style="font-size: 16px; color: #34495e;">Thank you for booking with Joker Creation Studio! Below are your booking details:</p>
        
        <table style="width: 100%; margin-top: 20px; border-collapse: collapse;">
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Booking ID</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.bookingId}</td>
          </tr>
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Package</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.package}</td>
          </tr>
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Event Dates</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.bookingDates}</td>
          </tr>
          ${booking.preWeddingDate ? `
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Pre-Wedding Date</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.preWeddingDate}</td>
          </tr>
          ` : ''}
          <tr style="background-color: #ecf0f1;">
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Amount Paid</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">₹${booking.amountPaid}</td>
          </tr>
          <tr>
            <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Transaction ID</td>
            <td style="padding: 10px; font-size: 14px; color: #34495e;">${booking.transactionId}</td>
          </tr>
        </table>

        <p style="font-size: 16px; color: #34495e; margin-top: 20px;">
          You can view and manage your booking in your <a href="https://www.jokercreation.store/account.html" style="color: #2980b9;">account page</a>.
        </p>

        <p style="font-size: 16px; color: #34495e; margin-top: 20px;"><strong>Terms and Conditions:</strong></p>
        <ul style="font-size: 14px; color: #34495e;">
          <li>Advance payment is non-refundable.</li>
          <li>Final payment must be made before the event starts.</li>
          <li>Cancellation must be done at least 7 days before the event for a full refund of the advance.</li>
        </ul>

        <p style="font-size: 16px; color: #34495e; text-align: center; margin-top: 30px;">
          Regards, <br><strong>Joker Creation Studio</strong>
        </p>
        <p style="font-size: 14px; color: #34495e; text-align: center;">
          <a href="https://www.jokercreation.store" style="color: #2980b9;">www.jokercreation.store</a><br>
          Email: <a href="mailto:jokercreationbuisness@gmail.com" style="color: #2980b9;">jokercreationbuisness@gmail.com</a><br>
          Mobile: 9641837935
        </p>
      </div>
    </div>
  `;
}

// Get user bookings for account page
app.get('/api/user-bookings/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const bookings = await Booking.find({ userId })
      .sort({ createdAt: -1 })
      .select('bookingId package bookingDates bookingStatus amountPaid transactionId createdAt');

    res.json({
      success: true,
      bookings
    });
  } catch (error) {
    console.error('Error fetching user bookings:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch bookings'
    });
  }
});

// Contact form submission
app.post('/contact-submit', (req, res) => {
  const { name, mobile, email, message } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: process.env.EMAIL_TO,
    subject: 'New Contact Form Submission',
    html: `
      <div style="font-family: Arial, sans-serif;">
        <h2 style="color: #2c3e50;">New Contact Inquiry</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Mobile:</strong> ${mobile}</p>
        <p><strong>Email:</strong> ${email}</p>
        ${message ? `<p><strong>Message:</strong> ${message}</p>` : ''}
        <p style="margin-top: 20px;">
          <em>Received from Joker Creation Studio website contact form</em>
        </p>
      </div>
    `
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

// Serve static files
app.use(express.static('public'));

// Start server
app.listen(PORT, () => {
  console.log(`Server running on https://www.jokercreation.store:${PORT}`);
});
