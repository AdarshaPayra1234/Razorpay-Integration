require('dotenv').config();  // Ensure that dotenv is loaded
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Razorpay = require('razorpay');
const nodemailer = require('nodemailer');
const mongoose = require('mongoose');

const app = express();
const PORT = 8080;

// Connect to MongoDB Atlas using the URI from the .env file
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB Atlas (booking_db)'))
  .catch((err) => console.error('MongoDB connection error:', err));

// Define Mongoose schema for the booking details
const bookingSchema = new mongoose.Schema({
  customerName: String,
  customerEmail: String,
  customerPhone: String,
  package: String,
  bookingDates: String,
  preWeddingDate: String,
  address: String,
  transactionId: String,
  paymentStatus: String,
});

const Booking = mongoose.model('Booking', bookingSchema);

app.use(cors());
app.use(bodyParser.json());

// Razorpay credentials from environment variables
const razorpayInstance = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// Endpoint to create an order with Razorpay
app.post('/create-order', (req, res) => {
  const { amount } = req.body;

  const options = {
    amount: amount * 100,  // Convert to paise
    currency: 'INR',
    receipt: 'receipt#1',
  };

  razorpayInstance.orders.create(options, (err, order) => {
    if (err) {
      console.error('Error creating Razorpay order:', err);
      return res.status(500).json({ error: 'Failed to create order' });
    }

    res.json({
      id: order.id,
    });
  });
});

// Email Transporter Setup
const transporter = nodemailer.createTransport({
  service: 'gmail', // or other service like Outlook or Yahoo
  auth: {
    user: process.env.EMAIL_USER,   // Your email address
    pass: process.env.EMAIL_PASS,   // Your email password or App Password
  },
});

// Endpoint to save booking details and send confirmation email
app.post('/save-booking', (req, res) => {
  console.log('Booking data received:', req.body);

  const {
    customerName,
    customerEmail,
    customerPhone,
    package,
    bookingDates,
    preWeddingDate,
    address,
    transactionId,
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
    paymentStatus: 'Paid', // Assuming payment is done after Razorpay transaction
  });

  // Save booking details
  newBooking.save()
    .then(() => {
      console.log("Booking details saved successfully");

      // Email sending setup
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: customerEmail,
        subject: 'Booking Confirmation - Joker Creation Studio',
        html: `
          <div style="font-family: Arial, sans-serif; background-color: #f9f9f9; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0px 4px 10px rgba(0, 0, 0, 0.1);">
              <h2 style="color: #2c3e50; text-align: center;">Booking Confirmation</h2>
              <p style="font-size: 16px; color: #34495e;">Hello ${customerName},</p>
              <p style="font-size: 16px; color: #34495e;">Thank you for booking with Joker Creation Studio! Below are the details of your booking:</p>
              <table style="width: 100%; margin-top: 20px; border-collapse: collapse;">
                <tr style="background-color: #ecf0f1;">
                  <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Package</td>
                  <td style="padding: 10px; font-size: 14px; color: #34495e;">${package}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Event Dates</td>
                  <td style="padding: 10px; font-size: 14px; color: #34495e;">${bookingDates}</td>
                </tr>
                <tr style="background-color: #ecf0f1;">
                  <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Pre-Wedding Date</td>
                  <td style="padding: 10px; font-size: 14px; color: #34495e;">${preWeddingDate}</td>
                </tr>
                <tr>
                  <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Address</td>
                  <td style="padding: 10px; font-size: 14px; color: #34495e;">${address}</td>
                </tr>
                <tr style="background-color: #ecf0f1;">
                  <td style="padding: 10px; font-size: 14px; font-weight: bold; color: #2c3e50;">Transaction ID</td>
                  <td style="padding: 10px; font-size: 14px; color: #34495e;">${transactionId}</td>
                </tr>
              </table>
              <p style="font-size: 16px; color: #34495e; margin-top: 20px;"><strong>Terms and Conditions:</strong></p>
              <ul style="font-size: 14px; color: #34495e;">
                <li>Advance payment is non-refundable.</li>
                <li>Final payment must be made before the event starts.</li>
                <li>Cancellation of booking can be done at least 7 days before the event for a full refund of the advance.</li>
                <li>We are not responsible for any delays caused by external factors such as weather, venue issues, etc.</li>
              </ul>
              <p style="font-size: 16px; color: #34495e; margin-top: 20px;">This is a computer-generated email, and no signature is required. Our team will review your booking and send you a confirmation email with the finalized details.</p>
              <br>
              <p style="font-size: 16px; color: #34495e; text-align: center;">Regards, <br><strong>Joker Creation Studio</strong></p>
              <p style="font-size: 14px; color: #34495e; text-align: center;">
                <a href="http://www.jokercreation.store" style="color: #2980b9;">www.jokercreation.store</a><br>
                Email: <a href="mailto:jokercreationbuisness@gmail.com" style="color: #2980b9;">jokercreationbuisness@gmail.com</a><br>
                Mobile: 9641837935
              </p>
            </div>
          </div>
        `,
      };

      // Send confirmation email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).send({ message: 'Failed to send confirmation email' });
        } else {
          console.log('Email sent:', info.response);
          return res.status(200).send({ message: 'Booking details saved successfully. We have sent a computer-generated email to your inbox. Please check your email for more details.' });
        }
      });
    })
    .catch((error) => {
      console.error('Error saving booking details:', error);
      res.status(500).send({ message: 'Failed to save booking details' });
    });
});

// Contact form handler for sending email
app.post('/contact-submit', (req, res) => {
  const { name, mobile, email } = req.body;

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: 'radhakantapayra@gmail.com',
    subject: 'New Contact Form Submission',
    text: `Name: ${name}\nMobile: ${mobile}\nEmail: ${email}`,
  };

  // Send email with contact form data
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      console.error('Error sending email:', error);
      return res.status(500).json({ message: 'Failed to send message' });
    } else {
      return res.status(200).json({ message: 'Message sent successfully!' });
    }
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
