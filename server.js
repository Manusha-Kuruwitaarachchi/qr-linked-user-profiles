const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const qrcode = require('qrcode');
const multer = require('multer');
const cors = require('cors');
const path = require('path');
const ip = require('ip');

const app = express();
app.use(express.json());

// Update CORS configuration
app.use(cors({
  origin: '*', // Be cautious with this in production
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Connect to MongoDB
mongoose.connect('mongodb://localhost/user_registration_db', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  dateOfBirth: Date,
  location: String,
  facebookId: String,
  email: String,
  username: { type: String, unique: true },
  password: String,
  profilePicture: String,
  qrCode: String,
});

const User = mongoose.model('User', userSchema);

// Multer setup for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Registration endpoint
app.post('/register', upload.single('profilePicture'), async (req, res) => {
  try {
    const { name, dateOfBirth, location, facebookId, email, username, password } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const user = new User({
      name,
      dateOfBirth,
      location,
      facebookId,
      email,
      username,
      password: hashedPassword,
      profilePicture: req.file.buffer.toString('base64'),
    });
    
    await user.save();
    
    // Generate QR code with the full URL to the user profile page
    const serverAddress = ip.address(); // Get the server's IP address
    const qrCodeUrl = `http://${serverAddress}:3000/user-profile.html#${user._id}`;
    const qrCode = await qrcode.toDataURL(qrCodeUrl);
    
    user.qrCode = qrCode;
    await user.save();
    
    res.status(201).json({ message: 'User registered successfully', qrCodeUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user._id }, 'your_jwt_secret', { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard endpoint
app.get('/dashboard', async (req, res) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, 'your_jwt_secret');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Generate QR code with the full URL to the user profile page
    const serverAddress = ip.address(); // Get the server's IP address
    const qrCodeUrl = `http://${serverAddress}:3000/user-profile.html#${user._id}`;
    const qrCode = await qrcode.toDataURL(qrCodeUrl);
    
    res.json({
      userId: user._id,
      name: user.name,
      qrCode: qrCode,
      profilePicture: user.profilePicture,
    });
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
});

// Endpoint to fetch user details by ID
app.get('/user/:id', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Send user details excluding sensitive information
    res.json({
      name: user.name,
      dateOfBirth: user.dateOfBirth,
      location: user.location,
      facebookId: user.facebookId,
      email: user.email,
      username: user.username,
      profilePicture: user.profilePicture,
    });
  } catch (error) {
    res.status(500).json({ error: 'Error fetching user data' });
  }
});

// Serve the user profile page
app.get('/user-profile.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'user-profile.html'));
});

const PORT = process.env.PORT || 3000;
const serverAddress = ip.address(); // Get the server's IP address

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on http://${serverAddress}:${PORT}`);
});