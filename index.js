// index.js
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Create MySQL connection pool
const pool = mysql.createPool({
  host: process.env.MYSQL_HOST,
  user: process.env.MYSQL_USER,
  password: process.env.MYSQL_PASSWORD,
  database: process.env.MYSQL_DATABASE,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to authenticate requests
const authenticate = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ message: 'Invalid token.' });
  }
};

// Routes

// Register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  pool.query(
    'INSERT INTO users (username, password) VALUES (?, ?)',
    [username, hashedPassword],
    (err, results) => {
      if (err) {
        return res.status(400).json({ message: 'Failed to register user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    }
  );
});

// Login a user
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  pool.query(
    'SELECT * FROM users WHERE username = ?',
    [username],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }
      const user = results[0];
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(400).json({ message: 'Invalid username or password' });
      }
      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });
      res.json({ token });
    }
  );
});

// Get all users (except the current user)
app.get('/users', authenticate, (req, res) => {
  pool.query(
    'SELECT id, username FROM users WHERE id != ?',
    [req.user.userId],
    (err, results) => {
      if (err) {
        return res.status(400).json({ message: 'Failed to fetch users' });
      }
      res.json(results);
    }
  );
});

// Send a message (protected route)
app.post('/send-message', authenticate, (req, res) => {
  const { recipient, content } = req.body;
  const sender = req.user.userId;
  pool.query(
    'INSERT INTO messages (sender, recipient, content) VALUES (?, ?, ?)',
    [sender, recipient, content],
    (err, results) => {
      if (err) {
        return res.status(400).json({ message: 'Failed to send message' });
      }
      const message = { id: results.insertId, sender, recipient, content, timestamp: new Date() };
      io.emit('newMessage', message); // Broadcast the new message
      res.status(201).json(message);
    }
  );
});

// Get all messages for the current user
app.get('/messages', authenticate, (req, res) => {
  const userId = req.user.userId;
  pool.query(
    'SELECT messages.*, users.username FROM messages JOIN users ON messages.sender = users.id WHERE messages.recipient = ? ORDER BY messages.timestamp DESC',
    [userId],
    (err, results) => {
      if (err) {
        return res.status(400).json({ message: 'Failed to fetch messages' });
      }
      res.json(results);
    }
  );
});

// Serve the HTML interface
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Socket.IO for real-time messaging
io.on('connection', (socket) => {
  console.log('A user connected');

  socket.on('disconnect', () => {
    console.log('A user disconnected');
  });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});