if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const path = require('path');
// const https = require('https');
const http = require('http');
const app = express();
const PORT = process.env.PORT || 4000;

// ------------------------------------------------------------------

const bcrypt = require('bcrypt'); // Encryption
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

const initializePassport = require('./passport-config');

const multer = require('multer');  // required for upload
// Files are kept in memory and persisted to Postgres (see uploads table below) instead of
// local disk: Render's free tier wipes the filesystem on every restart/redeploy, which was
// leaving chat history pointing at images that no longer existed.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB
});

// =============== Rate Limiting ===============
const rateLimit = require('express-rate-limit');

// Brute Force Protection for Login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Max 5 attempts per IP
  message: "Too many login attempts, please try again after 15 minutes."
});
// =============================================

// ============== Account Lockout ==============
// Track failed attempts
const MAX_ATTEMPTS = 5;
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes
// =============================================

const db = require('./db');

// Hash Emails
const crypto = require('crypto'); // For hashing emails securely

// Function to hash an email using SHA-256
function hashEmail(email) {
  return crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');
}

initializePassport(
  passport,
  async email => {
    const hashedEmail = hashEmail(email);
    const result = await db.query('SELECT * FROM users WHERE email = $1', [hashedEmail]);
    return result.rows[0];
  },
  async id => {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [id]);
    return result.rows[0];
  }
);

const server = http.createServer(app);

const io = require('socket.io')(server)

// REUQUIRES SECRET KEY FOR SESSION
/* const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
});*/

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'fallback-secret',
  resave: false,
  saveUninitialized: false,
});


app.set('io', io)
app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(sessionMiddleware)
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))
io.engine.use(sessionMiddleware);


// ------------------------------------------------------------------

// server.listen(PORT, LOCAL_IP, () => console.log(`Chat server running on https://${LOCAL_IP}:${PORT}`))
server.listen(PORT, () => console.log(`Chat server running on port ${PORT}`));

// Uploaded files are stored here (not on disk) so they survive restarts/redeploys.
db.query(`
  CREATE TABLE IF NOT EXISTS uploads (
    filename TEXT PRIMARY KEY,
    mimetype TEXT NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now()
  )
`).catch(err => console.error('Failed to ensure uploads table:', err));


app.use(express.static(path.join(__dirname, 'public')));

let usersConnected = new Set()

const rooms = {
  general: { users: [] },
  general2: { users: [] },
  general3: { users: [] },
}

// Messages older than this are hidden from history and eventually purged from the DB.
const MESSAGE_RETENTION = '1 day';

// Persist a message to Postgres so history survives server restarts.
async function logMessage(room, data) {
  try {
    await db.query(
      'INSERT INTO messages (room, name, message, timestamp) VALUES ($1, $2, $3, $4)',
      [room, data.name, data.message, data.dateTime]
    );
  } catch (err) {
    console.error('Failed to log message to DB:', err);
  }
}

// Load the most recent messages for a room from Postgres, oldest first.
async function getRoomHistory(room, limit = 100) {
  try {
    const result = await db.query(
      'SELECT name, message, timestamp FROM messages WHERE room = $1 AND timestamp > NOW() - $2::interval ORDER BY id DESC LIMIT $3',
      [room, MESSAGE_RETENTION, limit]
    );
    return result.rows.reverse().map(row => ({
      name: row.name,
      message: row.message,
      dateTime: row.timestamp
    }));
  } catch (err) {
    console.error('Failed to load room history from DB:', err);
    return [];
  }
}

// Permanently delete messages once they've aged past the retention window.
async function purgeOldMessages() {
  try {
    const result = await db.query('DELETE FROM messages WHERE timestamp <= NOW() - $1::interval', [MESSAGE_RETENTION]);
    if (result.rowCount) {
      console.log(`Purged ${result.rowCount} message(s) older than ${MESSAGE_RETENTION}`);
    }
  } catch (err) {
    console.error('Failed to purge old messages:', err);
  }
}

purgeOldMessages();
setInterval(purgeOldMessages, 60 * 60 * 1000); // hourly

io.on('connection', onConnected);

async function onConnected(socket) {
  const session = socket.request.session;

  const user = {
    name: session.user,
    id: socket.id,
    rooms: Object.keys(rooms).map(String),
    currentRoom: 'general'
  }

  socket.join('general')
  rooms['general'].users.push(socket.id)
  console.log(`User: ${user.name}, Socket ID: ${socket.id}`)
  io.emit('total-clients', rooms[user.currentRoom].users.length)

  session.user = user

  usersConnected.add(user)

  io.emit('new-user', user)

  const initialHistory = await getRoomHistory(user.currentRoom)
  socket.emit('joined-room', user.name, user.currentRoom, initialHistory)

  socket.on("join-room", async (roomName) => {
    socket.leave(user.currentRoom)
    rooms[user.currentRoom].users = rooms[user.currentRoom].users.filter((id) => id !== socket.id)

    socket.join(roomName)
    user.currentRoom = roomName

    if (!user.rooms.includes(roomName)) {
      user.rooms.push(roomName)
    }

    if (!rooms[roomName].users.includes(socket.id)) {
      rooms[roomName].users.push(socket.id)
    }

    socket.to(user.currentRoom).emit('total-clients', rooms[user.currentRoom].users.length)

    const history = await getRoomHistory(roomName)
    socket.emit('joined-room', user.name, user.currentRoom, history)
  })

  socket.on('disconnect', () => {
    console.log('Disconnected: ', socket.id)
    usersConnected.delete(socket.id)
    io.emit("total-clients", usersConnected.size)

    user.rooms = user.rooms.filter(roomName => rooms[roomName].users.includes(socket.id))
  })

  socket.on('message', async (room, data) => {
    if (room === user.currentRoom) {
      socket.to(user.currentRoom).emit('chat-message', { ...data, room: user.currentRoom })
      await logMessage(user.currentRoom, data)
    }
  })

  socket.on('feedback', (room, data) => {
    if (room === user.currentRoom) {
      socket.to(user.currentRoom).emit('feedback', data)
    }
  })
}

// Authentication
app.set('views', path.join(__dirname, 'views'));

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name, rooms: rooms });
});

// GET Login
app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs');
});

// POST Login
app.post('/login', checkNotAuthenticated, async (req, res) => {
  const hashedEmail = hashEmail(req.body.email);

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [hashedEmail]);
    const user = result.rows[0];

    if (!user) {
      return res.redirect('/login');
    }

    const now = Date.now();

    // Check if account is currently locked
    if (user.lockuntil && Number(user.lockuntil) > now) {
      return res.status(403).send('Account locked. Try again later.');
    }

    const match = await bcrypt.compare(req.body.password, user.password);

    if (match) {
      // Successful login: reset failedAttempts and lockUntil
      await db.query(
        'UPDATE users SET failedattempts = 0, lockuntil = NULL WHERE id = $1',
        [user.id]
      );

      req.login(user, err => {
        if (err) return res.status(500).send('Login error');
        res.redirect('/');
      });

    } else {
      // Failed login: increment failedAttempts
      const attempts = (user.failedattempts || 0) + 1;
      const lockUntil = attempts >= MAX_ATTEMPTS ? now + LOCKOUT_DURATION : null;

      await db.query(
        'UPDATE users SET failedattempts = $1, lockuntil = $2 WHERE id = $3',
        [attempts, lockUntil, user.id]
      );

      if (lockUntil) {
        return res.status(403).send('Too many attempts. Account locked for 30 minutes.');
      }

      res.redirect('/login');
    }
  } catch (err) {
    console.error(err);
    res.redirect('/login');
  }
});


// GET Register
app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs');
});

// POST Register
app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const hashedEmail = hashEmail(req.body.email);

    await db.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
      [req.body.name, hashedEmail, hashedPassword]
    );

    res.redirect('/login');
  } catch (err) {
    console.error(err);
    res.redirect('/register');
  }
});

app.post('/upload', (req, res, next) => {
  upload.single('file')(req, res, (err) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({ error: 'File too large (max 5MB)' });
    }
    if (err) {
      return res.status(400).json({ error: 'Upload failed' });
    }
    next();
  });
}, async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const ext = path.extname(req.file.originalname);
  const fileName = `${crypto.randomBytes(16).toString('hex')}${ext}`;

  try {
    await db.query(
      'INSERT INTO uploads (filename, mimetype, data) VALUES ($1, $2, $3)',
      [fileName, req.file.mimetype, req.file.buffer]
    );
    res.json({ filePath: `uploads/${fileName}` });
  } catch (err) {
    console.error('Failed to store upload:', err);
    res.status(500).json({ error: 'Upload failed' });
  }
});

app.get('/uploads/:filename', async (req, res) => {
  try {
    const result = await db.query('SELECT mimetype, data FROM uploads WHERE filename = $1', [req.params.filename]);
    const file = result.rows[0];
    if (!file) {
      return res.status(404).send('File not found');
    }
    res.set('Content-Type', file.mimetype);
    res.send(file.data);
  } catch (err) {
    console.error('Failed to fetch upload:', err);
    res.status(500).send('Failed to load file');
  }
});


// Logout
app.delete('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err); // Handle errors properly
    }
    res.redirect('/login');
  });
});

function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    req.session.user = req.user.name
    return next()
  }

  res.redirect('/login');
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    req.session.user = req.user.name
    return res.redirect('/')
  }
  next()
}

app.listen(3000);