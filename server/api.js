const { executeSQL } = require('./database')
require('dotenv').config();
const { body, validationResult } = require("express-validator");
const { initializeMariaDB, queryDB, insertDB } = require("./database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = process.env.SECRET_KEY || 'fallback-secret-key';
let db;
let io;


/**
 * A simple hello world endpoint.
 * @example
 * hello(req, res);
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const hello = (req, res) => {
  res.send('Hello World!')
}

/**
 * A simple users that shows the use of the database for insert and select statements.
 * @example
 * users(req, res);
 * @param {Object} req - The request object.
 * @param {Object} res - The response object.
 * @returns {void}
 */
const users = async (req, res) => {
  await executeSQL("INSERT INTO users (name) VALUES ('John Doe');")
  const result = await executeSQL('SELECT * FROM users;')
  res.json(result)
}

// Middleware for token authentication with logging
async function authenticateToken(req, res, next) {
  try {
    console.log(`Authenticating token for ${req.method} ${req.originalUrl}`);
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      console.warn("Authorization header missing");
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
      console.warn("Token not found in authorization header");
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }
    req.user = await new Promise((resolve, reject) => {
      jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
          console.error(`Token verification failed: ${err.message}`);
          reject(err);
        } else {
          resolve(decoded);
        }
      });
    });
    console.log(`Token authenticated for user: ${req.user.username}`);
    next();
  } catch (err) {
    console.error(`Authentication error: ${err.message}`);
    return res.status(403).json({ message: "Forbidden: invalid Token" });
  }
}



// Socket.io Authentifizierung
const authenticateSocketToken = (socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Nicht authentifiziert'));
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return next(new Error('Ungültiger Token'));
    }
    socket.user = decoded;
    next();
  });
};

const login = async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(`Login attempt for user: ${username}`);

    const query = `SELECT * FROM users WHERE username = ?`;
    const users = await queryDB(db, query, [username]);

    if (users.length !== 1) {
      console.warn(`Login failed for user ${username}: user not found`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];
    // Compare password with bcrypt
    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      console.warn(`Login failed for user ${username}: invalid password`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Remove sensitive data
    delete user.password;

    // Create token payload
    const tokenPayload = {
      id: user.id,
      username: user.username
    };

    // Generate signed token (valid for 1 hour)
    const token = jwt.sign(tokenPayload, secretKey, { expiresIn: "1h" });
    console.log(`User ${username} logged in successfully`);
    res.json({ token, username: user.username, id: user.id });
  } catch (err) {
    console.error(`Login error for user ${req.body.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const register = async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(`Registration attempt for user: ${username}`);

    if (!username || !password) {
      console.warn("Registration failed: Missing username or password");
      return res.status(400).json({ error: "Username and password are required" });
    }

    // Check if user already exists
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    const existingUsers = await queryDB(db, checkQuery, [username]);

    if (existingUsers.length > 0) {
      console.warn(`Registration failed: User ${username} already exists`);
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    const insertQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
    await insertDB(db, insertQuery, [username, hashedPassword]);

    console.log(`User ${username} registered successfully`);
    res.json({ status: "registered" });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT' || error.code === 'ER_DUP_ENTRY') {
      console.warn(`Registration failed (constraint): User ${req.body.username} already exists`);
      return res.status(400).json({ error: "User already exists" });
    }

    console.error(`Registration error for user ${req.body.username}: ${error.message}`);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

const getMessages = async (req, res) => {
  try {
    console.log(`Fetching messages for user: ${req.user.username}`);

    // Load all messages from the chat
    const query = `
      SELECT messages.id, messages.content, messages.timestamp, users.username as sender
      FROM messages
             JOIN users ON messages.sender_id = users.id
      ORDER BY messages.timestamp ASC
        LIMIT 100
    `;

    const messages = await queryDB(db, query);

    console.log(`Messages fetched successfully for user: ${req.user.username}`);
    res.json(messages);
  } catch (err) {
    console.error(`Error fetching messages for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

const sendMessage = async (req, res) => {
  try {
    console.log(`User ${req.user.username} is sending a new message`);

    const { content } = req.body;
    if (!content || content.trim() === "") {
      console.warn("Message sending failed: Message content is required");
      return res.status(400).json({ error: "Message content is required" });
    }

    // Get user ID from token
    const userId = req.user.id;
    const timestamp = new Date().toISOString();

    // Insert message into database
    const query = "INSERT INTO messages (sender_id, content, timestamp) VALUES (?, ?, ?)";
    const result = await insertDB(db, query, [userId, content, timestamp]);

    // Send message to all connected clients
    const messageData = {
      id: result.insertId,
      sender_id: userId,
      sender: req.user.username,
      content: content,
      timestamp: timestamp
    };

    // Broadcast to all clients via Socket.io
    io.emit('new_message', messageData);

    console.log(`Message sent successfully by user ${req.user.username}`);
    res.json({ status: "ok", message: messageData });
  } catch (err) {
    console.error(`Error sending message for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Function to retrieve active users
const getActiveUsers = async (req, res) => {
  try {
    console.log(`Fetching active users for user: ${req.user.username}`);

    // Get active users from database (users active in the last 5 minutes)
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const query = `
      SELECT users.id, users.username, active_users.last_active
      FROM active_users
             JOIN users ON active_users.user_id = users.id
      WHERE active_users.last_active > ?
    `;

    const activeUsers = await queryDB(db, query, [fiveMinutesAgo]);

    console.log(`Active users fetched successfully for user: ${req.user.username}`);
    res.json(activeUsers);
  } catch (err) {
    console.error(`Error fetching active users for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// Function to update user typing status
const setUserTyping = async (req, res) => {
  try {
    const { isTyping } = req.body;
    const userId = req.user.id;
    const username = req.user.username;

    // Broadcast to all clients that user is typing
    io.emit('user_typing', { userId, username, isTyping });

    res.json({ status: "ok" });
  } catch (err) {
    console.error(`Error updating typing status for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Function to update user's active status
const updateUserActivity = async (userId) => {
  try {
    const timestamp = new Date().toISOString();

    // Check if user already exists in active_users table
    const checkQuery = "SELECT * FROM active_users WHERE user_id = ?";
    const existingUser = await queryDB(db, checkQuery, [userId]);

    if (existingUser.length > 0) {
      // Update existing record
      const updateQuery = "UPDATE active_users SET last_active = ? WHERE user_id = ?";
      await queryDB(db, updateQuery, [timestamp, userId]);
    } else {
      // Insert new record
      const insertQuery = "INSERT INTO active_users (user_id, last_active) VALUES (?, ?)";
      await insertDB(db, insertQuery, [userId, timestamp]);
    }

    // Get updated list of active users
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    const activeUsersQuery = `
      SELECT users.id, users.username
      FROM active_users
      JOIN users ON active_users.user_id = users.id
      WHERE active_users.last_active > ?
    `;

    const activeUsers = await queryDB(db, activeUsersQuery, [fiveMinutesAgo]);

    // Broadcast updated active users list
    io.emit('active_users_updated', activeUsers);

  } catch (err) {
    console.error(`Error updating user activity: ${err.message}`);
  }
};


const initializeAPI = async (app, server) => {
  // Initialize database
  db = await initializeMariaDB();

  // Initialize Socket.io
  io = require('socket.io')(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  // Socket.io authentication middleware
  io.use(authenticateSocketToken);

  // Socket.io connection handling
  io.on('connection', (socket) => {
    console.log(`User ${socket.user.username} connected`);

    // Update user activity when connected
    updateUserActivity(socket.user.id);

    // Set up periodic activity update (every minute)
    const activityInterval = setInterval(() => {
      updateUserActivity(socket.user.id);
    }, 60000);

    // Handle user typing events
    socket.on('user_typing', (data) => {
      // Broadcast to all clients except sender
      socket.broadcast.emit('user_typing', {
        userId: socket.user.id,
        username: socket.user.username,
        isTyping: data.isTyping
      });
    });

    // Handle disconnect
    socket.on('disconnect', () => {
      console.log(`User ${socket.user.username} disconnected`);
      clearInterval(activityInterval);

      // Update active users list after a short delay
      setTimeout(() => {
        updateUserActivity(socket.user.id);
      }, 1000);
    });
  });

  // API Routes

  // Get messages
  app.get("/api/messages", authenticateToken, async (req, res) => {
    await getMessages(req, res);
  });

  // Send message
  app.post(
      "/api/messages",
      authenticateToken,
      [
        body("content")
            .trim()
            .notEmpty()
            .withMessage("Message content cannot be empty")
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          console.warn("Message validation failed", { errors: errors.array() });
          return res.status(400).json({ errors: errors.array() });
        }
        await sendMessage(req, res);
        // Update user activity when sending a message
        updateUserActivity(req.user.id);
      }
  );

  // Get active users
  app.get("/api/users/active", authenticateToken, async (req, res) => {
    await getActiveUsers(req, res);
  });

  // Update typing status
  app.post("/api/users/typing", authenticateToken, async (req, res) => {
    await setUserTyping(req, res);
  });

  // Register user
  app.post(
      "/api/register",
      [
        body("username")
            .isLength({ min: 3 })
            .withMessage("Username must be at least 3 characters long")
            .trim()
            .escape(),
        body("password")
            .isLength({ min: 6 })
            .withMessage("Password must be at least 6 characters long")
            .trim()
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          console.warn("Registration validation failed", { errors: errors.array() });
          return res.status(400).json({ errors: errors.array() });
        }
        await register(req, res);
      }
  );

  // Login user
  app.post(
      "/api/login",
      [
        body("username")
            .trim()
            .escape()
            .notEmpty()
            .withMessage("Username is required"),
        body("password")
            .trim()
            .escape()
            .notEmpty()
            .withMessage("Password is required")
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          console.warn("Login validation failed", { errors: errors.array() });
          return res.status(400).json({ errors: errors.array() });
        }
        await login(req, res);
      }
  );

  // Update username
  app.put(
      "/api/users/username",
      authenticateToken,
      [
        body("username")
            .isLength({ min: 3 })
            .withMessage("Username must be at least 3 characters long")
            .trim()
            .escape()
      ],
      async (req, res) => {
        try {
          const errors = validationResult(req);
          if (!errors.isEmpty()) {
            console.warn("Username update validation failed", { errors: errors.array() });
            return res.status(400).json({ errors: errors.array() });
          }

          const { username } = req.body;
          const userId = req.user.id;

          // Check if username is already taken
          const checkQuery = "SELECT * FROM users WHERE username = ? AND id != ?";
          const existingUsers = await queryDB(db, checkQuery, [username, userId]);

          if (existingUsers.length > 0) {
            console.warn(`Username update failed: Username ${username} already exists`);
            return res.status(400).json({ error: "Username already exists" });
          }

          // Update username
          const updateQuery = "UPDATE users SET username = ? WHERE id = ?";
          await queryDB(db, updateQuery, [username, userId]);

          // Create new token with updated username
          const tokenPayload = {
            id: userId,
            username: username
          };

          const token = jwt.sign(tokenPayload, secretKey, { expiresIn: "1h" });

          console.log(`Username updated successfully for user ID ${userId}`);
          res.json({ token, username, id: userId });
        } catch (err) {
          console.error(`Username update error: ${err.message}`);
          res.status(500).json({ error: "Internal server error" });
        }
      }
  );
};



module.exports = { initializeAPI }
