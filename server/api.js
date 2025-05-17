require('dotenv').config();
const logger = require('../utils/logger');
const { executeSQL } = require('./database');
const { body, validationResult } = require("express-validator");
const { initializeMariaDB, queryDB, insertDB } = require("./database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = process.env.SECRET_KEY || 'fallback-secret-key';
let db;
let io;

/**
 * Formats a JavaScript Date object to a MariaDB compatible datetime string
 * @param {Date} date - The date to format
 * @returns {string} - Formatted date string in 'YYYY-MM-DD HH:MM:SS' format
 */
const formatDateForDB = (date) => {
  return date.toISOString().slice(0, 19).replace('T', ' ');
};


/**
 * Middleware to authenticate JWT tokens from request headers
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {Promise<void>} - Continues to next middleware or returns error response
 */
async function authenticateToken(req, res, next) {
  try {
    const authHeader = req.headers["authorization"];
    if (!authHeader) {
      logger.warn("Authorization header missing");
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      logger.warn("Token not found in authorization header");
      return res.status(401).json({ message: "Unauthorized: Token missing" });
    }

    req.user = await new Promise((resolve, reject) => {
      jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
          logger.error(`Token verification failed: ${err.message}`);
          reject(err);
        } else {
          logger.debug(`Token verified for user: ${decoded.username}`);
          resolve(decoded);
        }
      });
    });

    next();
  } catch (err) {
    logger.error(`Authentication error: ${err.message}`);
    return res.status(403).json({ message: "Forbidden: invalid Token" });
  }
}



// Track active users in memory
const activeUsers = new Map();

/**
 * Socket.io middleware to authenticate connections using JWT tokens
 * @param {Object} socket - Socket.io socket object
 * @param {Function} next - Socket.io next middleware function
 * @returns {void} - Continues to next middleware or returns error
 */
const authenticateSocketToken = (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      logger.warn('Socket.io: No token provided');
      return next(new Error('Authentication required'));
    }

    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        logger.error(`Socket.io: Token verification failed: ${err.message}`);
        return next(new Error('Invalid token'));
      }

      socket.user = decoded;
      logger.info(`Socket.io: User ${decoded.username} authenticated`);

      // Add user to active users map when they connect
      activeUsers.set(decoded.id.toString(), {
        id: decoded.id,
        username: decoded.username,
        socketId: socket.id
      });

      next();
    });
  } catch (error) {
    logger.error(`Socket.io authentication error: ${error.message}`);
    return next(new Error('Socket authentication error'));
  }
};

/**
 * Handles user login authentication and token generation
 * @param {Object} req - Express request object with username and password
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns token or error response
 */
const login = async (req, res) => {
  try {
    const { username, password } = req.body;

    const query = `SELECT * FROM users WHERE username = ?`;
    const users = await queryDB(db, query, [username]);

    if (users.length !== 1) {
      logger.warn(`Login failed for user ${username}: user not found`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const user = users[0];
    // Compare password with bcrypt
    const passwordMatches = await bcrypt.compare(password, user.password);
    if (!passwordMatches) {
      logger.warn(`Login failed for user ${username}: invalid password`);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    logger.info(`User ${username} logged in successfully`);

    // Remove sensitive data
    delete user.password;

    // Create token payload
    const tokenPayload = {
      id: user.id,
      username: user.username
    };

    // Generate signed token (valid for 1 hour)
    const token = jwt.sign(tokenPayload, secretKey, { expiresIn: "1h" });
    res.json({ token, username: user.username, id: user.id });
  } catch (err) {
    logger.error(`Login error for user ${req.body.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};


/**
 * Handles new user registration with password hashing
 * @param {Object} req - Express request object with username and password
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns success or error response
 */
const register = async (req, res) => {
  try {
    const { username, password } = req.body;

    // Manual validation check - should not be needed with express-validator but adding as a safeguard
    if (!username || username.length < 3) {
      logger.warn(`Registration validation failed: Username must be at least 3 characters long`);
      return res.status(400).json({ error: "Username must be at least 3 characters long" });
    }

    if (!password || password.length < 6) {
      logger.warn(`Registration validation failed: Password must be at least 6 characters long`);
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Check if user already exists
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    const existingUsers = await queryDB(db, checkQuery, [username]);

    if (existingUsers && existingUsers.length > 0) {
      logger.warn(`Registration failed: User ${username} already exists`);
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database
    const insertQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
    await insertDB(db, insertQuery, [username, hashedPassword]);

    logger.info(`New user registered: ${username}`);
    res.json({ status: "registered" });
  } catch (error) {
    if (error.code === 'SQLITE_CONSTRAINT' || error.code === 'ER_DUP_ENTRY') {
      logger.warn(`Registration failed (constraint): User ${req.body.username} already exists`);
      return res.status(400).json({ error: "User already exists" });
    }

    logger.error(`Registration error for user ${req.body.username}: ${error.message}`);
    return res.status(500).json({ error: "Internal Server Error" });
  }
};

/**
 * Retrieves chat messages from the database
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns messages or error response
 */
const getMessages = async (req, res) => {
  try {
    // Load all messages from the chat
    const query = `
      SELECT messages.id, messages.content, messages.timestamp, users.username as sender
      FROM messages
             JOIN users ON messages.sender_id = users.id
      ORDER BY messages.timestamp ASC
        LIMIT 100
    `;

    const messages = await queryDB(db, query);
    logger.debug(`Retrieved ${messages.length} messages for user ${req.user.username}`);

    res.json(messages);
  } catch (err) {
    logger.error(`Error fetching messages for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

/**
 * Saves a new message to the database and broadcasts to all connected clients
 * @param {Object} req - Express request object with message content
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns success or error response
 */
const sendMessage = async (req, res) => {
  try {
    const { content } = req.body;
    if (!content || content.trim() === "") {
      logger.warn("Message sending failed: Message content is required");
      return res.status(400).json({ error: "Message content is required" });
    }

    // Get user ID from token
    const userId = req.user.id;
    const now = new Date();
    
    // Format for DB: YYYY-MM-DD HH:MM:SS
    const dbTimestamp = formatDateForDB(now);

    // For client response we can use ISO format
    const isoTimestamp = now.toISOString();

    // Insert message into database
    const query = "INSERT INTO messages (sender_id, content, timestamp) VALUES (?, ?, ?)";
    const result = await insertDB(db, query, [userId, content, dbTimestamp]);

    // Send message to all connected clients
    // Convert any BigInt values to regular numbers
    const insertId = typeof result.insertId === 'bigint' ? Number(result.insertId) : result.insertId;

    const messageData = {
      id: insertId,
      sender_id: Number(userId),
      sender: req.user.username,
      content: content,
      timestamp: isoTimestamp  // Use ISO format for client display
    };

    logger.info(`New message from ${req.user.username}: ${content.substring(0, 30)}${content.length > 30 ? '...' : ''}`);

    // Broadcast to all clients via Socket.io
    io.emit('new_message', messageData);

    res.json({ status: "ok", message: messageData });
  } catch (err) {
    logger.error(`Error sending message for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};

/**
 * Retrieves list of currently active users
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns active users or error response
 */
const getActiveUsers = async (req, res) => {
  try {
    // Get active users from memory instead of database
    const currentActiveUsers = Array.from(activeUsers.values());
    logger.debug(`Retrieved ${currentActiveUsers.length} active users`);
    res.json(currentActiveUsers);
  } catch (err) {
    logger.error(`Error fetching active users for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

/**
 * Updates and broadcasts a user's typing status
 * @param {Object} req - Express request object with isTyping status
 * @param {Object} res - Express response object
 * @returns {Promise<void>} - Returns success or error response
 */
const setUserTyping = async (req, res) => {
  try {
    const { isTyping } = req.body;
    const userId = req.user.id;
    const username = req.user.username;

    logger.debug(`User ${username} typing status: ${isTyping}`);

    // Broadcast to all clients that user is typing
    io.emit('user_typing', { userId, username, isTyping });

    res.json({ status: "ok" });
  } catch (err) {
    logger.error(`Error updating typing status for user ${req.user.username}: ${err.message}`);
    res.status(500).json({ error: "Internal server error" });
  }
};


/**
 * Initializes API routes, database connection, and Socket.io server
 * @param {Object} app - Express application instance
 * @param {Object} server - HTTP server instance
 * @returns {Promise<void>} - Initializes API and Socket.io handlers
 */
const initializeAPI = async (app, server) => {
  // Initialize database
  try {
    logger.info('Initializing API and database connection');
    db = await initializeMariaDB();
  } catch (error) {
    logger.error(`Failed to initialize database: ${error.message}`);
    throw error;
  }

  // Initialize Socket.io
  io = require('socket.io')(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
  });
  logger.info('Socket.io server initialized');

  // Socket.io authentication middleware
  io.use(authenticateSocketToken);

  // Helper function to broadcast active users
  const broadcastActiveUsers = () => {
    const activeUsersList = Array.from(activeUsers.values());
    io.emit('active_users_updated', activeUsersList);
  };

  // Socket.io connection handling
  io.on('connection', (socket) => {
    logger.info(`Socket connected: ${socket.user.username} (ID: ${socket.user.id})`);

    // Broadcast updated active users list
    broadcastActiveUsers();

    // Handle user typing events
    socket.on('user_typing', (data) => {
      // Broadcast typing status to all clients except sender
      socket.broadcast.emit('user_typing', {
        userId: socket.user.id,
        username: socket.user.username,
        isTyping: data.isTyping
      });
    });

    // Handle disconnect
    socket.on('disconnect', () => {
      const userId = socket.user.id;
      logger.info(`Socket disconnected: ${socket.user.username} (ID: ${userId})`);

      // Remove user from active users map
      activeUsers.delete(userId.toString());

      // Broadcast that user is no longer typing
      socket.broadcast.emit('user_typing', {
        userId: userId,
        username: socket.user.username,
        isTyping: false
      });

      // Broadcast updated active users list after user disconnects
      broadcastActiveUsers();
    });
  });

  // API Routes
  logger.info('Setting up API routes');

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
          logger.warn("Message validation failed", { errors: errors.array() });
          return res.status(400).json({ errors: errors.array() });
        }
        await sendMessage(req, res);
        // Active users are tracked via socket connections, no need to update here
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
            .notEmpty()
            .withMessage("Username is required")
            .isLength({ min: 3 })
            .withMessage("Username must be at least 3 characters long")
            .trim(),
        body("password")
            .notEmpty()
            .withMessage("Password is required")
            .isLength({ min: 6 })
            .withMessage("Password must be at least 6 characters long")
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          logger.warn("Registration validation failed", { errors: errors.array() });

          // Return the first error message for simplicity
          const firstError = errors.array()[0];
          return res.status(400).json({ error: firstError.msg });
        }
        await register(req, res);
      }
  );

  // Login user
  app.post(
      "/api/login",
      [
        body("username")
            .notEmpty()
            .withMessage("Username is required")
            .trim(),
        body("password")
            .notEmpty()
            .withMessage("Password is required")
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          logger.warn("Login validation failed", { errors: errors.array() });

          // Return the first error message for simplicity
          const firstError = errors.array()[0];
          return res.status(400).json({ error: firstError.msg });
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
            logger.warn("Username update validation failed", { errors: errors.array() });
            return res.status(400).json({ errors: errors.array() });
          }

          const { username } = req.body;
          const userId = req.user.id;

          // Check if username is already taken
          const checkQuery = "SELECT * FROM users WHERE username = ? AND id != ?";
          const existingUsers = await queryDB(db, checkQuery, [username, userId]);

          if (existingUsers.length > 0) {
            logger.warn(`Username update failed: Username ${username} already exists`);
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

          // Get old username from active users map if available
          const oldUsername = activeUsers.get(userId.toString())?.username || '';

          logger.info(`Username changed: ${oldUsername} -> ${username}`);

          // Update username in active users map
          if (activeUsers.has(userId.toString())) {
            const userData = activeUsers.get(userId.toString());
            userData.username = username;
            activeUsers.set(userId.toString(), userData);
          }

          // Broadcast username change to all clients
          io.emit('username_updated', {
            userId: userId,
            oldUsername: oldUsername,
            newUsername: username
          });

          res.json({ token, username, id: userId });
        } catch (err) {
          logger.error(`Username update error: ${err.message}`);
          res.status(500).json({ error: "Internal server error" });
        }
      }
  );

  logger.info('API initialization complete');
};

module.exports = { initializeAPI }
