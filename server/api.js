require('dotenv').config();
const { executeSQL } = require('./database');
const { body, validationResult } = require("express-validator");
const { initializeMariaDB, queryDB, insertDB } = require("./database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = process.env.SECRET_KEY || 'fallback-secret-key';
let db;
let io;

// Helper function to format datetime for MariaDB
const formatDateForDB = (date) => {
  return date.toISOString().slice(0, 19).replace('T', ' ');
};


// Middleware for token authentication with logging
async function authenticateToken(req, res, next) {
  try {
    console.log(`Authenticating token for ${req.method} ${req.originalUrl}`);
    console.log(`Using secret key: ${secretKey.substring(0, 3)}...`);
    
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
    
    console.log(`Token to verify: ${token.substring(0, 10)}...`);
    
    req.user = await new Promise((resolve, reject) => {
      jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
          console.error(`Token verification failed: ${err.message}`);
          reject(err);
        } else {
          console.log(`Token decoded successfully: ${JSON.stringify(decoded)}`);
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



// Track active users in memory
const activeUsers = new Map();

// Socket.io Authentication
const authenticateSocketToken = (socket, next) => {
  console.log('Socket.io: authenticating connection...');
  
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      console.error('Socket.io: No token provided');
      return next(new Error('Authentication required'));
    }
    
    console.log(`Socket.io: Token received: ${token.substring(0, 10)}...`);
    console.log(`Socket.io: Using secret key: ${secretKey.substring(0, 3)}...`);
    
    jwt.verify(token, secretKey, (err, decoded) => {
      if (err) {
        console.error(`Socket.io: Token verification failed: ${err.message}`);
        return next(new Error('Invalid token'));
      }
      
      console.log(`Socket.io: Token verified for user: ${decoded.username}`);
      socket.user = decoded;
      
      // Add user to active users map when they connect
      activeUsers.set(decoded.id.toString(), {
        id: decoded.id,
        username: decoded.username,
        socketId: socket.id
      });
      
      next();
    });
  } catch (error) {
    console.error('Socket.io authentication error:', error);
    return next(new Error('Socket authentication error'));
  }
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

    // Manual validation check - should not be needed with express-validator but adding as a safeguard
    if (!username || username.length < 3) {
      console.warn(`Registration validation failed: Username must be at least 3 characters long`);
      return res.status(400).json({ error: "Username must be at least 3 characters long" });
    }

    if (!password || password.length < 6) {
      console.warn(`Registration validation failed: Password must be at least 6 characters long`);
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Log the actual values being validated
    console.log(`Validating username: "${username}" (length: ${username.length})`);
    console.log(`Validating password length: ${password.length}`);

    // Check if user already exists
    const checkQuery = "SELECT * FROM users WHERE username = ?";
    const existingUsers = await queryDB(db, checkQuery, [username]);

    if (existingUsers && existingUsers.length > 0) {
      console.warn(`Registration failed: User ${username} already exists`);
      return res.status(400).json({ error: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(`Password hashed successfully`);

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

    // Get active users from memory instead of database
    const currentActiveUsers = Array.from(activeUsers.values());
    
    console.log(`Active users (${currentActiveUsers.length}) fetched successfully for user: ${req.user.username}`);
    res.json(currentActiveUsers);
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


const initializeAPI = async (app, server) => {
  // Initialize database
  try {
    db = await initializeMariaDB();
    console.log("Database connection initialized successfully");
  } catch (error) {
    console.error("Failed to initialize database:", error);
    throw error;
  }

  // Initialize Socket.io
  console.log("Initializing Socket.io server");
  io = require('socket.io')(server, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
  });
  console.log("Socket.io server initialized");

  // Socket.io authentication middleware
  io.use(authenticateSocketToken);

  // Helper function to broadcast active users
  const broadcastActiveUsers = () => {
    const activeUsersList = Array.from(activeUsers.values());
    console.log(`Broadcasting ${activeUsersList.length} active users`);
    io.emit('active_users_updated', activeUsersList);
  };

  // Socket.io connection handling
  io.on('connection', (socket) => {
    console.log(`User ${socket.user.username} connected`);

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
      console.log(`User ${socket.user.username} disconnected`);
      const userId = socket.user.id;
      
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
          console.warn("Registration validation failed", { errors: errors.array() });
          
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
          console.warn("Login validation failed", { errors: errors.array() });
          
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
