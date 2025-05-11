const { executeSQL } = require('./database')
require('dotenv').config();
const { body, validationResult } = require("express-validator");
const { initializeDatabase, queryDB, insertDB } = require("./database");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const secretKey = process.env.SECRET_KEY || 'fallback-secret-key';
let db;
let io;

/**
 * Initializes the API endpoints.
 * @example
 * initializeAPI(app);
 * @param {Object} app - The express app object.
 * @returns {void}
 */
const initializeAPI = (app) => {
  console.log('Initializing API')
  // default REST api endpoint
  app.get('/api/hello', hello)
  app.get('/api/users', users)
  console.log('API initialized')
}

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


module.exports = { initializeAPI }
