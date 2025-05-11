let pool = null

/**
 * Initializes the MariaDB connection pool.
 * The connection pool is used to execute SQL queries.
 * The connection pool is created with the following parameters:
 * - database: The name of the database to connect to. (process.env.DB_NAME)
 * - host: The host of the database. (process.env.DB_HOST)
 * - user: The user to connect to the database. (process.env.DB_USER)
 * - password: The password to connect to the database. (process.env.DB_PASSWORD)
 * - connectionLimit: The maximum number of connections in the pool. (5)
 * @example
 * initializeMariaDB();
 * @returns {void}
 * @see {@link https://mariadb.com/kb/en/mariadb-connector-nodejs-pooling/}
 */
const initializeMariaDB = async () => {
  console.log('Initializing MariaDB')
  const mariadb = require('mariadb')
  
  try {
    pool = mariadb.createPool({
      database: process.env.DB_NAME || 'mychat',
      host: process.env.DB_HOST || 'localhost',
      user: process.env.DB_USER || 'mychat',
      password: process.env.DB_PASSWORD || 'mychatpassword',
      connectionLimit: 5,
    });
    
    // Test the connection
    const conn = await pool.getConnection();
    console.log('Successfully connected to MariaDB');
    conn.release();
    
    console.log('MariaDB initialized successfully');
    return pool;
  } catch (error) {
    console.error('Error initializing MariaDB:', error);
    throw error;
  }
}

/**
 * Allows the execution of SQL queries.
 * @example
 * // Insert statement with a parameter. Can be multiple in an array format like ["Patrick", 1]
 * executeSQL("INSERT INTO users value (?)", ["Patrick"]);
 * @example
 * // Select statement without parameters.
 * executeSQL("SELECT * FROM users;");
 * @returns {Promise<Array>} Returns the result of the query.
 */
const executeSQL = async (query, params) => {
  let conn
  try {
    if (!pool) {
      throw new Error('Database pool is not initialized');
    }
    
    conn = await pool.getConnection();
    const res = await conn.query(query, params);
    return res;
  } catch (err) {
    console.error(`SQL execution error: ${err.message}`);
    throw err;
  } finally {
    if (conn) conn.release();
  }
}

/**
 * Initializes the database schema.
 * Creates the tables if they do not exist.
 * Useful for the first time setup.
 */
const initializeDBSchema = async () => {
  console.log('Initializing database schema')
  
  // Create users table with username and password fields
  const userTableQuery = `CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    PRIMARY KEY (id)
  );`
  await executeSQL(userTableQuery)
  
  // Create messages table
  const messageTableQuery = `CREATE TABLE IF NOT EXISTS messages (
    id INT NOT NULL AUTO_INCREMENT,
    sender_id INT NOT NULL,
    content TEXT NOT NULL,
    timestamp DATETIME NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
  );`
  await executeSQL(messageTableQuery)
  
  // Create active_users table
  const activeUsersTableQuery = `CREATE TABLE IF NOT EXISTS active_users (
    id INT NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    last_active DATETIME NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (user_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );`
  await executeSQL(activeUsersTableQuery)
  
  console.log('Database schema initialized')
}

/**
 * Execute a query on the database
 * @param {Object} db - Database connection pool
 * @param {string} query - SQL query to execute
 * @param {Array} params - Parameters for the query
 * @returns {Promise<Array>} - Query results
 */
const queryDB = async (db, query, params = []) => {
  let conn;
  try {
    conn = await db.getConnection();
    const results = await conn.query(query, params);
    return results;
  } catch (error) {
    console.error(`Database query error: ${error.message}`);
    throw error;
  } finally {
    if (conn) conn.release();
  }
};

/**
 * Insert data into the database
 * @param {Object} db - Database connection pool
 * @param {string} query - SQL query to execute
 * @param {Array} params - Parameters for the query
 * @returns {Promise<Object>} - Insert result with insertId
 */
const insertDB = async (db, query, params = []) => {
  let conn;
  try {
    conn = await db.getConnection();
    const result = await conn.query(query, params);
    return result;
  } catch (error) {
    console.error(`Database insert error: ${error.message}`);
    throw error;
  } finally {
    if (conn) conn.release();
  }
};

module.exports = { 
  executeSQL, 
  initializeMariaDB, 
  initializeDBSchema,
  queryDB,
  insertDB 
}
