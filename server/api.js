const { executeSQL } = require('./database')

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

module.exports = { initializeAPI }
