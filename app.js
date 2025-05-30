require('dotenv').config();
const express = require('express')
const http = require('http')
var livereload = require('livereload')
var connectLiveReload = require('connect-livereload')
const { initializeWebsocketServer } = require('./server/websocketserver')
const { initializeAPI } = require('./server/api')
const { initializeMariaDB, initializeDBSchema } = require('./server/database')

// Create the express server
const app = express()
const server = http.createServer(app)

// Parse JSON request bodies
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

// create a livereload server
// ONLY FOR DEVELOPMENT important to remove in production
// by set the NODE_ENV to production
const env = process.env.NODE_ENV || 'development'
if (env !== 'production') {
  const liveReloadServer = livereload.createServer()
  liveReloadServer.server.once('connection', () => {
    setTimeout(() => {
      liveReloadServer.refresh('/')
    }, 100)
  })
  // use livereload middleware
  app.use(connectLiveReload())
}

// deliver static files from the client folder like css, js, images
app.use(express.static('client'))

// redirect to login when accessing webpage
app.get("/", (req, res) => {
  res.redirect("/login.html");
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/client/login.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/client/register.html");
});
// Allowing top-level await
;(async function () {
  try {
    // Initialize the database first
    const dbPool = await initializeMariaDB();
    
    await initializeDBSchema();
    
    // Initialize the REST api AFTER database is ready
    await initializeAPI(app, server);
    
    // Start the web server
    const serverPort = process.env.PORT || 3000;
    server.listen(serverPort, () => {
      // Server started
    });
  } catch (error) {
    process.exit(1);
  }
})()
