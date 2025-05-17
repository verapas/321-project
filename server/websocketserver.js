const logger = require('../utils/logger')
const WebSocket = require('ws')

const clients = []

/**
 * Initializes the websocket server.
 * @example
 * initializeWebsocketServer(server);
 * @param {Object} server - The http server object.
 * @returns {void}
 */
const initializeWebsocketServer = (server) => {
  const websocketServer = new WebSocket.Server({ server })
  logger.info('WebSocket server initialized')
  websocketServer.on('connection', onConnection)
}

/**
 * Handles a new websocket connection.
 * @example
 * onConnection(ws);
 * @param {Object} ws - The websocket object.
 * @returns {void}
 */
const onConnection = (ws) => {
  logger.info('New WebSocket client connected')
  ws.on('message', (message) => onMessage(ws, message))
}

/**
 * Handles a new message from a websocket connection.
 * @example
 * onMessage(ws, messageBuffer);
 * @param {Object} ws - The websocket object.
 * @param {Buffer} messageBuffer - The message buffer. IMPORTANT: Needs to be converted to a string or JSON object first.
 */
const onMessage = (ws, messageBuffer) => {
  const messageString = messageBuffer.toString()
  const message = JSON.parse(messageString)
  // The message type is checked and the appropriate action is taken
  switch (message.type) {
    case 'user': {
      logger.info(`User connected: ${message.user.name}`)
      clients.push({ ws, user: message.user })
      const usersMessage = {
        type: 'users',
        users: clients.map((client) => client.user),
      }
      clients.forEach((client) => {
        client.ws.send(JSON.stringify(usersMessage))
      })
      ws.on('close', () => onDisconnect(ws))
      break
    }
    case 'message': {
      logger.info(`New message received: ${message.text}`)
      clients.forEach((client) => {
        client.ws.send(messageString)
      })
      break
    }
    default: {
      logger.warn(`Unknown message type: ${message.type}`)
    }
  }
}

/**
 * Handles a websocket disconnect. All other clients are notified about the disconnect.
 * @example
 * onDisconnect(ws);
 * @param {Object} ws - The websocket object.
 * @returns {void}
 */
const onDisconnect = (ws) => {
  const index = clients.findIndex((client) => client.ws === ws)
  logger.info(`Client disconnected`)
  clients.splice(index, 1)
  const usersMessage = {
    type: 'users',
    users: clients.map((client) => client.user),
  }
  clients.forEach((client) => {
    client.ws.send(JSON.stringify(usersMessage))
  })
}

module.exports = { initializeWebsocketServer }
