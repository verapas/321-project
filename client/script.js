// The websocket object is created by the browser and is used to connect to the server.
// Think about it when the backend is not running on the same server as the frontend
// replace localhost with the server's IP address or domain name.
const socket = new WebSocket('ws://localhost:3000')

/**
 * Handles WebSocket connection open event
 * @param {Event} event - WebSocket open event
 * @description Sends initial user information to the server
 */
socket.addEventListener('open', (event) => {
  // Send a dummy user to the backend
  const user = { id: 1, name: 'John Doe' }
  const message = {
    type: 'user',
    user,
  }
  socket.send(JSON.stringify(message))
})

/**
 * Creates and appends a new message element to the DOM
 * @param {string} message - Message text to display
 * @returns {void} - Appends message to the messages container
 */
const createMessage = (message) => {
  const p = document.createElement('p')
  p.textContent = message
  document.getElementById('messages').appendChild(p)
}

/**
 * Handles incoming messages from the server
 * @param {MessageEvent} event - WebSocket message event
 * @description Displays received messages in the UI
 */
socket.addEventListener('message', (event) => {
  createMessage(event.data)
})

/**
 * Handles WebSocket connection close event
 * @param {CloseEvent} event - WebSocket close event
 * @description Logs when the connection is closed
 */
socket.addEventListener('close', (event) => {
  console.log('WebSocket closed.')
})

/**
 * Handles WebSocket connection errors
 * @param {Event} event - WebSocket error event
 * @description Logs any connection errors to the console
 */
socket.addEventListener('error', (event) => {
  console.error('WebSocket error:', event)
})

/**
 * Initializes DOM event listeners when the page loads
 * @description Sets up click handler for the send button
 */
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('btnSendHello').addEventListener('click', () => {
    const message = {
      type: 'message',
      text: 'Hello, server!',
    }
    socket.send(JSON.stringify(message))
  })
})
