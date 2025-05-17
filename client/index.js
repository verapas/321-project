/**
 * Initializes the chat application
 * @description Sets up event listeners, socket connection, and UI components
 */
document.addEventListener("DOMContentLoaded", () => {
    // DOM elements
    const messageInput = document.getElementById("message-input");
    const sendMessageButton = document.getElementById("send-message");
    const messagesContainer = document.getElementById("messages-container");
    const activeUsersContainer = document.getElementById("active-users");
    const logoutButton = document.getElementById("logout");
    const usernameDisplay = document.getElementById("username-display");
    const editUsernameButton = document.getElementById("edit-username");
    const usernameModal = document.getElementById("username-modal");
    const newUsernameInput = document.getElementById("new-username");
    const saveUsernameButton = document.getElementById("save-username");
    const cancelUsernameButton = document.getElementById("cancel-username");
    const usernameError = document.getElementById("username-error");
    const typingIndicatorsContainer = document.getElementById("typing-indicators-container");
    
    // Track users who are currently typing
    const typingUsers = new Map();
    
    // Initially hide the typing indicators container
    typingIndicatorsContainer.classList.add('hidden');

    // Load user from local storage
    const user = JSON.parse(localStorage.getItem("user"));
    if (!user || !user.token) {
        window.location.href = "/login.html";
        return;
    }

    // Display username
    usernameDisplay.textContent = user.username;

    // Socket.io connection
    const socket = io({
        auth: {
            token: user.token
        }
    });

    // Typing state
    let isTyping = false;
    let typingTimeout = null;

    /**
     * Generates HTML for a chat message
     * @param {Object} message - Message object with sender, content, and timestamp
     * @returns {string} - HTML string for the message
     */
    const generateMessage = (message) => {
        const date = new Date(message.timestamp).toLocaleDateString("de-CH", {
            hour: "numeric",
            minute: "numeric",
        });

        const isCurrentUser = message.sender === user.username;
        const alignmentClass = isCurrentUser ? "self-end" : "self-start";
        const bgColorClass = isCurrentUser ? "bg-blue-600" : "bg-slate-600";

        return `
      <div class="flex flex-col ${alignmentClass} max-w-[70%]">
        <div class="${bgColorClass} rounded-lg p-3 break-words">
          ${isCurrentUser ? '' : `<div class="font-semibold text-blue-300">${message.sender}</div>`}
          <p>${escapeHtml(message.content)}</p>
        </div>
        <span class="text-xs text-gray-400 mt-1 ${isCurrentUser ? 'text-right' : ''}">${date}</span>
      </div>
    `;
    };

    /**
     * Generates HTML for an active user in the sidebar
     * @param {Object} activeUser - User object with username
     * @returns {string} - HTML string for the active user
     */
    const generateActiveUser = (activeUser) => {
        const isCurrentUser = activeUser.username === user.username;
        return `
      <div class="flex items-center gap-2 p-2 ${isCurrentUser ? 'bg-slate-600' : 'hover:bg-slate-600'} rounded">
        <div class="w-2 h-2 rounded-full bg-green-500"></div>
        <span class="${isCurrentUser ? 'font-semibold' : ''}">${escapeHtml(activeUser.username)}</span>
        ${isCurrentUser ? ' (You)' : ''}
      </div>
    `;
    };

    /**
     * Escapes HTML special characters to prevent XSS attacks
     * @param {string} unsafe - Raw string that might contain HTML
     * @returns {string} - Escaped safe HTML string
     */
    const escapeHtml = (unsafe) => {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    /**
     * Fetches chat history from the server
     * @returns {Promise<void>} - Retrieves and displays message history
     */
    const getMessages = async () => {
        try {
            const response = await fetch("/api/messages", {
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${user.token}`
                }
            });

            if (response.ok) {
                const messages = await response.json();
                if (Array.isArray(messages)) {
                    console.log(`Loaded ${messages.length} messages`);
                    messagesContainer.innerHTML = messages.map(generateMessage).join("");
                    // Scroll to bottom
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                }
            }
        } catch (err) {
            console.error("Error fetching messages:", err);
        }
    };

    /**
     * Fetches active users list from the server
     * @returns {Promise<void>} - Retrieves and displays active users
     */
    const getActiveUsers = async () => {
        try {
            const response = await fetch("/api/users/active", {
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${user.token}`
                }
            });

            if (response.ok) {
                const activeUsers = await response.json();
                if (Array.isArray(activeUsers)) {
                    activeUsersContainer.innerHTML = activeUsers.map(generateActiveUser).join("");
                } else {
                    console.error("Active users is not an array:", activeUsers);
                }
            } else {
                console.error("Error fetching active users:", response.statusText);
            }
        } catch (err) {
            console.error("Error in getActiveUsers:", err);
        }
    };

    /**
     * Sends a new message to the server
     * @returns {Promise<void>} - Sends message and resets input field
     */
    const sendMessage = async () => {
        const content = messageInput.value.trim();
        if (!content) return; // Avoid empty messages

        try {
            const response = await fetch("/api/messages", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${user.token}`
                },
                body: JSON.stringify({ content }),
            });

            if (response.ok) {
                messageInput.value = "";
                
                // Reset typing state since the input is now empty
                if (isTyping) {
                    isTyping = false;
                    socket.emit('user_typing', { isTyping });
                }
            } else {
                console.error("Error sending message:", response.statusText);
            }
        } catch (err) {
            console.error("Error in sendMessage:", err);
        }
    };

    /**
     * Updates the user's username
     * @returns {Promise<void>} - Updates username and reconnects socket
     */
    const updateUsername = async () => {
        const newUsername = newUsernameInput.value.trim();
        usernameError.textContent = "";

        if (!newUsername) {
            usernameError.textContent = "Username cannot be empty";
            return;
        }

        if (newUsername === user.username) {
            usernameModal.classList.add("hidden");
            return;
        }

        try {
            const response = await fetch("/api/users/username", {
                method: "PUT",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${user.token}`
                },
                body: JSON.stringify({ username: newUsername }),
            });

            if (response.ok) {
                const data = await response.json();
                // Update local storage with new token and username
                user.token = data.token;
                user.username = data.username;
                localStorage.setItem("user", JSON.stringify(user));

                // Update display
                usernameDisplay.textContent = user.username;
                usernameModal.classList.add("hidden");

                // Reconnect socket with new token
                socket.disconnect();
                socket.auth.token = user.token;
                socket.connect();
            } else {
                const data = await response.json();
                usernameError.textContent = data.error || "Failed to update username";
            }
        } catch (err) {
            console.error("Error updating username:", err);
            usernameError.textContent = "Connection error";
        }
    };

    /**
     * Updates the typing indicators display
     * @description Shows who is currently typing based on typingUsers map
     */
    const updateTypingIndicators = () => {
        // Clear the container
        typingIndicatorsContainer.innerHTML = '';
        
        // If no one is typing, hide the container
        if (typingUsers.size === 0) {
            typingIndicatorsContainer.classList.add('hidden');
            return;
        }
        
        // Show the container
        typingIndicatorsContainer.classList.remove('hidden');
        
        // Create the typing message based on who is typing
        const typingUsersList = Array.from(typingUsers.values());
        
        if (typingUsersList.length === 1) {
            // One user typing
            typingIndicatorsContainer.textContent = `${typingUsersList[0]} is typing...`;
        } else if (typingUsersList.length === 2) {
            // Two users typing
            typingIndicatorsContainer.textContent = `${typingUsersList[0]} and ${typingUsersList[1]} are typing...`;
        } else if (typingUsersList.length === 3) {
            // Three users typing
            typingIndicatorsContainer.textContent = `${typingUsersList[0]}, ${typingUsersList[1]}, and ${typingUsersList[2]} are typing...`;
        } else {
            // More than three users typing
            typingIndicatorsContainer.textContent = `${typingUsersList.length} people are typing...`;
        }
    };

    /**
     * Handles user typing events
     * @description Detects typing state changes and emits events to server
     */
    const handleTyping = () => {
        // Check if the input field has content
        const hasContent = messageInput.value.trim() !== '';
        
        // Only emit a typing event when the state changes
        if (hasContent !== isTyping) {
            isTyping = hasContent;
            socket.emit('user_typing', { isTyping });
        }
    };

    // Event listeners
    sendMessageButton.addEventListener("click", sendMessage);

    messageInput.addEventListener("input", handleTyping);
    
    messageInput.addEventListener("keyup", (event) => {
        if (event.key === "Enter") {
            sendMessage();
        }
    });

    logoutButton.addEventListener("click", () => {
        localStorage.removeItem("user");
        socket.disconnect();
        window.location.href = "/login.html";
    });

    editUsernameButton.addEventListener("click", () => {
        newUsernameInput.value = user.username;
        usernameError.textContent = "";
        usernameModal.classList.remove("hidden");
    });

    saveUsernameButton.addEventListener("click", updateUsername);

    cancelUsernameButton.addEventListener("click", () => {
        usernameModal.classList.add("hidden");
    });

    // Close modal when clicking outside
    usernameModal.addEventListener("click", (event) => {
        if (event.target === usernameModal) {
            usernameModal.classList.add("hidden");
        }
    });

    // Socket.io event handlers
    socket.on('connect', () => {
        console.log('Connected to server');
        getMessages();
        getActiveUsers();
    });

    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        if (error.message.includes('authentication')) {
            // Token might be expired
            localStorage.removeItem("user");
            window.location.href = "/login.html";
        }
    });

    socket.on('new_message', (message) => {
        // Add new message to container
        messagesContainer.innerHTML += generateMessage(message);
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    });

    socket.on('active_users_updated', (activeUsers) => {
        activeUsersContainer.innerHTML = activeUsers.map(generateActiveUser).join("");
    });

    socket.on('username_updated', (data) => {
        // Update the username in all messages in the chat history
        const messageElements = messagesContainer.querySelectorAll('.flex.flex-col');
        
        messageElements.forEach(messageElement => {
            // Find the username display in the message
            const usernameElement = messageElement.querySelector('.font-semibold.text-blue-300');
            
            // Only update if this message has a username element and it matches the old username
            if (usernameElement && usernameElement.textContent === data.oldUsername) {
                usernameElement.textContent = data.newUsername;
            }
        });
    });

    socket.on('user_typing', (data) => {
        // Ignore our own typing events
        if (data.userId.toString() === user.id.toString()) {
            return;
        }
        
        // Add or remove user from typing users map
        if (data.isTyping) {
            // Add this user to the typing users map
            typingUsers.set(data.userId.toString(), data.username);
        } else {
            // Remove this user from the typing users map
            typingUsers.delete(data.userId.toString());
        }
        
        // Update the typing indicators display
        updateTypingIndicators();
    });

    // Initial data load
    if (!socket.connected) {
        getMessages();
        getActiveUsers();
    }
});
