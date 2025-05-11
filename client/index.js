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
    const typingIndicator = document.getElementById("typing-indicator");

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

    // Generate message HTML
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

    // Generate active user HTML
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

    // Escape HTML to prevent XSS
    const escapeHtml = (unsafe) => {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    // Fetch messages
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
                    messagesContainer.innerHTML = messages.map(generateMessage).join("");
                    // Scroll to bottom
                    messagesContainer.scrollTop = messagesContainer.scrollHeight;
                } else {
                    console.error("Messages is not an array:", messages);
                }
            } else {
                console.error("Error fetching messages:", response.statusText);
            }
        } catch (err) {
            console.error("Error in getMessages:", err);
        }
    };

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

    // Send message
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
                // Reset typing state
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

    // Update username
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

    const handleTyping = () => {
        if (!isTyping) {
            isTyping = true;
            socket.emit('user_typing', { isTyping });
        }

        // Reset timeout
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(() => {
            isTyping = false;
            socket.emit('user_typing', { isTyping });
        }, 2000);
    };

    // Event listeners
    sendMessageButton.addEventListener("click", sendMessage);

    messageInput.addEventListener("keyup", (event) => {
        if (event.key === "Enter") {
            sendMessage();
        } else {
            handleTyping();
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

    socket.on('user_typing', (data) => {
        if (data.userId !== user.id) {
            if (data.isTyping) {
                typingIndicator.textContent = `${data.username} is typing...`;
                typingIndicator.classList.remove("hidden");
            } else {
                typingIndicator.classList.add("hidden");
            }
        }
    });

    // Initial data load
    if (!socket.connected) {
        getMessages();
        getActiveUsers();
    }
});
