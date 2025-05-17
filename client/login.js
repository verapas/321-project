/**
 * Initializes the login page functionality
 * @description Sets up event listeners and form validation for user login
 */
/**
 * Initializes the login page functionality
 * @description Sets up event listeners and form validation for user login
 */
document.addEventListener("DOMContentLoaded", () => {
    console.log("Login page loaded");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const loginButton = document.getElementById("login");
    const errorText = document.getElementById("error");

    // Check if user is already logged in
    const storedUser = localStorage.getItem("user");
    if (storedUser) {
        try {
            const userData = JSON.parse(storedUser);
            if (userData.token) {
                console.log("User already logged in, redirecting to chat");
                window.location.href = "/";
                return;
            }
        } catch (e) {
            console.warn("Invalid user data in localStorage, clearing");
            localStorage.removeItem("user");
        }
    }

    // Handle Enter key press
    const handleEnterKey = (event) => {
        if (event.key === "Enter") {
            loginButton.click();
        }
    };

    usernameInput.addEventListener("keyup", handleEnterKey);
    passwordInput.addEventListener("keyup", handleEnterKey);

    // Handle login button click
    loginButton.addEventListener("click", async () => {
        console.log("Login attempt started");
        // Clear previous error
        errorText.innerText = "";

        // Validate inputs
        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username) {
            console.warn("Login validation failed: Username is required");
            errorText.innerText = "Username is required";
            return;
        }

        if (!password) {
            console.warn("Login validation failed: Password is required");
            errorText.innerText = "Password is required";
            return;
        }

        // Disable button during login attempt
        loginButton.disabled = true;
        loginButton.innerText = "Logging in...";

        try {
            console.log(`Attempting to login user: ${username}`);
            const response = await fetch("/api/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (data?.token) {
                console.log("Login successful");
                localStorage.setItem("user", JSON.stringify(data));
                window.location.href = "/";
            } else if (data?.error) {
                console.warn(`Login failed: ${data.error}`);
                errorText.innerText = data.error;
            } else {
                console.warn("Login failed: Unknown error");
                errorText.innerText = "Unknown error occurred";
            }
        } catch (error) {
            console.error("Login error:", error);
            errorText.innerText = "Connection error. Please try again.";
        } finally {
            // Re-enable button
            loginButton.disabled = false;
            loginButton.innerText = "Login";
        }
    });
});
