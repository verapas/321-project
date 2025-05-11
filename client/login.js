document.addEventListener("DOMContentLoaded", () => {
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
                // Redirect to chat page if already logged in
                window.location.href = "/";
                return;
            }
        } catch (e) {
            // Invalid stored data, clear it
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
        // Clear previous error
        errorText.innerText = "";

        // Validate inputs
        const username = usernameInput.value.trim();
        const password = passwordInput.value;

        if (!username) {
            errorText.innerText = "Username is required";
            return;
        }

        if (!password) {
            errorText.innerText = "Password is required";
            return;
        }

        // Disable button during login attempt
        loginButton.disabled = true;
        loginButton.innerText = "Logging in...";

        try {
            const response = await fetch("/api/login", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({ username, password }),
            });

            const data = await response.json();

            if (data?.token) {
                localStorage.setItem("user", JSON.stringify(data));
                window.location.href = "/";
            } else if (data?.error) {
                errorText.innerText = data.error;
            } else {
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
