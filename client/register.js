document.addEventListener("DOMContentLoaded", () => {
    console.log("Registration page loaded");
    const usernameInput = document.getElementById("username");
    const passwordInput = document.getElementById("password");
    const confirmPasswordInput = document.getElementById("confirm-password");
    const registerButton = document.getElementById("register");
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
            registerButton.click();
        }
    };

    usernameInput.addEventListener("keyup", handleEnterKey);
    passwordInput.addEventListener("keyup", handleEnterKey);
    confirmPasswordInput.addEventListener("keyup", handleEnterKey);

    registerButton.addEventListener("click", async (e) => {
        e.preventDefault();
        console.log("Registration attempt started");

        // Clear previous error
        errorText.innerText = "";
        errorText.className = "text-center mt-2";

        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        // Validation
        if (!username) {
            console.warn("Registration validation failed: Username is required");
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Username is required";
            return;
        }

        if (username.length < 3) {
            console.warn("Registration validation failed: Username too short");
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Username must be at least 3 characters long";
            return;
        }

        if (!password) {
            console.warn("Registration validation failed: Password is required");
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Password is required";
            return;
        }

        if (password.length < 6) {
            console.warn("Registration validation failed: Password too short");
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Password must be at least 6 characters long";
            return;
        }

        if (password !== confirmPassword) {
            console.warn("Registration validation failed: Passwords do not match");
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Passwords do not match";
            return;
        }

        // Disable button during registration attempt
        registerButton.disabled = true;
        registerButton.innerText = "Creating account...";

        try {
            console.log(`Attempting to register user: ${username}`);
            const response = await fetch("/api/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok) {
                console.log("Registration successful");
                errorText.className = "text-green-500 text-center mt-2";
                errorText.innerText = "Registration successful! Redirecting to login...";

                setTimeout(() => {
                    window.location.href = "/login.html";
                }, 2000);
            } else {
                console.warn(`Registration failed: ${data.error}`);
                errorText.className = "text-red-500 text-center mt-2";
                errorText.innerText = data.error || "Registration failed";
            }
        } catch (err) {
            console.error("Registration error:", err);
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Connection error. Please try again";
        } finally {
            // Re-enable button
            registerButton.disabled = false;
            registerButton.innerText = "Register";
        }
    });
});
