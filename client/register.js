document.addEventListener("DOMContentLoaded", () => {
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
            registerButton.click();
        }
    };

    usernameInput.addEventListener("keyup", handleEnterKey);
    passwordInput.addEventListener("keyup", handleEnterKey);
    confirmPasswordInput.addEventListener("keyup", handleEnterKey);

    registerButton.addEventListener("click", async (e) => {
        e.preventDefault();

        // Clear previous error
        errorText.innerText = "";
        errorText.className = "text-center mt-2";

        const username = usernameInput.value.trim();
        const password = passwordInput.value;
        const confirmPassword = confirmPasswordInput.value;

        // Validation
        if (!username) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Username is required";
            return;
        }

        if (username.length < 3) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Username must be at least 3 characters long";
            return;
        }

        if (!password) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Password is required";
            return;
        }

        if (password.length < 6) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Password must be at least 6 characters long";
            return;
        }

        if (password !== confirmPassword) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Passwords do not match";
            return;
        }

        // Disable button during registration attempt
        registerButton.disabled = true;
        registerButton.innerText = "Creating account...";

        try {
            const response = await fetch("/api/register", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();
            if (response.ok) {
                errorText.className = "text-green-500 text-center mt-2";
                errorText.innerText = "Registration successful! Redirecting to login...";

                setTimeout(() => {
                    window.location.href = "/login.html";
                }, 2000);
            } else {
                errorText.className = "text-red-500 text-center mt-2";
                errorText.innerText = data.error || "Registration failed";
            }
        } catch (err) {
            errorText.className = "text-red-500 text-center mt-2";
            errorText.innerText = "Connection error. Please try again";
            console.error("Registration error:", err);
        } finally {
            // Re-enable button
            registerButton.disabled = false;
            registerButton.innerText = "Register";
        }
    });
});
