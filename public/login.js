const loginForm = document.querySelector("#login-form");
const loginFeedback = document.querySelector("#login-feedback");

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = loginForm.querySelector("button[type='submit']");
  const formData = new FormData(loginForm);
  submitButton.disabled = true;
  loginFeedback.textContent = "";

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        loginId: formData.get("loginId"),
        password: formData.get("password")
      })
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(payload.message || "로그인하지 못했습니다.");
    }

    window.location.replace("/");
  } catch (error) {
    loginFeedback.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});
