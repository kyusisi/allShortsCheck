const acceptInviteForm = document.querySelector("#accept-invite-form");
const invitedEmail = document.querySelector("#invited-email");
const newPassword = document.querySelector("#new-password");
const confirmPassword = document.querySelector("#confirm-password");
const inviteFeedback = document.querySelector("#invite-feedback");
const token = new URLSearchParams(window.location.search).get("token");

async function loadInvitation() {
  if (!token) {
    inviteFeedback.textContent = "초대 링크가 유효하지 않습니다.";
    return;
  }

  try {
    const response = await fetch(`/api/invitations/${encodeURIComponent(token)}`);
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(payload.message || "초대 링크가 유효하지 않습니다.");
    }

    invitedEmail.value = payload.email;
    acceptInviteForm.hidden = false;
  } catch (error) {
    inviteFeedback.textContent = error.message;
  }
}

acceptInviteForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  if (newPassword.value !== confirmPassword.value) {
    inviteFeedback.textContent = "비밀번호 확인이 일치하지 않습니다.";
    return;
  }

  const submitButton = acceptInviteForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  inviteFeedback.textContent = "";

  try {
    const response = await fetch(`/api/invitations/${encodeURIComponent(token)}/accept`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: newPassword.value })
    });
    const payload = await response.json().catch(() => ({}));

    if (!response.ok) {
      throw new Error(payload.message || "계정을 만들지 못했습니다.");
    }

    window.location.replace("/");
  } catch (error) {
    inviteFeedback.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

loadInvitation();
