const accountName = document.querySelector("#account-name");
const adminPanel = document.querySelector("#admin-panel");
const logoutButton = document.querySelector("#logout-button");
const inviteForm = document.querySelector("#invite-form");
const inviteEmail = document.querySelector("#invite-email");
const inviteFeedback = document.querySelector("#invite-feedback");
const inviteResult = document.querySelector("#invite-result");
const inviteLink = document.querySelector("#invite-link");
const copyInviteLink = document.querySelector("#copy-invite-link");

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options
  });
  const payload = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(payload.message || "요청을 처리하지 못했습니다.");
  }

  return payload;
}

async function initialize() {
  try {
    const session = await api("/api/auth/me", { method: "GET" });

    if (!session.authenticated) {
      window.location.replace("/login");
      return;
    }

    accountName.textContent = session.user.email || session.user.loginId;

    if (session.user.role === "admin") {
      adminPanel.hidden = false;
    }
  } catch {
    window.location.replace("/login");
  }
}

logoutButton.addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" }).catch(() => undefined);
  window.location.replace("/login");
});

inviteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitButton = inviteForm.querySelector("button[type='submit']");
  submitButton.disabled = true;
  inviteFeedback.textContent = "";
  inviteResult.hidden = true;

  try {
    const result = await api("/api/admin/invitations", {
      method: "POST",
      body: JSON.stringify({ email: inviteEmail.value })
    });

    inviteLink.value = result.invitationUrl;
    inviteResult.hidden = false;
    inviteFeedback.textContent = `${result.email} 주소의 초대 링크를 만들었습니다.`;
    inviteForm.reset();
  } catch (error) {
    inviteFeedback.textContent = error.message;
  } finally {
    submitButton.disabled = false;
  }
});

copyInviteLink.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(inviteLink.value);
    inviteFeedback.textContent = "초대 링크를 복사했습니다.";
  } catch {
    inviteLink.select();
    document.execCommand("copy");
    inviteFeedback.textContent = "초대 링크를 복사했습니다.";
  }
});

initialize();
