// Consulta a sessão na mesma origem (o cookie vai sozinho, sem token no JavaScript).
const status = document.getElementById("status");
const loginArea = document.getElementById("login-area");
const logoutArea = document.getElementById("logout-area");

fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    if (user) {
      status.textContent = `Sessão de ${user.email ?? user.displayName}.`;
      logoutArea.hidden = false;
    } else {
      status.textContent = "Nenhuma sessão neste navegador.";
      loginArea.hidden = false;
    }
  })
  .catch(() => {
    status.textContent = "Não foi possível consultar a sessão.";
    loginArea.hidden = false;
  });
