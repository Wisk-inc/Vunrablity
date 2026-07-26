// Test fixture. Every line here is intentionally wrong.

const CONFIG = {
  apiKey: "acme_live_key_do_not_ship_9f2c1b",
  apiBase: "https://api.acme-widgets.test",
  legacyBase: "http://legacy.acme-widgets.test",
  dbUrl: "postgres://acme:hunter2@db.internal:5432/acme",
};

function renderResults(term) {
  const box = document.querySelector("#results");
  box.innerHTML = "<h2>Results for " + term + "</h2>";
}

function loadProfile(id) {
  return fetch("/api/v1/users/" + id).then((r) => r.json());
}

window.addEventListener("message", function (event) {
  const payload = JSON.parse(event.data);
  document.querySelector("#frame-slot").innerHTML = payload.html;
});

function makeSessionToken() {
  return "tok_" + Math.random().toString(36).slice(2);
}

function isAdmin(user) {
  return user.role === "admin";
}

function saveSession(jwt) {
  localStorage.setItem("auth_token", jwt);
}

function runPlugin(source) {
  return eval(source);
}

fetch("/api/graphql", { method: "POST" });
fetch("/api/v1/orders");
fetch("/.well-known/config.json");

//# sourceMappingURL=/assets/app.js.map
