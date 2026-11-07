const adminApi = async (path, options = {}) => {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body
        ? { "Content-Type": "application/json" }
        : {}),
      ...options.headers
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }

  return data;
};

const escapeAdminHTML = value =>
  String(value).replace(/[&<>"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);

async function loadAdminServices() {
  const { services = [] } = await adminApi("/api/services");
  const container = document.getElementById("admin-services");

  if (!container) return;

  if (!Array.isArray(services) || services.length === 0) {
    container.textContent = "登録サービスはありません。";
    return;
  }

  container.innerHTML = services.map(service => `
    <article class="admin-service">
      <div>
        <strong>${escapeAdminHTML(service.name)}</strong>
        <p>${escapeAdminHTML(service.slug)}</p>
        <small>${escapeAdminHTML(service.origin)}</small>
      </div>
      <button
        data-toggle-service="${escapeAdminHTML(service.slug)}"
        data-enabled="${Boolean(service.enabled)}"
        class="${service.enabled ? "danger" : "secondary"}"
      >${service.enabled ? "停止" : "有効化"}</button>
    </article>
  `).join("");

  container.querySelectorAll("[data-toggle-service]").forEach(button => {
    button.addEventListener("click", async () => {
      const slug = button.dataset.toggleService;
      const enabled = button.dataset.enabled === "true";

      if (!slug) return;
      if (enabled && !confirm(`${slug} を停止しますか？`)) return;

      button.disabled = true;

      try {
        await adminApi(
          enabled
            ? "/api/admin/services/disable"
            : "/api/admin/services/enable",
          {
            method: "POST",
            body: JSON.stringify({ slug })
          }
        );

        await loadAdminServices();
      } catch (error) {
        alert(error.message);
        button.disabled = false;
      }
    });
  });
}

async function loadAdminEvents() {
  const { events = [] } = await adminApi("/api/admin/events");
  const container = document.getElementById("admin-events");

  if (!container) return;

  if (!Array.isArray(events) || events.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.textContent = "アクセス記録はありません。";
    row.append(cell);
    container.replaceChildren(row);
    return;
  }

  container.innerHTML = events.map(event => `
    <tr>
      <td>${escapeAdminHTML(event.email)}</td>
      <td>${escapeAdminHTML(event.service_slug)}</td>
      <td>${escapeAdminHTML(event.method)}</td>
      <td>${Number(event.status)}</td>
      <td>${escapeAdminHTML(event.created_at)}</td>
    </tr>
  `).join("");
}

async function initializeAdmin() {
  try {
    const me = await adminApi("/api/me");

    if (!me.admin) return;

    await Promise.all([
      loadAdminServices(),
      loadAdminEvents()
    ]);
  } catch (error) {
    console.error("Admin initialization failed", error);
  }
}

document.addEventListener("DOMContentLoaded", initializeAdmin);
