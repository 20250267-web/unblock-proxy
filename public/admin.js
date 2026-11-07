
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
  const services = await adminApi("/api/services");
  const container = document.getElementById("admin-services");

  if (!container) return;

  container.innerHTML = services.map(service => `
    <article class="admin-service">
      <div>
        <strong>${escapeAdminHTML(service.name)}</strong>
        <p>${escapeAdminHTML(service.slug)}</p>
        <small>${escapeAdminHTML(service.origin)}</small>
      </div>
      <button
        data-disable="${escapeAdminHTML(service.slug)}"
        class="danger"
      >停止</button>
    </article>
  `).join("");

  container.querySelectorAll("[data-disable]").forEach(button => {
    button.addEventListener("click", async () => {
      const slug = button.dataset.disable;

      if (!confirm(`${slug} を停止しますか？`)) return;

      try {
        await adminApi("/api/admin/services/disable", {
          method: "POST",
          body: JSON.stringify({ slug })
        });

        await loadAdminServices();
      } catch (error) {
        alert(error.message);
      }
    });
  });
}

async function loadAdminEvents() {
  const events = await adminApi("/api/admin/events");
  const container = document.getElementById("admin-events");

  if (!container) return;

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
    console.error("Admin initialization failed");
  }
}

document.addEventListener("DOMContentLoaded", initializeAdmin);
