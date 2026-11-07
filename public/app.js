const $ = id => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {})
    }
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }

  return data;
}

function escapeHTML(value) {
  return String(value).replace(/[&<>\"']/g, char => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[char]);
}

async function load() {
  try {
    const me = await api("/api/me");

    $("identity").textContent =
      me.email + (me.admin ? " / 管理者" : " / メンバー");

    $("status").textContent = "認証済み";
    $("admin").classList.toggle("hidden", !me.admin);

    const { services = [] } = await api("/api/services");

    if (!Array.isArray(services) || services.length === 0) {
      $("services").textContent = "利用可能なサービスはありません。";
      return;
    }

    $("services").innerHTML = services.map(service => `
      <article class="service">
        <h3>${escapeHTML(service.name)}</h3>
        <p>${escapeHTML(service.slug)}</p>
        <a
          href="${escapeHTML(service.origin)}"
          target="_blank"
          rel="noopener noreferrer"
        >元のWebサイトを開く ↗</a>
        <p>
          <small>API中継: /api/relay/${encodeURIComponent(service.slug)}/</small>
        </p>
      </article>
    `).join("");
  } catch (error) {
    $("status").textContent = "認証エラー";
    $("identity").textContent = error.message;
    $("services").textContent = "Cloudflare Accessの設定を確認してください。";
  }
}

$("reload").addEventListener("click", load);

$("service-form").addEventListener("submit", async event => {
  event.preventDefault();

  const formElement = event.currentTarget;
  const form = new FormData(formElement);

  try {
    const paths = JSON.parse(form.get("paths"));

    await api("/api/admin/services", {
      method: "POST",
      body: JSON.stringify({
        slug: form.get("slug"),
        name: form.get("name"),
        origin: form.get("origin"),
        allowedPaths: paths
      })
    });

    $("admin-message").textContent = "サービスを登録しました。";
    formElement.reset();
    await load();
  } catch (error) {
    $("admin-message").textContent = error.message;
  }
});

$("member-form").addEventListener("submit", async event => {
  event.preventDefault();

  const formElement = event.currentTarget;
  const form = new FormData(formElement);

  try {
    await api("/api/admin/members", {
      method: "POST",
      body: JSON.stringify({
        slug: form.get("slug"),
        email: form.get("email")
      })
    });

    $("admin-message").textContent = "メンバーに利用権限を付与しました。";
    formElement.reset();
  } catch (error) {
    $("admin-message").textContent = error.message;
  }
});

load();
