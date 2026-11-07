
export function validatePublicHttpsUrl(value: string): URL | null {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== "443") return null;

  const host = url.hostname.toLowerCase();

  const blockedHosts = [
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal"
  ];

  if (blockedHosts.includes(host)) return null;
  if (host.endsWith(".localhost")) return null;
  if (host.endsWith(".local")) return null;
  if (host.endsWith(".internal")) return null;

  // IPv4リテラルは登録させない
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return null;
  }

  // IPv6リテラルは登録させない
  if (host.startsWith("[") || host.includes(":")) {
    return null;
  }

  return url;
}

export function validateServiceSlug(slug: string): boolean {
  return /^[a-z0-9][a-z0-9-]{1,47}$/.test(slug);
}

export function validateAllowedPaths(
  paths: unknown
): paths is string[] {
  if (!Array.isArray(paths)) return false;
  if (paths.length === 0 || paths.length > 20) return false;

  return paths.every(path => {
    if (typeof path !== "string") return false;
    if (!path.startsWith("/")) return false;
    if (path.includes("..")) return false;
    if (path.includes("\\")) return false;
    if (path.length > 160) return false;

    return true;
  });
}
