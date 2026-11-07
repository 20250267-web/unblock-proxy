
export function validateOrigin(value: string): URL | null {
  let url: URL;

  try {
    url = new URL(value);
  } catch {
    return null;
  }

  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== "443") return null;

  // Originにはパス・クエリ・フラグメントを含めない
  if (url.pathname !== "/" || url.search || url.hash) {
    return null;
  }

  const host = url.hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "metadata.google.internal"
  ) {
    return null;
  }

  // IPアドレスを直接指定した接続先は拒否
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    return null;
  }

  if (host.startsWith("[") || host.includes(":")) {
    return null;
  }

  if (!host.includes(".")) {
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
    if (path.length > 160) return false;
    if (path.includes("\\")) return false;
    if (path.includes("\0")) return false;

    const segments = path.split("/");

    if (segments.some(segment => segment === "." || segment === "..")) {
      return false;
    }

    try {
      const decoded = decodeURIComponent(path);

      if (decoded.includes("\\")) return false;
      if (decoded.includes("\0")) return false;

      const decodedSegments = decoded.split("/");

      if (
        decodedSegments.some(
          segment => segment === "." || segment === ".."
        )
      ) {
        return false;
      }
    } catch {
      return false;
    }

    return true;
  });
}

export function normalizeServicePath(
  value: string
): string | null {
  if (!value.startsWith("/")) return null;
  if (value.length > 2048) return null;
  if (value.includes("\\")) return null;
  if (value.includes("\0")) return null;

  let decoded: string;

  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }

  if (decoded.includes("\\")) return null;
  if (decoded.includes("\0")) return null;

  const segments = decoded.split("/");

  if (
    segments.some(
      segment => segment === "." || segment === ".."
    )
  ) {
    return null;
  }

  return value;
}

export function pathAllowed(
  path: string,
  prefixes: string[]
): boolean {
  return prefixes.some(prefix => {
    const normalizedPrefix =
      prefix === "/" ? "/" : prefix.replace(/\/+$/, "");

    if (normalizedPrefix === "/") {
      return path.startsWith("/");
    }

    return (
      path === normalizedPrefix ||
      path.startsWith(normalizedPrefix + "/")
    );
  });
}
