
import { createRemoteJWKSet, jwtVerify } from "jose";

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;
  ADMIN_EMAILS: string;
}

interface Service {
  id: number;
  slug: string;
  name: string;
  origin: string;
  allowed_paths: string;
  enabled: number;
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}

function isAdmin(email: string, env: Env) {
  return env.ADMIN_EMAILS
    .split(",")
    .map(x => x.trim().toLowerCase())
    .includes(email.toLowerCase());
}

async function authenticate(req: Request, env: Env) {
  const token = req.headers.get("Cf-Access-Jwt-Assertion");

  if (!token) {
    throw new Error("UNAUTHORIZED");
  }

  const issuer = `https://${env.ACCESS_TEAM_DOMAIN}`;

  let jwks = jwksCache.get(issuer);

  if (!jwks) {
    jwks = createRemoteJWKSet(
      new URL(`${issuer}/cdn-cgi/access/certs`)
    );
    jwksCache.set(issuer, jwks);
  }

  const { payload } = await jwtVerify(token, jwks, {
    issuer,
    audience: env.ACCESS_AUD
  });

  if (typeof payload.email !== "string") {
    throw new Error("INVALID_IDENTITY");
  }

  return payload.email.toLowerCase();
}

function validateOrigin(value: string): URL | null {
  try {
    const url = new URL(value);

    if (url.protocol !== "https:") return null;
    if (url.username || url.password) return null;
    if (url.port && url.port !== "443") return null;
    if (url.pathname !== "/" || url.search || url.hash) return null;

    const host = url.hostname.toLowerCase();

    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host === "metadata.google.internal" ||
      /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ||
      host.includes(":")
    ) {
      return null;
    }

    return url;
  } catch {
    return null;
  }
}

function validSlug(value: string) {
  return /^[a-z0-9][a-z0-9-]{1,47}$/.test(value);
}

function validPrefixes(value: unknown): value is string[] {
  return Array.isArray(value) &&
    value.length > 0 &&
    value.length <= 20 &&
    value.every(
      p =>
        typeof p === "string" &&
        p.startsWith("/") &&
        !p.includes("..") &&
        p.length <= 160
    );
}

function pathAllowed(path: string, prefixes: string[]) {
  return prefixes.some(prefix => {
    const base = prefix.endsWith("/")
      ? prefix
      : prefix + "/";

    return path === prefix || path.startsWith(base);
  });
}

async function getService(
  env: Env,
  slug: string,
  email: string,
  admin: boolean
): Promise<Service | null> {
  return await env.DB.prepare(`
    SELECT s.*
    FROM services s
    WHERE s.slug = ?
      AND s.enabled = 1
      AND (
        ? = 1 OR EXISTS (
          SELECT 1
          FROM service_members m
          WHERE m.service_id = s.id
          AND m.email = ?
        )
      )
  `).bind(slug, admin ? 1 : 0, email)
    .first<Service>();
}

async function logEvent(
  env: Env,
  email: string,
  slug: string,
  method: string,
  status: number
) {
  // URLやクエリ文字列、本文は保存しない
  await env.DB.prepare(`
    INSERT INTO access_events
    (email, service_slug, method, status)
    VALUES (?, ?, ?, ?)
  `).bind(email, slug, method, status).run();
}

async function listServices(
  env: Env,
  email: string,
  admin: boolean
) {
  if (admin) {
    const result = await env.DB.prepare(`
      SELECT id, slug, name, origin, enabled
      FROM services
      ORDER BY name
    `).all();

    return result.results;
  }

  const result = await env.DB.prepare(`
    SELECT s.id, s.slug, s.name, s.origin, s.enabled
    FROM services s
    INNER JOIN service_members m
      ON m.service_id = s.id
    WHERE m.email = ?
      AND s.enabled = 1
    ORDER BY s.name
  `).bind(email).all();

  return result.results;
}

async function adminApi(
  req: Request,
  env: Env,
  pathname: string
) {
  if (
    req.method === "POST" &&
    pathname === "/api/admin/services"
  ) {
    let body: any;

    try {
      body = await req.json();
    } catch {
      return response({ error: "Invalid JSON" }, 400);
    }

    const slug = String(body.slug || "");
    const name = String(body.name || "").trim();
    const origin = validateOrigin(String(body.origin || ""));
    const paths = body.allowedPaths;

    if (!validSlug(slug) || !name || name.length > 80) {
      return response({ error: "Invalid service information" }, 400);
    }

    if (!origin) {
      return response({ error: "Invalid HTTPS origin" }, 400);
    }

    if (!validPrefixes(paths)) {
      return response({ error: "Invalid allowed paths" }, 400);
    }

    try {
      await env.DB.prepare(`
        INSERT INTO services
        (slug, name, origin, allowed_paths)
        VALUES (?, ?, ?, ?)
      `).bind(
        slug,
        name,
        origin.origin,
        JSON.stringify(paths)
      ).run();
    } catch {
      return response({ error: "Service already exists or DB error" }, 409);
    }

    return response({ ok: true }, 201);
  }

  if (
    req.method === "POST" &&
    pathname === "/api/admin/members"
  ) {
    let body: any;

    try {
      body = await req.json();
    } catch {
      return response({ error: "Invalid JSON" }, 400);
    }

    const slug = String(body.slug || "");
    const email = String(body.email || "").trim().toLowerCase();

    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return response({ error: "Invalid email" }, 400);
    }

    const service = await env.DB.prepare(
      "SELECT id FROM services WHERE slug = ?"
    ).bind(slug).first<{id:number}>();

    if (!service) {
      return response({ error: "Unknown service" }, 404);
    }

    await env.DB.prepare(`
      INSERT OR IGNORE INTO service_members
      (service_id, email)
      VALUES (?, ?)
    `).bind(service.id, email).run();

    return response({ ok: true });
  }

  if (
    req.method === "GET" &&
    pathname === "/api/admin/events"
  ) {
    const result = await env.DB.prepare(`
      SELECT email, service_slug, method, status, created_at
      FROM access_events
      ORDER BY id DESC
      LIMIT 100
    `).all();

    return response(result.results);
  }

  return response({ error: "Not found" }, 404);
}

async function relayApi(
  req: Request,
  env: Env,
  email: string,
  admin: boolean,
  slug: string,
  rest: string
) {
  if (!["GET", "POST"].includes(req.method)) {
    return response({ error: "Method not allowed" }, 405);
  }

  const service = await getService(env, slug, email, admin);

  if (!service) {
    return response({ error: "Service unavailable" }, 404);
  }

  let prefixes: string[];

  try {
    prefixes = JSON.parse(service.allowed_paths);
  } catch {
    return response({ error: "Invalid service configuration" }, 500);
  }

  const path = "/" + rest.replace(/^\/+/, "");

  if (!pathAllowed(path, prefixes)) {
    return response({ error: "Path not allowed" }, 403);
  }

  const length = Number(req.headers.get("content-length") || 0);

  if (length > 512 * 1024) {
    return response({ error: "Request too large" }, 413);
  }

  let upstream = new URL(service.origin);
  upstream.pathname = path;
  upstream.search = new URL(req.url).search;

  const headers = new Headers();
  const contentType = req.headers.get("content-type");

  if (contentType) {
    headers.set("content-type", contentType);
  }

  headers.set(
    "accept",
    req.headers.get("accept") || "application/json"
  );

  headers.set("user-agent", "PrivateProxy/1.0");

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    15000
  );

  let upstreamResponse: Response;

  try {
    upstreamResponse = await fetch(upstream.toString(), {
      method: req.method,
      headers,
      body: req.method === "POST" ? req.body : undefined,
      redirect: "manual",
      signal: controller.signal
    });
  } catch {
    clearTimeout(timeout);

    await logEvent(
      env, email, slug, req.method, 502
    );

    return response({ error: "Upstream request failed" }, 502);
  }

  clearTimeout(timeout);

  if (
    upstreamResponse.status >= 300 &&
    upstreamResponse.status < 400
  ) {
    await logEvent(
      env, email, slug, req.method, 502
    );

    return response({
      error: "Upstream redirect is not followed"
    }, 502);
  }

  const outputHeaders = new Headers();

  for (const key of ["content-type"]) {
    const value = upstreamResponse.headers.get(key);
    if (value) outputHeaders.set(key, value);
  }

  outputHeaders.set("Cache-Control", "no-store");
  outputHeaders.set("X-Content-Type-Options", "nosniff");

  await logEvent(
    env,
    email,
    slug,
    req.method,
    upstreamResponse.status
  );

  // Response body is streamed instead of buffering the entire response.
  return new Response(upstreamResponse.body, {
    status: upstreamResponse.status,
    headers: outputHeaders
  });
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return response({ ok: true });
    }

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(req);
    }

    let email: string;

    try {
      email = await authenticate(req, env);
    } catch {
      return response({ error: "Authentication required" }, 401);
    }

    const admin = isAdmin(email, env);

    if (
      req.method === "GET" &&
      url.pathname === "/api/me"
    ) {
      return response({ email, admin });
    }

    if (
      req.method === "GET" &&
      url.pathname === "/api/services"
    ) {
      return response(
        await listServices(env, email, admin)
      );
    }

    if (url.pathname.startsWith("/api/admin/")) {
      if (!admin) {
        return response({ error: "Admin only" }, 403);
      }

      return adminApi(req, env, url.pathname);
    }

    const match = url.pathname.match(
      /^\/api\/relay\/([a-z0-9-]{2,48})\/(.*)$/
    );

    if (match) {
      return relayApi(
        req,
        env,
        email,
        admin,
        match[1],
        match[2]
      );
    }

    return response({ error: "Not found" }, 404);
  }
};
