
import {
  createRemoteJWKSet,
  jwtVerify
} from "jose";

import {
  validateOrigin,
  validateServiceSlug,
  validateAllowedPaths,
  normalizeServicePath,
  pathAllowed
} from "./security";

import {
  createStreamingResponse
} from "./streaming";

import {
  writeAccessLog
} from "./logger";

import {
  relayWebSocket
} from "./websocket";

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;

  // Set with: npx wrangler secret put ADMIN_EMAILS
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

interface Identity {
  email: string;
}

const jwksCache = new Map<
  string,
  ReturnType<typeof createRemoteJWKSet>
>();

const MAX_JSON_BYTES = 32 * 1024;
const MAX_REQUEST_BYTES = 1024 * 1024;

function json(
  data: unknown,
  status = 200,
  extraHeaders?: HeadersInit
): Response {
  const headers = new Headers(extraHeaders);

  headers.set(
    "Content-Type",
    "application/json; charset=utf-8"
  );
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");

  return new Response(JSON.stringify(data), {
    status,
    headers
  });
}

function getIssuer(env: Env): string {
  const domain = env.ACCESS_TEAM_DOMAIN
    .trim()
    .replace(/^https?:\/\//, "")
    .replace(/\/+$/, "");

  if (!domain || domain.includes("/")) {
    throw new Error("INVALID_ACCESS_DOMAIN");
  }

  return `https://${domain}`;
}

async function authenticate(
  request: Request,
  env: Env
): Promise<Identity> {
  const token = request.headers.get(
    "Cf-Access-Jwt-Assertion"
  );

  if (!token) {
    throw new Error("UNAUTHORIZED");
  }

  const issuer = getIssuer(env);

  let jwks = jwksCache.get(issuer);

  if (!jwks) {
    jwks = createRemoteJWKSet(
      new URL(`${issuer}/cdn-cgi/access/certs`)
    );

    jwksCache.set(issuer, jwks);
  }

  const verified = await jwtVerify(token, jwks, {
    issuer,
    audience: env.ACCESS_AUD
  });

  const email = verified.payload.email;

  if (
    typeof email !== "string" ||
    email.length > 254 ||
    !email.includes("@")
  ) {
    throw new Error("INVALID_IDENTITY");
  }

  return {
    email: email.toLowerCase()
  };
}

function isAdmin(email: string, env: Env): boolean {
  const admins = (env.ADMIN_EMAILS || "")
    .split(",")
    .map(value => value.trim().toLowerCase())
    .filter(Boolean);

  return admins.includes(email.toLowerCase());
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("Origin");

  // Non-browser clients may omit Origin.
  if (!origin) return true;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

async function readJson(
  request: Request
): Promise<any | null> {
  const contentType = request.headers.get("Content-Type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return null;
  }

  const length = Number(
    request.headers.get("Content-Length") || 0
  );

  if (length > MAX_JSON_BYTES) {
    return null;
  }

  try {
    const buffer = await request.arrayBuffer();

    if (buffer.byteLength > MAX_JSON_BYTES) {
      return null;
    }

    return JSON.parse(
      new TextDecoder().decode(buffer)
    );
  } catch {
    return null;
  }
}

async function findService(
  env: Env,
  slug: string,
  email: string,
  admin: boolean
): Promise<Service | null> {
  const query = admin
    ? `
      SELECT *
      FROM services
      WHERE slug = ?
        AND enabled = 1
      LIMIT 1
    `
    : `
      SELECT s.*
      FROM services s
      INNER JOIN service_members m
        ON m.service_id = s.id
      WHERE s.slug = ?
        AND s.enabled = 1
        AND m.email = ?
      LIMIT 1
    `;

  const statement = admin
    ? env.DB.prepare(query).bind(slug)
    : env.DB.prepare(query).bind(slug, email);

  return statement.first<Service>();
}

async function listServices(
  env: Env,
  email: string,
  admin: boolean
): Promise<unknown[]> {
  const statement = admin
    ? env.DB.prepare(`
        SELECT id, slug, name, origin, enabled
        FROM services
        ORDER BY name
      `)
    : env.DB.prepare(`
        SELECT s.id, s.slug, s.name, s.origin, s.enabled
        FROM services s
        INNER JOIN service_members m
          ON m.service_id = s.id
        WHERE m.email = ?
          AND s.enabled = 1
        ORDER BY s.name
      `).bind(email);

  const result = await statement.all();

  return result.results || [];
}

async function getAllowedPaths(
  service: Service
): Promise<string[] | null> {
  try {
    const paths = JSON.parse(service.allowed_paths);

    if (!validateAllowedPaths(paths)) {
      return null;
    }

    return paths;
  } catch {
    return null;
  }
}

async function adminApi(
  request: Request,
  env: Env,
  pathname: string
): Promise<Response> {
  if (!sameOrigin(request)) {
    return json({ error: "Invalid origin" }, 403);
  }

  if (
    request.method === "POST" &&
    pathname === "/api/admin/services"
  ) {
    const body = await readJson(request);

    if (!body) {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const slug = String(body.slug || "").trim();
    const name = String(body.name || "").trim();
    const origin = validateOrigin(
      String(body.origin || "")
    );
    const paths = body.allowedPaths;

    if (!validateServiceSlug(slug)) {
      return json({ error: "Invalid service slug" }, 400);
    }

    if (!name || name.length > 80) {
      return json({ error: "Invalid service name" }, 400);
    }

    if (!origin) {
      return json({ error: "Invalid HTTPS origin" }, 400);
    }

    if (!validateAllowedPaths(paths)) {
      return json({ error: "Invalid allowed paths" }, 400);
    }

    try {
      await env.DB.prepare(`
        INSERT INTO services
          (slug, name, origin, allowed_paths, enabled)
        VALUES (?, ?, ?, ?, 1)
      `).bind(
        slug,
        name,
        origin.origin,
        JSON.stringify(paths)
      ).run();

      return json({ ok: true }, 201);
    } catch {
      return json({
        error: "Service already exists or database error"
      }, 409);
    }
  }

  if (
    request.method === "POST" &&
    pathname === "/api/admin/members"
  ) {
    const body = await readJson(request);

    if (!body) {
      return json({ error: "Invalid JSON body" }, 400);
    }

    const slug = String(body.slug || "").trim();
    const email = String(body.email || "")
      .trim()
      .toLowerCase();

    if (
      email.length > 254 ||
      !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)
    ) {
      return json({ error: "Invalid email" }, 400);
    }

    const service = await env.DB.prepare(`
      SELECT id
      FROM services
      WHERE slug = ?
      LIMIT 1
    `).bind(slug).first<{ id: number }>();

    if (!service) {
      return json({ error: "Service not found" }, 404);
    }

    await env.DB.prepare(`
      INSERT OR IGNORE INTO service_members
        (service_id, email)
      VALUES (?, ?)
    `).bind(service.id, email).run();

    return json({ ok: true }, 201);
  }

  if (
    request.method === "POST" &&
    pathname === "/api/admin/services/disable"
  ) {
    const body = await readJson(request);

    if (!body || typeof body.slug !== "string") {
      return json({ error: "Invalid request" }, 400);
    }

    const result = await env.DB.prepare(`
      UPDATE services
      SET enabled = 0
      WHERE slug = ?
    `).bind(body.slug).run();

    return json({
      ok: true,
      changed: result.meta.changes || 0
    });
  }

  if (
    request.method === "POST" &&
    pathname === "/api/admin/members/remove"
  ) {
    const body = await readJson(request);

    if (
      !body ||
      typeof body.slug !== "string" ||
      typeof body.email !== "string"
    ) {
      return json({ error: "Invalid request" }, 400);
    }

    const service = await env.DB.prepare(`
      SELECT id
      FROM services
      WHERE slug = ?
    `).bind(body.slug).first<{ id: number }>();

    if (!service) {
      return json({ error: "Service not found" }, 404);
    }

    await env.DB.prepare(`
      DELETE FROM service_members
      WHERE service_id = ?
        AND email = ?
    `).bind(
      service.id,
      body.email.toLowerCase()
    ).run();

    return json({ ok: true });
  }

  if (
    request.method === "GET" &&
    pathname === "/api/admin/events"
  ) {
    const result = await env.DB.prepare(`
      SELECT email, service_slug, method, status, created_at
      FROM access_events
      ORDER BY id DESC
      LIMIT 100
    `).all();

    return json(result.results || []);
  }

  return json({ error: "Not found" }, 404);
}

function buildUpstreamUrl(
  origin: string,
  path: string,
  search: string
): URL | null {
  const base = validateOrigin(origin);

  if (!base) return null;

  const normalized = normalizeServicePath(path);

  if (!normalized) return null;

  const target = new URL(base.origin);

  target.pathname = normalized;
  target.search = search;

  return target;
}

async function relayApi(
  request: Request,
  env: Env,
  identity: Identity,
  admin: boolean,
  slug: string,
  rest: string
): Promise<Response> {
  const method = request.method;

  if (!["GET", "HEAD", "POST"].includes(method)) {
    return json({ error: "Method not allowed" }, 405, {
      Allow: "GET, HEAD, POST"
    });
  }

  if (method === "POST" && !sameOrigin(request)) {
    return json({ error: "Invalid origin" }, 403);
  }

  const service = await findService(
    env,
    slug,
    identity.email,
    admin
  );

  if (!service) {
    return json({ error: "Service unavailable" }, 404);
  }

  const prefixes = await getAllowedPaths(service);

  if (!prefixes) {
    return json({ error: "Invalid service configuration" }, 500);
  }

  const path = normalizeServicePath("/" + rest);

  if (!path || !pathAllowed(path, prefixes)) {
    return json({ error: "Path not allowed" }, 403);
  }

  const target = buildUpstreamUrl(
    service.origin,
    path,
    new URL(request.url).search
  );

  if (!target) {
    return json({ error: "Invalid upstream URL" }, 400);
  }

  let body: ArrayBuffer | undefined;

  if (method === "POST") {
    const declaredLength = Number(
      request.headers.get("Content-Length") || 0
    );

    if (declaredLength > MAX_REQUEST_BYTES) {
      return json({ error: "Request too large" }, 413);
    }

    try {
      body = await request.arrayBuffer();
    } catch {
      return json({ error: "Unable to read request" }, 400);
    }

    if (body.byteLength > MAX_REQUEST_BYTES) {
      return json({ error: "Request too large" }, 413);
    }
  }

  const headers = new Headers();

  const contentType = request.headers.get("Content-Type");
  if (contentType) {
    headers.set("Content-Type", contentType);
  }

  const accept = request.headers.get("Accept");
  if (accept) {
    headers.set("Accept", accept);
  }

  const range = request.headers.get("Range");
  if (range && method !== "POST") {
    headers.set("Range", range);
  }

  headers.set("User-Agent", "PrivateProxyGateway/1.0");

  let upstream: Response;

  try {
    upstream = await fetch(target.toString(), {
      method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(20000)
    });
  } catch {
    await writeAccessLog(env.DB, {
      email: identity.email,
      serviceSlug: slug,
      method,
      status: 502
    });

    return json({ error: "Upstream request failed" }, 502);
  }

  // Do not automatically follow redirects. A redirect could
  // send the request to an unapproved destination.
  if (upstream.status >= 300 && upstream.status < 400) {
    await writeAccessLog(env.DB, {
      email: identity.email,
      serviceSlug: slug,
      method,
      status: 502
    });

    return json({
      error: "Upstream redirect blocked"
    }, 502);
  }

  await writeAccessLog(env.DB, {
    email: identity.email,
    serviceSlug: slug,
    method,
    status: upstream.status
  });

  return createStreamingResponse(upstream, {
    allowRange: true,
    cache: false
  });
}

async function relayWs(
  request: Request,
  env: Env,
  identity: Identity,
  admin: boolean,
  slug: string,
  rest: string
): Promise<Response> {
  if (
    request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
  ) {
    return json({ error: "WebSocket upgrade required" }, 426);
  }

  const service = await findService(
    env,
    slug,
    identity.email,
    admin
  );

  if (!service) {
    return json({ error: "Service unavailable" }, 404);
  }

  const prefixes = await getAllowedPaths(service);

  if (!prefixes) {
    return json({ error: "Invalid service configuration" }, 500);
  }

  const path = normalizeServicePath("/" + rest);

  if (!path || !pathAllowed(path, prefixes)) {
    return json({ error: "Path not allowed" }, 403);
  }

  const target = buildUpstreamUrl(
    service.origin,
    path,
    new URL(request.url).search
  );

  if (!target) {
    return json({ error: "Invalid upstream URL" }, 400);
  }

  const result = await relayWebSocket(request, target);

  await writeAccessLog(env.DB, {
    email: identity.email,
    serviceSlug: slug,
    method: "WEBSOCKET",
    status: result.status
  });

  return result;
}

export default {
  async fetch(
    request: Request,
    env: Env
  ): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ ok: true });
    }

    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }

    let identity: Identity;

    try {
      identity = await authenticate(request, env);
    } catch {
      return json({
        error: "Authentication required"
      }, 401);
    }

    const admin = isAdmin(identity.email, env);

    if (
      request.method === "GET" &&
      url.pathname === "/api/me"
    ) {
      return json({
        email: identity.email,
        admin
      });
    }

    if (
      request.method === "GET" &&
      url.pathname === "/api/services"
    ) {
      return json(
        await listServices(env, identity.email, admin)
      );
    }

    if (url.pathname.startsWith("/api/admin/")) {
      if (!admin) {
        return json({ error: "Admin only" }, 403);
      }

      return adminApi(request, env, url.pathname);
    }

    const wsMatch = url.pathname.match(
      /^\/api\/ws\/([a-z0-9-]{2,48})\/(.*)$/
    );

    if (wsMatch) {
      return relayWs(
        request,
        env,
        identity,
        admin,
        wsMatch[1],
        wsMatch[2]
      );
    }

    const apiMatch = url.pathname.match(
      /^\/api\/relay\/([a-z0-9-]{2,48})\/(.*)$/
    );

    if (apiMatch) {
      return relayApi(
        request,
        env,
        identity,
        admin,
        apiMatch[1],
        apiMatch[2]
      );
    }

    return json({ error: "Not found" }, 404);
  }
};
