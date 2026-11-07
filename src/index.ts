// ============================================================
// Private Proxy
// File: src/index.ts
// Cloudflare Workers + Cloudflare Access + D1
// ============================================================

import { createRemoteJWKSet, jwtVerify } from "jose";
import { createStreamingResponse } from "./streaming";
import { relayWebSocket } from "./websocket";

// ------------------------------------------------------------
// Types
// ------------------------------------------------------------

interface Env {
  DB: D1Database;
  ASSETS: Fetcher;

  ACCESS_TEAM_DOMAIN: string;
  ACCESS_AUD: string;

  ADMIN_EMAILS: string;
}

interface ServiceRow {
  id: number;
  slug: string;
  name: string;
  origin: string;
  allowed_paths: string;
  enabled: number;
  created_at: string;
}

interface AccessIdentity {
  email: string;
}

interface ApiError {
  error: string;
}

// ------------------------------------------------------------
// Constants
// ------------------------------------------------------------

const MAX_JSON_BODY = 64 * 1024;
const MAX_PROXY_BODY = 1024 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;

const RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "content-range",
  "accept-ranges",
  "last-modified",
  "etag",
];

const REQUEST_HEADERS = [
  "accept",
  "accept-language",
  "content-type",
  "range",
  "if-range",
  "if-none-match",
  "if-modified-since",
];

// ------------------------------------------------------------
// Response helpers
// ------------------------------------------------------------

function json(
  data: unknown,
  status = 200,
  extraHeaders?: HeadersInit,
): Response {
  const headers = new Headers(extraHeaders);

  headers.set("Content-Type", "application/json; charset=utf-8");
  headers.set("Cache-Control", "no-store");
  headers.set("X-Content-Type-Options", "nosniff");

  return new Response(JSON.stringify(data), {
    status,
    headers,
  });
}

function error(message: string, status = 400): Response {
  return json({ error: message } satisfies ApiError, status);
}

function notFound(): Response {
  return error("Not found", 404);
}

function methodNotAllowed(): Response {
  return error("Method not allowed", 405, {
    Allow: "GET, HEAD, POST",
  });
}

// ------------------------------------------------------------
// Basic validation
// ------------------------------------------------------------

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;

  const email = value.trim().toLowerCase();

  if (email.length < 3 || email.length > 254) return null;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return null;

  return email;
}

function validateSlug(value: unknown): string | null {
  if (typeof value !== "string") return null;

  const slug = value.trim().toLowerCase();

  if (!/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(slug)) {
    return null;
  }

  return slug;
}

function validateServiceName(value: unknown): string | null {
  if (typeof value !== "string") return null;

  const name = value.trim();

  if (name.length < 1 || name.length > 80) return null;
  if (/[\u0000-\u001f\u007f]/.test(name)) return null;

  return name;
}

function validateOrigin(value: unknown): string | null {
  if (typeof value !== "string") return null;

  let url: URL;

  try {
    url = new URL(value.trim());
  } catch {
    return null;
  }

  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.port && url.port !== "443") return null;
  if (url.pathname !== "/" || url.search || url.hash) return null;

  const hostname = url.hostname.toLowerCase();

  if (!hostname.includes(".")) return null;
  if (hostname === "localhost") return null;
  if (hostname.endsWith(".localhost")) return null;
  if (hostname.endsWith(".local")) return null;
  if (hostname.endsWith(".internal")) return null;
  if (hostname.endsWith(".test")) return null;
  if (hostname === "metadata.google.internal") return null;

  // IP literals are not accepted as service origins.
  if (
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) ||
    hostname.startsWith("[")
  ) {
    return null;
  }

  return url.origin;
}

function validateAllowedPaths(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  if (value.length < 1 || value.length > 20) return null;

  const result: string[] = [];

  for (const item of value) {
    if (typeof item !== "string") return null;

    const path = item.trim();

    if (!path.startsWith("/")) return null;
    if (path.length > 160) return null;
    if (path.includes("\\") || path.includes("\0")) return null;

    let decoded: string;

    try {
      decoded = decodeURIComponent(path);
    } catch {
      return null;
    }

    if (decoded.includes("\0") || decoded.includes("\\")) {
      return null;
    }

    const segments = decoded.split("/");

    if (segments.some((segment) => segment === "." || segment === "..")) {
      return null;
    }

    result.push(path);
  }

  return [...new Set(result)];
}

function normalizeProxyPath(value: string): string | null {
  if (!value.startsWith("/")) return null;
  if (value.length > 2048) return null;
  if (value.includes("\\") || value.includes("\0")) return null;

  let decoded: string;

  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }

  if (decoded.includes("\\") || decoded.includes("\0")) {
    return null;
  }

  const segments = decoded.split("/");

  if (segments.some((segment) => segment === "." || segment === "..")) {
    return null;
  }

  return value;
}

function pathIsAllowed(
  requestedPath: string,
  allowedPaths: string[],
): boolean {
  return allowedPaths.some((allowed) => {
    if (allowed === "/") return true;

    const normalized = allowed.endsWith("/")
      ? allowed.slice(0, -1)
      : allowed;

    return (
      requestedPath === normalized ||
      requestedPath.startsWith(`${normalized}/`)
    );
  });
}

// ------------------------------------------------------------
// Request body helpers
// ------------------------------------------------------------

async function readLimitedBody(
  request: Request,
  limit: number,
): Promise<ArrayBuffer | null> {
  if (!request.body) return new ArrayBuffer(0);

  const declaredLength = Number(request.headers.get("content-length"));

  if (
    Number.isFinite(declaredLength) &&
    declaredLength > limit
  ) {
    return null;
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();

      if (done) break;
      if (!value) continue;

      total += value.byteLength;

      if (total > limit) {
        await reader.cancel();
        return null;
      }

      chunks.push(value);
    }
  } catch {
    return null;
  }

  const combined = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return combined.buffer;
}

async function readJson(
  request: Request,
): Promise<Record<string, unknown> | null> {
  const contentType = request.headers.get("content-type") || "";

  if (!contentType.toLowerCase().includes("application/json")) {
    return null;
  }

  const body = await readLimitedBody(request, MAX_JSON_BODY);

  if (!body) return null;

  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder().decode(body),
    );

    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      return null;
    }

    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------
// Same-origin protection for state-changing requests
// ------------------------------------------------------------

function isSameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");

  if (!origin) return false;

  try {
    return new URL(origin).origin === new URL(request.url).origin;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------
// Cloudflare Access authentication
// ------------------------------------------------------------

function getAccessIssuer(env: Env): string | null {
  const domain = env.ACCESS_TEAM_DOMAIN
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/+$/, "");

  if (!domain || domain.includes("/")) return null;

  return `https://${domain}`;
}

async function authenticate(
  request: Request,
  env: Env,
): Promise<AccessIdentity | null> {
  const assertion = request.headers.get("Cf-Access-Jwt-Assertion");

  if (!assertion) return null;
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD) return null;

  const issuer = getAccessIssuer(env);

  if (!issuer) return null;

  try {
    const jwks = createRemoteJWKSet(
      new URL(`${issuer}/cdn-cgi/access/certs`),
    );

    const { payload } = await jwtVerify(assertion, jwks, {
      issuer,
      audience: env.ACCESS_AUD,
    });

    const email = normalizeEmail(payload.email);

    if (!email) return null;

    return { email };
  } catch {
    return null;
  }
}

function isAdmin(email: string, env: Env): boolean {
  const admins = (env.ADMIN_EMAILS || "")
    .split(",")
    .map((item) => normalizeEmail(item))
    .filter((item): item is string => item !== null);

  return admins.includes(email);
}

async function requireAdmin(
  identity: AccessIdentity,
  env: Env,
): Promise<boolean> {
  return isAdmin(identity.email, env);
}

// ------------------------------------------------------------
// Database helpers
// ------------------------------------------------------------

async function findService(
  env: Env,
  slug: string,
): Promise<ServiceRow | null> {
  return env.DB.prepare(
    `SELECT id, slug, name, origin, allowed_paths, enabled, created_at
     FROM services
     WHERE slug = ?
     LIMIT 1`,
  )
    .bind(slug)
    .first<ServiceRow>();
}

async function isServiceMember(
  env: Env,
  serviceId: number,
  email: string,
): Promise<boolean> {
  const row = await env.DB.prepare(
    `SELECT 1 AS allowed
     FROM service_members
     WHERE service_id = ? AND email = ?
     LIMIT 1`,
  )
    .bind(serviceId, email)
    .first<{ allowed: number }>();

  return Boolean(row);
}

async function canUseService(
  env: Env,
  service: ServiceRow,
  identity: AccessIdentity,
): Promise<boolean> {
  if (!service.enabled) return false;

  if (isAdmin(identity.email, env)) {
    return true;
  }

  return isServiceMember(env, service.id, identity.email);
}

function parseAllowedPaths(value: string): string[] | null {
  try {
    const parsed: unknown = JSON.parse(value);

    return validateAllowedPaths(parsed);
  } catch {
    return null;
  }
}

async function listServices(
  env: Env,
  identity: AccessIdentity,
): Promise<ServiceRow[]> {
  if (isAdmin(identity.email, env)) {
    const result = await env.DB.prepare(
      `SELECT id, slug, name, origin, allowed_paths, enabled, created_at
       FROM services
       ORDER BY name COLLATE NOCASE ASC`,
    ).all<ServiceRow>();

    return result.results || [];
  }

  const result = await env.DB.prepare(
    `SELECT
       s.id,
       s.slug,
       s.name,
       s.origin,
       s.allowed_paths,
       s.enabled,
       s.created_at
     FROM services s
     INNER JOIN service_members sm ON sm.service_id = s.id
     WHERE sm.email = ? AND s.enabled = 1
     ORDER BY s.name COLLATE NOCASE ASC`,
  )
    .bind(identity.email)
    .all<ServiceRow>();

  return result.results || [];
}

// ------------------------------------------------------------
// Access event logging
// No full URLs, query strings, or request bodies are stored.
// ------------------------------------------------------------

async function logAccess(
  env: Env,
  email: string,
  slug: string,
  method: string,
  status: number,
): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT INTO access_events
       (email, service_slug, method, status)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(email, slug, method, status)
      .run();
  } catch {
    // Logging failure must not break the actual request.
  }
}

// ------------------------------------------------------------
// Admin API
// ------------------------------------------------------------

async function adminCreateService(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = await readJson(request);

  if (!body) return error("Invalid JSON request", 400);

  const slug = validateSlug(body.slug);
  const name = validateServiceName(body.name);
  const origin = validateOrigin(body.origin);
  const allowedPaths = validateAllowedPaths(
    body.allowedPaths ?? ["/"],
  );

  if (!slug) return error("Invalid service slug");
  if (!name) return error("Invalid service name");
  if (!origin) return error("Invalid HTTPS service origin");
  if (!allowedPaths) return error("Invalid allowed paths");

  try {
    await env.DB.prepare(
      `INSERT INTO services
       (slug, name, origin, allowed_paths, enabled)
       VALUES (?, ?, ?, ?, 1)`,
    )
      .bind(
        slug,
        name,
        origin,
        JSON.stringify(allowedPaths),
      )
      .run();

    return json({
      success: true,
      message: "Service created",
      slug,
    }, 201);
  } catch {
    return error("Could not create service. The slug may already exist.", 409);
  }
}

async function adminAddMember(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = await readJson(request);

  if (!body) return error("Invalid JSON request", 400);

  const slug = validateSlug(body.slug);
  const email = normalizeEmail(body.email);

  if (!slug) return error("Invalid service slug");
  if (!email) return error("Invalid email address");

  const service = await findService(env, slug);

  if (!service) return error("Service not found", 404);

  try {
    await env.DB.prepare(
      `INSERT INTO service_members (service_id, email)
       VALUES (?, ?)`,
    )
      .bind(service.id, email)
      .run();

    return json({
      success: true,
      message: "Member added",
      slug,
      email,
    }, 201);
  } catch {
    return error("Member is already registered or could not be added.", 409);
  }
}

async function adminRemoveMember(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = await readJson(request);

  if (!body) return error("Invalid JSON request", 400);

  const slug = validateSlug(body.slug);
  const email = normalizeEmail(body.email);

  if (!slug) return error("Invalid service slug");
  if (!email) return error("Invalid email address");

  const service = await findService(env, slug);

  if (!service) return error("Service not found", 404);

  const result = await env.DB.prepare(
    `DELETE FROM service_members
     WHERE service_id = ? AND email = ?`,
  )
    .bind(service.id, email)
    .run();

  return json({
    success: true,
    removed: result.meta.changes > 0,
  });
}

async function adminDisableService(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = await readJson(request);

  if (!body) return error("Invalid JSON request", 400);

  const slug = validateSlug(body.slug);

  if (!slug) return error("Invalid service slug");

  const result = await env.DB.prepare(
    `UPDATE services
     SET enabled = 0
     WHERE slug = ?`,
  )
    .bind(slug)
    .run();

  if (result.meta.changes === 0) {
    return error("Service not found", 404);
  }

  return json({
    success: true,
    message: "Service disabled",
    slug,
  });
}

async function adminEnableService(
  request: Request,
  env: Env,
): Promise<Response> {
  const body = await readJson(request);

  if (!body) return error("Invalid JSON request", 400);

  const slug = validateSlug(body.slug);

  if (!slug) return error("Invalid service slug");

  const result = await env.DB.prepare(
    `UPDATE services
     SET enabled = 1
     WHERE slug = ?`,
  )
    .bind(slug)
    .run();

  if (result.meta.changes === 0) {
    return error("Service not found", 404);
  }

  return json({
    success: true,
    message: "Service enabled",
    slug,
  });
}

async function adminListMembers(
  url: URL,
  env: Env,
): Promise<Response> {
  const slug = validateSlug(url.searchParams.get("slug"));

  if (!slug) return error("A valid service slug is required");

  const service = await findService(env, slug);

  if (!service) return error("Service not found", 404);

  const result = await env.DB.prepare(
    `SELECT email
     FROM service_members
     WHERE service_id = ?
     ORDER BY email COLLATE NOCASE ASC`,
  )
    .bind(service.id)
    .all<{ email: string }>();

  return json({
    service: {
      slug: service.slug,
      name: service.name,
    },
    members: result.results || [],
  });
}

async function adminListEvents(
  url: URL,
  env: Env,
): Promise<Response> {
  const requestedLimit = Number(url.searchParams.get("limit") || "50");

  const limit = Number.isFinite(requestedLimit)
    ? Math.min(Math.max(Math.floor(requestedLimit), 1), 200)
    : 50;

  const result = await env.DB.prepare(
    `SELECT email, service_slug, method, status, created_at
     FROM access_events
     ORDER BY id DESC
     LIMIT ?`,
  )
    .bind(limit)
    .all<{
      email: string;
      service_slug: string;
      method: string;
      status: number;
      created_at: string;
    }>();

  return json({
    events: result.results || [],
  });
}

// ------------------------------------------------------------
// Proxy request handling
// ------------------------------------------------------------

function getProxyRoute(pathname: string): {
  slug: string;
  servicePath: string;
} | null {
  const prefix = "/api/relay/";

  if (!pathname.startsWith(prefix)) return null;

  const remainder = pathname.slice(prefix.length);
  const slashIndex = remainder.indexOf("/");

  if (slashIndex <= 0) {
    return {
      slug: remainder,
      servicePath: "/",
    };
  }

  return {
    slug: remainder.slice(0, slashIndex),
    servicePath: remainder.slice(slashIndex),
  };
}

function buildUpstreamHeaders(request: Request): Headers {
  const headers = new Headers();

  for (const name of REQUEST_HEADERS) {
    const value = request.headers.get(name);

    if (value) {
      headers.set(name, value);
    }
  }

  // Do not forward the visitor's cookies or Cloudflare Access JWT.
  // Upstream authentication should be configured separately for
  // each approved service when required.

  return headers;
}

async function relayHttp(
  request: Request,
  env: Env,
  identity: AccessIdentity,
  service: ServiceRow,
  servicePath: string,
): Promise<Response> {
  if (!["GET", "HEAD", "POST"].includes(request.method)) {
    return methodNotAllowed();
  }

  const normalizedPath = normalizeProxyPath(servicePath);

  if (!normalizedPath) {
    return error("Invalid service path", 400);
  }

  const allowedPaths = parseAllowedPaths(service.allowed_paths);

  if (!allowedPaths) {
    return error("Service path configuration is invalid", 500);
  }

  if (!pathIsAllowed(normalizedPath, allowedPaths)) {
    return error("This path is not allowed for this service", 403);
  }

  const origin = validateOrigin(service.origin);

  if (!origin) {
    return error("Service origin configuration is invalid", 500);
  }

  const upstreamUrl = new URL(origin);

  upstreamUrl.pathname =
    normalizedPath === "/" ? "/" : normalizedPath;

  // Preserve the query string for the registered service.
  upstreamUrl.search = new URL(request.url).search;

  const headers = buildUpstreamHeaders(request);

  let body: ArrayBuffer | undefined;

  if (request.method === "POST") {
    const contentLength = Number(
      request.headers.get("content-length") || "0",
    );

    if (
      Number.isFinite(contentLength) &&
      contentLength > MAX_PROXY_BODY
    ) {
      return error("Request body is too large", 413);
    }

    const limitedBody = await readLimitedBody(
      request,
      MAX_PROXY_BODY,
    );

    if (!limitedBody) {
      return error("Request body is too large or invalid", 413);
    }

    body = limitedBody;
  }

  let upstreamResponse: Response;

  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    await logAccess(
      env,
      identity.email,
      service.slug,
      request.method,
      502,
    );

    return error("The registered service could not be reached", 502);
  }

  // Do not relay redirects to arbitrary destinations.
  if (
    upstreamResponse.status >= 300 &&
    upstreamResponse.status < 400
  ) {
    await logAccess(
      env,
      identity.email,
      service.slug,
      request.method,
      502,
    );

    return error(
      "The upstream service returned a redirect. Open the approved service directly if appropriate.",
      502,
    );
  }

  const response = createStreamingResponse(upstreamResponse, {
    allowRange: true,
    cache: false,
  });

  await logAccess(
    env,
    identity.email,
    service.slug,
    request.method,
    response.status,
  );

  return response;
}

// ------------------------------------------------------------
// API router
// ------------------------------------------------------------

async function handleApi(
  request: Request,
  env: Env,
  identity: AccessIdentity,
): Promise<Response> {
  const url = new URL(request.url);
  const pathname = url.pathname;
  const method = request.method.toUpperCase();

  // Current user
  if (pathname === "/api/me" && method === "GET") {
    return json({
      email: identity.email,
      admin: isAdmin(identity.email, env),
    });
  }

  // Services available to this account
  if (pathname === "/api/services" && method === "GET") {
    const services = await listServices(env, identity);

    return json({
      services: services.map((service) => ({
        slug: service.slug,
        name: service.name,
        enabled: Boolean(service.enabled),
        origin: service.origin,
      })),
    });
  }

  // All state-changing admin requests require same-origin.
  if (method !== "GET" && !isSameOrigin(request)) {
    return error("Invalid request origin", 403);
  }

  // Admin API
  if (pathname.startsWith("/api/admin/")) {
    if (!(await requireAdmin(identity, env))) {
      return error("Administrator access required", 403);
    }

    if (pathname === "/api/admin/services" && method === "POST") {
      return adminCreateService(request, env);
    }

    if (pathname === "/api/admin/members" && method === "POST") {
      return adminAddMember(request, env);
    }

    if (
      pathname === "/api/admin/members/remove" &&
      method === "POST"
    ) {
      return adminRemoveMember(request, env);
    }

    if (
      pathname === "/api/admin/services/disable" &&
      method === "POST"
    ) {
      return adminDisableService(request, env);
    }

    if (
      pathname === "/api/admin/services/enable" &&
      method === "POST"
    ) {
      return adminEnableService(request, env);
    }

    if (
      pathname === "/api/admin/members/list" &&
      method === "GET"
    ) {
      return adminListMembers(url, env);
    }

    if (
      pathname === "/api/admin/events" &&
      method === "GET"
    ) {
      return adminListEvents(url, env);
    }

    return notFound();
  }

  // HTTP relay
  const relayRoute = getProxyRoute(pathname);

  if (relayRoute) {
    const slug = validateSlug(relayRoute.slug);

    if (!slug) return error("Invalid service slug", 400);

    const service = await findService(env, slug);

    if (!service || !(await canUseService(env, service, identity))) {
      return error("Service not found or access denied", 403);
    }

    return relayHttp(
      request,
      env,
      identity,
      service,
      relayRoute.servicePath,
    );
  }

  // WebSocket relay
  const websocketPrefix = "/api/ws/";

  if (pathname.startsWith(websocketPrefix)) {
    const remainder = pathname.slice(websocketPrefix.length);
    const slashIndex = remainder.indexOf("/");

    const rawSlug =
      slashIndex === -1
        ? remainder
        : remainder.slice(0, slashIndex);

    const servicePath =
      slashIndex === -1
        ? "/"
        : remainder.slice(slashIndex);

    const slug = validateSlug(rawSlug);

    if (!slug) return error("Invalid service slug", 400);

    const service = await findService(env, slug);

    if (!service || !(await canUseService(env, service, identity))) {
      return error("Service not found or access denied", 403);
    }

    const normalizedPath = normalizeProxyPath(servicePath);

    if (!normalizedPath) {
      return error("Invalid service path", 400);
    }

    const allowedPaths = parseAllowedPaths(service.allowed_paths);

    if (
      !allowedPaths ||
      !pathIsAllowed(normalizedPath, allowedPaths)
    ) {
      return error("This path is not allowed for this service", 403);
    }

    const origin = validateOrigin(service.origin);

    if (!origin) {
      return error("Service origin configuration is invalid", 500);
    }

    const upstreamUrl = new URL(origin);
    upstreamUrl.pathname = normalizedPath;
    upstreamUrl.search = url.search;

    try {
      return await relayWebSocket(request, upstreamUrl);
    } catch {
      return error("WebSocket relay failed", 502);
    }
  }

  return notFound();
}

// ------------------------------------------------------------
// Main Worker
// ------------------------------------------------------------

export default {
  async fetch(
    request: Request,
    env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    // Public health endpoint. It reveals no account or service data.
    if (url.pathname === "/health") {
      return json({
        status: "ok",
        service: "private-proxy",
      });
    }

    // API routes always require Cloudflare Access authentication.
    if (url.pathname.startsWith("/api/")) {
      const identity = await authenticate(request, env);

      if (!identity) {
        return error("Authentication required", 401);
      }

      try {
        return await handleApi(request, env, identity);
      } catch {
        return error("Internal server error", 500);
      }
    }

    // Static frontend assets.
    // Protect the site itself with Cloudflare Access as well.
    const identity = await authenticate(request, env);

    if (!identity) {
      return new Response("Authentication required", {
        status: 401,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return methodNotAllowed();
    }

    return env.ASSETS.fetch(request);
  },
};
