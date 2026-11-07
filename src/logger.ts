
export interface AccessLog {
  email: string;
  serviceSlug: string;
  method: string;
  status: number;
}

export async function writeAccessLog(
  db: D1Database,
  event: AccessLog
): Promise<void> {
  const email = event.email.toLowerCase().slice(0, 254);
  const slug = event.serviceSlug.slice(0, 48);
  const method = event.method.slice(0, 10);
  const status = Math.max(100, Math.min(599, event.status));

  await db.prepare(`
    INSERT INTO access_events
      (email, service_slug, method, status)
    VALUES (?, ?, ?, ?)
  `).bind(email, slug, method, status).run();
}
