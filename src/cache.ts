
export function noStoreHeaders(
  extra?: HeadersInit
): Headers {
  const headers = new Headers(extra);

  headers.set("Cache-Control", "no-store");
  headers.set("Pragma", "no-cache");
  headers.set("X-Content-Type-Options", "nosniff");

  return headers;
}

export function noStoreResponse(
  body: BodyInit | null,
  status = 200,
  extra?: HeadersInit
): Response {
  return new Response(body, {
    status,
    headers: noStoreHeaders(extra)
  });
}
