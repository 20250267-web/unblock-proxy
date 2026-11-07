
const SAFE_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "content-range",
  "accept-ranges",
  "last-modified",
  "etag"
];

export function createStreamingResponse(
  upstream: Response,
  options: {
    allowRange?: boolean;
    cache?: boolean;
  } = {}
): Response {
  const headers = new Headers();

  for (const name of SAFE_RESPONSE_HEADERS) {
    if (name === "content-range" || name === "accept-ranges") {
      if (!options.allowRange) continue;
    }

    const value = upstream.headers.get(name);
    if (value) headers.set(name, value);
  }

  headers.set("X-Content-Type-Options", "nosniff");
  headers.set(
    "Cache-Control",
    options.cache ? "private, max-age=30" : "no-store"
  );

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers
  });
}
