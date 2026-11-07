
const RESPONSE_HEADERS = [
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

  for (const name of RESPONSE_HEADERS) {
    if (
      !options.allowRange &&
      (name === "content-range" || name === "accept-ranges")
    ) {
      continue;
    }

    const value = upstream.headers.get(name);

    if (value) {
      headers.set(name, value);
    }
  }

  headers.set("X-Content-Type-Options", "nosniff");

  headers.set(
    "Cache-Control",
    options.cache ? "private, max-age=30" : "no-store"
  );

  // Set-Cookieや認証関連ヘッダーは転送しない
  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers
  });
}
