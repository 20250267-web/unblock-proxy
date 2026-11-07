
export async function relayWebSocket(
  request: Request,
  upstreamUrl: URL
): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method Not Allowed", {
      status: 405
    });
  }

  if (
    request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
  ) {
    return new Response("WebSocket upgrade required", {
      status: 426
    });
  }

  if (upstreamUrl.protocol !== "https:") {
    return new Response("HTTPS upstream required", {
      status: 400
    });
  }

  const headers = new Headers();

  headers.set("Upgrade", "websocket");

  const protocol = request.headers.get("Sec-WebSocket-Protocol");
  if (protocol) {
    headers.set("Sec-WebSocket-Protocol", protocol);
  }

  try {
    const upstream = await fetch(upstreamUrl.toString(), {
      method: "GET",
      headers
    });

    if (upstream.status !== 101) {
      return new Response("Upstream WebSocket unavailable", {
        status: 502
      });
    }

    const clientSocket = (upstream as Response & {
      webSocket?: WebSocket;
    }).webSocket;

    if (!clientSocket) {
      return new Response("WebSocket unavailable", {
        status: 502
      });
    }

    return new Response(null, {
      status: 101,
      webSocket: clientSocket
    } as ResponseInit);
  } catch {
    return new Response("WebSocket connection failed", {
      status: 502
    });
  }
}
