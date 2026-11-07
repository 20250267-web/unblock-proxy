
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
    request.headers.get("Upgrade")?.toLowerCase() !==
    "websocket"
  ) {
    return new Response("WebSocket upgrade required", {
      status: 426
    });
  }

  if (upstreamUrl.protocol !== "https:") {
    return new Response("HTTPS required", {
      status: 400
    });
  }

  const headers = new Headers({
    Upgrade: "websocket"
  });

  const protocol = request.headers.get(
    "Sec-WebSocket-Protocol"
  );

  if (protocol) {
    headers.set("Sec-WebSocket-Protocol", protocol);
  }

  let upstreamResponse: Response;

  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: "GET",
      headers,
      redirect: "manual"
    });
  } catch {
    return new Response("Upstream connection failed", {
      status: 502
    });
  }

  if (upstreamResponse.status !== 101) {
    return new Response("Upstream WebSocket unavailable", {
      status: 502
    });
  }

  const upstreamSocket = (
    upstreamResponse as Response & {
      webSocket?: WebSocket;
    }
  ).webSocket;

  if (!upstreamSocket) {
    return new Response("WebSocket unavailable", {
      status: 502
    });
  }

  const pair = new WebSocketPair();
  const clientSocket = pair[0];
  const workerSocket = pair[1];

  workerSocket.accept();
  upstreamSocket.accept();

  let closed = false;

  const closeBoth = (
    code = 1000,
    reason = "Connection closed"
  ) => {
    if (closed) return;

    closed = true;

    try {
      workerSocket.close(code, reason);
    } catch {
      // Already closed
    }

    try {
      upstreamSocket.close(code, reason);
    } catch {
      // Already closed
    }
  };

  workerSocket.addEventListener("message", event => {
    if (closed) return;

    try {
      upstreamSocket.send(event.data);
    } catch {
      closeBoth(1011, "Upstream send failed");
    }
  });

  upstreamSocket.addEventListener("message", event => {
    if (closed) return;

    try {
      workerSocket.send(event.data);
    } catch {
      closeBoth(1011, "Client send failed");
    }
  });

  workerSocket.addEventListener("close", event => {
    closeBoth(event.code, event.reason);
  });

  upstreamSocket.addEventListener("close", event => {
    closeBoth(event.code, event.reason);
  });

  workerSocket.addEventListener("error", () => {
    closeBoth(1011, "Client socket error");
  });

  upstreamSocket.addEventListener("error", () => {
    closeBoth(1011, "Upstream socket error");
  });

  return new Response(null, {
    status: 101,
    webSocket: clientSocket
  } as ResponseInit);
}
