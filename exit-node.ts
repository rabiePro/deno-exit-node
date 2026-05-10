// mhrv-rs exit node — deploy as an HTTP endpoint on any serverless
// TypeScript host with a public IP that isn't a Google datacenter
// (Deno Deploy, fly.io, your own VPS, etc.). Uses only web-standard
// `Request` / `Response` / `fetch` so it's portable across runtimes.
//
// Purpose: chain client → Apps Script → this exit node → destination.
// Apps Script's UrlFetchApp can't reach Cloudflare-protected sites that
// flag Google datacenter IPs as bots (chatgpt.com, claude.ai, grok.com,
// many other CF-fronted SaaS). This exit node sits between Apps Script
// and the destination; the destination sees the exit node's outbound IP
// (generally not flagged as Google datacenter) and accepts the request.
//
// Setup:
//   1. Pick a host that runs web-standard fetch handlers (e.g. Deno
//      Deploy, fly.io with a thin server wrapper, or any cheap VPS
//      running Deno / Node + this script as a handler).
//   2. Paste the contents of this file as the request handler.
//   3. Set PSK below to a strong secret (`openssl rand -hex 32` from
//      a terminal — DO NOT leave the placeholder in production).
//   4. Deploy and copy the public URL of the deployed handler.
//   5. In mhrv-rs config.json, add:
//        "exit_node": {
//          "enabled": true,
//          "relay_url": "https://your-deployed-exit-node.example.com",
//          "psk": "<the same PSK you set above>",
//          "mode": "selective",
//          "hosts": ["chatgpt.com", "claude.ai", "x.com", "grok.com"]
//        }
//
// Threat model: PSK is the only thing keeping this from being an open
// proxy on the public internet. Treat it like a password: do not commit
// to source control, do not share publicly, rotate if leaked. The exit
// node refuses all requests that don't carry the matching PSK.
//
// Failure mode: if the exit node is unreachable, mhrv-rs falls back to
// the regular Apps Script relay automatically — the only consequence
// of an offline exit node is that ChatGPT/Claude/Grok stop working;
// other sites are unaffected.

// ============================================
// SIMPLIFIED EXIT NODE FOR DENO DEPLOY
// ============================================

const PSK = "mySuperSecretPassword123!";

Deno.serve(async (req: Request) => {
  // 1. Only accept POST requests
  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "method_not_allowed" }),
      { status: 405, headers: { "content-type": "application/json" } }
    );
  }

  // 2. Parse body once (for auth and data)
  let body;
  try {
    body = await req.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "invalid_json" }),
      { status: 400, headers: { "content-type": "application/json" } }
    );
  }

  // 3. Check authentication - try headers OR body.k
  const authHeader = req.headers.get("x-upstream-auth") || 
                     req.headers.get("authorization");
  const authKey = authHeader || body?.k;
  
  if (authKey !== PSK) {
    return new Response(
      JSON.stringify({ error: "unauthorized" }),
      { status: 401, headers: { "content-type": "application/json" } }
    );
  }

  // 4. Get request details
  const { u: url, m: method = "GET", h: headers = {}, b: bodyData } = body;

  // 5. Validate URL
  if (!url || !url.startsWith("http")) {
    return new Response(
      JSON.stringify({ error: "invalid_url" }),
      { status: 400, headers: { "content-type": "application/json" } }
    );
  }

  // 6. Forward the request
  try {
    const fetchOptions: RequestInit = {
      method: method.toUpperCase(),
      headers: headers,
    };
    
    if (bodyData) {
      fetchOptions.body = bodyData;
    }

    const response = await fetch(url, fetchOptions);
    const responseBody = await response.text();

    return new Response(responseBody, {
      status: response.status,
      headers: {
        "content-type": response.headers.get("content-type") || "text/plain",
      },
    });
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      { status: 500, headers: { "content-type": "application/json" } }
    );
  }
});
