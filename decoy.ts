/**
 * Decoy & Camouflage Engine for Deno Deploy
 * Handles unauthenticated requests, health checks, and anti-probe landing pages.
 */

export function handleDecoyTraffic(request: Request, url: URL): Response {
  const path = url.pathname.toLowerCase();

  // هندلینگ پیش‌پرواز CORS و متدهای بازرسی
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-API-Key, X-Sub-Auth, X-Target-Node, X-Slice-Offset, X-Slice-Length",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // فایل robots.txt جهت گمراه‌سازی خزشگرها
  if (path === "/robots.txt") {
    return new Response(
      `User-agent: *\nAllow: /\nDisallow: /api/private/\nSitemap: ${url.origin}/sitemap.xml\n`,
      {
        status: 200,
        headers: {
          "Content-Type": "text/plain; charset=utf-8",
          "Cache-Control": "public, max-age=86400",
        },
      }
    );
  }

  // هندلینگ آیکون فاویکون SVG
  if (path === "/favicon.ico") {
    const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" fill="#2563eb"/><path d="M10 17l4 4 8-8" stroke="#ffffff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    return new Response(svgIcon, {
      status: 200,
      headers: {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "public, max-age=604800",
      },
    });
  }

  // اندپوینت‌های مانیتورینگ سلامت سرویس
  if (path === "/health" || path === "/healthz" || path === "/ping") {
    return new Response(
      JSON.stringify({
        status: "operational",
        service: "ApexEdge-Telemetry-Ingress",
        version: "4.3.0-lts",
        region: Deno.env.get("DENO_REGION") || "global-anycast",
        timestamp: Math.floor(Date.now() / 1000),
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-cache",
        },
      }
    );
  }

  if (path === "/status" || path === "/api/v1/status") {
    return new Response(
      JSON.stringify({
        cluster: "mesh-eu-central",
        nodes_active: 7,
        latency_p99: "4.2ms",
        uptime_30d: "99.992%",
        engine: "EdgeCore Deno V8",
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-cache",
        },
      }
    );
  }

  // صفحه اصلی پورتال شرکتی
  if (path === "/" || path === "/index.html" || path === "/overview" || path === "/docs") {
    return new Response(renderEnterpriseLandingPage(url.host), {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=3600",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
      },
    });
  }

  // صفحه خطای ۴۰۴ ساختاریافته برای مسیرهای ثبت‌نشده
  return new Response(renderBrandedNotFoundPage(url.pathname), {
    status: 404,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function renderEnterpriseLandingPage(host: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ApexEdge | High-Performance Cloud Mesh & Ingestion Gateway</title>
  <meta name="description" content="Global real-time data ingestion, telemetry routing mesh, and edge acceleration network.">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --accent: #10b981;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: var(--font); }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    header { border-bottom: 1px solid var(--border); padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; }
    .brand { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; display: flex; align-items: center; gap: 10px; color: #fff; }
    .brand-badge { background: #2563eb22; color: #60a5fa; border: 1px solid #3b82f644; font-size: 11px; padding: 3px 8px; border-radius: 9999px; font-weight: 600; }
    .status-pill { display: inline-flex; align-items: center; gap: 8px; background: #064e3b33; color: #34d399; border: 1px solid #05966944; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 500; }
    .dot { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 10px var(--accent); }
    main { max-width: 1080px; margin: 0 auto; padding: 60px 24px; flex: 1; }
    .hero { text-align: center; margin-bottom: 60px; }
    .hero h1 { font-size: 42px; font-weight: 800; letter-spacing: -1px; margin-bottom: 16px; background: linear-gradient(135deg, #ffffff 30%, #93c5fd 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { font-size: 17px; color: var(--text-muted); max-width: 640px; margin: 0 auto 30px; line-height: 1.6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; margin-bottom: 50px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 28px; }
    .card h3 { font-size: 17px; font-weight: 600; margin-bottom: 10px; color: #fff; }
    .card p { font-size: 14px; color: var(--text-muted); line-height: 1.5; }
    .code-box { background: #050811; border: 1px solid var(--border); border-radius: 8px; padding: 18px; font-family: monospace; font-size: 13px; color: #93c5fd; overflow-x: auto; margin-top: 15px; }
    footer { border-top: 1px solid var(--border); padding: 24px 32px; font-size: 13px; color: var(--text-muted); display: flex; justify-content: space-between; align-items: center; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>ApexEdge Mesh</span>
      <span class="brand-badge">Enterprise v4.3</span>
    </div>
    <div class="status-pill">
      <span class="dot"></span>
      <span>All Systems Operational (99.99%)</span>
    </div>
  </header>
  <main>
    <div class="hero">
      <h1>Global Ingestion & Edge Telemetry Gateway</h1>
      <p>Distributed zero-trust proxy layer providing sub-millisecond edge routing, TLS 1.3 mutual handshake acceleration, and automated endpoint resilience.</p>
    </div>
    <div class="grid">
      <div class="card">
        <h3>Sub-Millisecond Routing</h3>
        <p>Low-latency telemetry nodes terminating connections at optimal geo-distributed Anycast clusters globally.</p>
      </div>
      <div class="card">
        <h3>Zero-Trust API Ingress</h3>
        <p>Enforced bearer token authorization with automated replay prevention and granular endpoint rate-limiting.</p>
      </div>
      <div class="card">
        <h3>High-Throughput Streaming</h3>
        <p>Engineered for high-concurrency microservice payloads with native HTTP/2 multiplexing and dynamic buffer sizing.</p>
      </div>
    </div>
    <div class="card">
      <h3>Active Health & Diagnostics Endpoint</h3>
      <p>Automated telemetry scanners may verify gateway availability via standard HTTP GET ping:</p>
      <div class="code-box">curl -s https://${host}/health</div>
    </div>
  </main>
  <footer>
    <div>&copy; 2026 ApexEdge Cloud Infrastructure Ltd. All rights reserved.</div>
    <div>Runtime: Deno Edge V8 | Latency: 1.1ms</div>
  </footer>
</body>
</html>`;
}

function renderBrandedNotFoundPage(requestedPath: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 Not Found - ApexEdge Gateway</title>
  <style>
    body { background: #0b0f19; color: #f3f4f6; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .box { text-align: center; max-width: 480px; padding: 32px; background: #111827; border: 1px solid #1f293d; border-radius: 12px; }
    h1 { font-size: 56px; color: #3b82f6; margin-bottom: 8px; font-weight: 800; }
    h2 { font-size: 18px; margin-bottom: 12px; color: #fff; }
    p { font-size: 14px; color: #9ca3af; line-height: 1.6; margin-bottom: 24px; word-break: break-all; }
    a { display: inline-block; background: #2563eb; color: #fff; padding: 10px 20px; border-radius: 8px; text-decoration: none; font-size: 14px; font-weight: 500; }
    a:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <div class="box">
    <h1>404</h1>
    <h2>API Endpoint Not Registered</h2>
    <p>The requested route <code>${requestedPath}</code> was not found on this Edge cluster or requires active bearer credentials.</p>
    <a href="/">Return to Mesh Portal</a>
  </div>
</body>
</html>`;
}
