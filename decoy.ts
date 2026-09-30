/**
 * Decoy & Active-Probing Mitigation Engine for Deno Deploy
 */

export function handleDecoyTraffic(request: Request, url: URL): Response {
  const path = url.pathname.toLowerCase();

  // هندلینگ استاندارد درخواست‌های OPTIONS
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type, X-API-Key, Range",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  // فایل استاندارد robots.txt[cite: 3]
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

  // آیکون استاندارد favicon.ico[cite: 3]
  if (path === "/favicon.ico") {
    const svgIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><circle cx="16" cy="16" r="14" fill="#0284c7"/><path d="M10 17l4 4 8-8" stroke="#ffffff" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
    return new Response(svgIcon, {
      status: 200,
      headers: {
        "Content-Type": "image/svg+xml",
        "Cache-Control": "public, max-age=604800",
      },
    });
  }

  // اندپوینت‌های مانیتورینگ عمومی بدون افشای ساختار پروکسی[cite: 3]
  if (path === "/health" || path === "/healthz" || path === "/ping") {
    return new Response(
      JSON.stringify({
        status: "operational",
        service: "Edge-Mesh-Ingress",
        version: "4.3.1-lts",
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
        latency_p99: "3.8ms",
        uptime_30d: "99.995%",
        engine: "EdgeCore V8",
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

  // صفحه اصلی پورتال شرکتی معتبر
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

  // پاسخ ۴۰۴ وب‌سرور استاندارد جهت مقابله با اسکنرهای مسیر
  return new Response(renderStandardNotFoundPage(url.pathname), {
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
  <title>ApexEdge | High-Performance Cloud Ingestion Gateway</title>
  <meta name="description" content="Distributed real-time telemetry routing mesh, edge acceleration and API gateway.">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f293d;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --accent: #10b981;
      --font: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; font-family: var(--font); }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    header { border-bottom: 1px solid var(--border); padding: 18px 32px; display: flex; justify-content: space-between; align-items: center; }
    .brand { font-size: 20px; font-weight: 700; display: flex; align-items: center; gap: 10px; color: #fff; }
    .status-pill { display: inline-flex; align-items: center; gap: 8px; background: #064e3b33; color: #34d399; border: 1px solid #05966944; padding: 5px 14px; border-radius: 9999px; font-size: 12px; font-weight: 500; }
    .dot { width: 8px; height: 8px; background: var(--accent); border-radius: 50%; box-shadow: 0 0 10px var(--accent); }
    main { max-width: 1040px; margin: 0 auto; padding: 60px 24px; flex: 1; }
    .hero { text-align: center; margin-bottom: 60px; }
    .hero h1 { font-size: 38px; font-weight: 800; margin-bottom: 16px; background: linear-gradient(135deg, #ffffff 40%, #93c5fd 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .hero p { font-size: 16px; color: var(--text-muted); max-width: 640px; margin: 0 auto; line-height: 1.6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; margin-bottom: 40px; }
    .card { background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px; padding: 26px; }
    .card h3 { font-size: 16px; font-weight: 600; margin-bottom: 8px; color: #fff; }
    .card p { font-size: 14px; color: var(--text-muted); line-height: 1.5; }
    .code-box { background: #050811; border: 1px solid var(--border); border-radius: 8px; padding: 16px; font-family: monospace; font-size: 13px; color: #93c5fd; overflow-x: auto; margin-top: 12px; }
    footer { border-top: 1px solid var(--border); padding: 20px 32px; font-size: 13px; color: var(--text-muted); display: flex; justify-content: space-between; }
  </style>
</head>
<body>
  <header>
    <div class="brand">
      <span>ApexEdge Mesh</span>
    </div>
    <div class="status-pill">
      <span class="dot"></span>
      <span>Cluster Operational (99.99%)</span>
    </div>
  </header>
  <main>
    <div class="hero">
      <h1>Global Telemetry & Edge Ingress Layer</h1>
      <p>High-concurrency anycast endpoint network providing zero-latency ingress routing, automated failover, and cryptographic request verification.</p>
    </div>
    <div class="grid">
      <div class="card">
        <h3>Anycast Edge Termination</h3>
        <p>Low-latency telemetry endpoints terminating sessions at geodistributed network edges globally.</p>
      </div>
      <div class="card">
        <h3>Cryptographic Ingress</h3>
        <p>Zero-trust bearer token authentication with automated replay prevention and anti-scan filters.</p>
      </div>
      <div class="card">
        <h3>Dynamic Stream Multiplexing</h3>
        <p>Architected for microservice and event-driven data streaming over persistent HTTP/2 channels.</p>
      </div>
    </div>
    <div class="card">
      <h3>Active Health & Readiness Verification</h3>
      <p>System monitors may verify endpoint availability via HTTP GET ping:</p>
      <div class="code-box">curl -s https://${host}/health</div>
    </div>
  </main>
  <footer>
    <div>&copy; 2026 ApexEdge Cloud Infrastructure Ltd. All rights reserved.</div>
    <div>Runtime: Edge-V8</div>
  </footer>
</body>
</html>`;
}

function renderStandardNotFoundPage(path: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>404 Not Found</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 15% 0; background: #fff; color: #222; }
    h1 { font-size: 24px; margin-bottom: 8px; }
    hr { max-width: 500px; border: 0; border-top: 1px solid #ccc; margin: 15px auto; }
    p { font-size: 14px; color: #666; }
  </style>
</head>
<body>
  <h1>404 Not Found</h1>
  <p>The endpoint <code>${path}</code> does not exist on this cluster.</p>
  <hr>
  <p>LiteSpeed Web Server</p>
</body>
</html>`;
}
