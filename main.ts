import { serveDecoy } from "./decoy.ts";

// ==========================================
// CONFIGURATION & CONSTANTS
// ==========================================
const DEFAULT_SECRET_TOKEN = "LY8hvDZPaM4CyXXJMP3FgPQsUXinYp3nHC8Nd";
const DEFAULT_TARGET_DOMAIN = "fp-network.link";

const SECRET_TOKEN = Deno.env.get("SECRET_TOKEN") || DEFAULT_SECRET_TOKEN;
const TARGET_DOMAIN = Deno.env.get("TARGET_DOMAIN") || DEFAULT_TARGET_DOMAIN;

const ALLOWED_NODES = new Set<string>([
  "s1",
  "s2",
  "s3",
  "s4",
  "s5",
  "s6",
  "s7",
]);

// Headers allowed to be mirrored back from X-ui to Iranian cPanel Host
const ALLOWED_RESPONSE_HEADERS = new Set<string>([
  "content-type",
  "content-length",
  "subscription-userinfo",
  "profile-update-interval",
  "profile-title",
  "profile-web-page-url",
  "content-disposition",
  "cache-control",
  "etag",
  "last-modified",
]);

// Upstream request timeout in milliseconds
const UPSTREAM_TIMEOUT_MS = 12000;

// ==========================================
// UTILITY FUNCTIONS
// ==========================================

/**
 * Constant-time string equality check to prevent side-channel timing attacks.
 * Hashing with SHA-256 ensures equal buffer length for timingSafeEqual.
 */
async function timingSafeEqualStrings(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);

  const [aHash, bHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", aBuf),
    crypto.subtle.digest("SHA-256", bBuf),
  ]);

  return crypto.subtle.timingSafeEqual(aHash, bHash);
}

/**
 * Extract target node identifier from request headers, path prefix, or query parameters.
 */
function resolveNodeAndPath(url: URL, req: Request): { node: string | null; targetPath: string } {
  // 1. Direct header lookup (Preferred)
  const headerNode = req.headers.get("x-target-node")?.toLowerCase().trim();
  if (headerNode && ALLOWED_NODES.has(headerNode)) {
    return {
      node: headerNode,
      targetPath: url.pathname + url.search,
    };
  }

  // 2. Query param lookup (?node=s1)
  const queryNode = url.searchParams.get("node")?.toLowerCase().trim();
  if (queryNode && ALLOWED_NODES.has(queryNode)) {
    const cleanParams = new URLSearchParams(url.searchParams);
    cleanParams.delete("node");
    const searchString = cleanParams.toString() ? `?${cleanParams.toString()}` : "";
    return {
      node: queryNode,
      targetPath: url.pathname + searchString,
    };
  }

  // 3. Path prefix lookup (/s1/sub/... or /s1/api/...)
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length > 0 && ALLOWED_NODES.has(segments[0].toLowerCase())) {
    const node = segments[0].toLowerCase();
    const remainingPath = "/" + segments.slice(1).join("/");
    return {
      node: node,
      targetPath: remainingPath + url.search,
    };
  }

  // 4. Host header subdomain lookup (e.g., s1.sub.fp-network.ir)
  const host = req.headers.get("host")?.toLowerCase() || "";
  const firstSubdomain = host.split(".")[0];
  if (ALLOWED_NODES.has(firstSubdomain)) {
    return {
      node: firstSubdomain,
      targetPath: url.pathname + url.search,
    };
  }

  return { node: null, targetPath: url.pathname + url.search };
}

/**
 * Extract auth token from custom header, Authorization header, or URL query.
 */
function extractAuthToken(req: Request, url: URL): string | null {
  const headerSecret = req.headers.get("x-proxy-secret");
  if (headerSecret) {
    return headerSecret.trim();
  }

  const authHeader = req.headers.get("authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }

  const querySecret = url.searchParams.get("secret");
  if (querySecret) {
    return querySecret.trim();
  }

  return null;
}

// ==========================================
// CORE SERVER HANDLER
// ==========================================

Deno.serve(async (req: Request): Promise<Response> => {
  const url = new URL(req.url);

  // 1. Authenticate Request
  const providedToken = extractAuthToken(req, url);
  if (!providedToken) {
    return await serveDecoy(req);
  }

  const isTokenValid = await timingSafeEqualStrings(providedToken, SECRET_TOKEN);
  if (!isTokenValid) {
    return await serveDecoy(req);
  }

  // 2. Resolve Destination Node
  const { node, targetPath } = resolveNodeAndPath(url, req);
  if (!node || !ALLOWED_NODES.has(node)) {
    return await serveDecoy(req);
  }

  // 3. Construct Upstream Target URL
  const targetHost = `${node}.${TARGET_DOMAIN}`;
  const targetUrl = `https://${targetHost}${targetPath}`;

  // 4. Prepare Forwarded Headers (Sanitize upstream request)
  const forwardHeaders = new Headers();
  for (const [key, value] of req.headers.entries()) {
    const lowerKey = key.toLowerCase();
    // Strip internal and sensitive proxy headers
    if (
      lowerKey === "host" ||
      lowerKey === "x-proxy-secret" ||
      lowerKey === "x-target-node" ||
      lowerKey === "authorization" ||
      lowerKey === "cf-connecting-ip" ||
      lowerKey === "x-forwarded-for" ||
      lowerKey === "x-real-ip"
    ) {
      continue;
    }
    forwardHeaders.set(key, value);
  }

  // Set explicit Host header for accurate SNI / VHost routing on X-ui
  forwardHeaders.set("Host", targetHost);

  // 5. Execute Upstream Request with Timeout
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);

  try {
    const upstreamResponse = await fetch(targetUrl, {
      method: req.method,
      headers: forwardHeaders,
      body: req.method !== "GET" && req.method !== "HEAD" ? req.body : undefined,
      redirect: "manual",
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    // 6. Build Clean Sanitized Response Headers
    const responseHeaders = new Headers();
    for (const [key, value] of upstreamResponse.headers.entries()) {
      if (ALLOWED_RESPONSE_HEADERS.has(key.toLowerCase())) {
        responseHeaders.set(key, value);
      }
    }

    // Security & anti-fingerprint headers
    responseHeaders.set("x-content-type-options", "nosniff");
    responseHeaders.set("access-control-allow-origin", "*");

    // 7. Mirror Exact Status Code and Payload
    return new Response(upstreamResponse.body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (err: unknown) {
    clearTimeout(timeoutId);

    const isTimeout =
      err instanceof DOMException && err.name === "AbortError";

    const errorStatusCode = isTimeout ? 504 : 502;
    const errorStatusText = isTimeout ? "Gateway Timeout" : "Bad Gateway";
    const errorMessage = isTimeout
      ? "Upstream Node Timeout: Target node did not respond within the deadline."
      : "Upstream Node Unreachable: Unable to establish TLS connection with target node.";

    // Masked, production-safe diagnostic error for Iranian host
    return new Response(
      JSON.stringify({
        status: errorStatusCode,
        node: node,
        error: errorStatusText,
        message: errorMessage,
      }),
      {
        status: errorStatusCode,
        statusText: errorStatusText,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "x-content-type-options": "nosniff",
        },
      }
    );
  }
});
