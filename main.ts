/**
 * ==============================================================================
 * ApexEdge Gateway - High-Performance Edge API Mesh (Deno Deploy)
 * Hardened Edge Routing, Header Sanitization & Zero-Information Decoy
 * ==============================================================================
 */

import { handleDecoyTraffic } from "./decoy.ts";

const DEFAULT_SECRET_TOKEN = "LY8hvDZPaM4CyXXJMP3FgPQsUXinYp3nHC8Nd";
const DEFAULT_TARGET_DOMAIN = "fp-network.link";
const ALLOWED_NODES = new Set(["s1", "s2", "s3", "s4", "s5", "s6", "s7"]);

function verifyAuthentication(request: Request, url: URL, secretToken: string): boolean {
  const authHeader = request.headers.get("Authorization");
  const apiKey = request.headers.get("X-API-Key");
  const subAuth = request.headers.get("X-Sub-Auth");
  const queryToken = url.searchParams.get("token") || url.searchParams.get("auth");

  if (authHeader && authHeader.startsWith("Bearer ")) {
    if (authHeader.substring(7).trim() === secretToken) return true;
  }
  if (apiKey && apiKey.trim() === secretToken) return true;
  if (subAuth && subAuth.trim() === secretToken) return true;
  if (queryToken && queryToken.trim() === secretToken) return true;

  return false;
}

async function handleProxyRequest(
  request: Request,
  url: URL,
  info: Deno.ServeHandlerInfo
): Promise<Response> {
  const targetDomain = Deno.env.get("TARGET_DOMAIN") || DEFAULT_TARGET_DOMAIN;

  // ۱. شناسایی نود مقصد از روی هدر یا پارامترهای ارسالی
  let targetNode = request.headers.get("X-Target-Node")?.toLowerCase()?.trim();

  if (!targetNode) {
    const pathSegments = url.pathname.split("/").filter(Boolean);
    if (pathSegments.length > 0 && ALLOWED_NODES.has(pathSegments[0].toLowerCase())) {
      targetNode = pathSegments[0].toLowerCase();
      url.pathname = "/" + pathSegments.slice(1).join("/");
    }
  }

  if (!targetNode) {
    const hostParts = url.hostname.split(".");
    if (hostParts.length > 2 && ALLOWED_NODES.has(hostParts[0].toLowerCase())) {
      targetNode = hostParts[0].toLowerCase();
    }
  }

  if (!targetNode || !ALLOWED_NODES.has(targetNode)) {
    return new Response(renderWebserverErrorPage(404, "Not Found"), {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ۲. آدرس‌دهی دقیق به سرور بالادستی
  const upstreamHostname = `${targetNode}.${targetDomain}`;
  const upstreamUrl = new URL(url.pathname + url.search, `https://${upstreamHostname}:443`);

  // ۳. پاکسازی هدرها و حذف سرنخ‌های پروتکل
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.set("Host", upstreamHostname);

  upstreamHeaders.delete("Authorization");
  upstreamHeaders.delete("X-API-Key");
  upstreamHeaders.delete("X-Sub-Auth");
  upstreamHeaders.delete("X-Target-Node");
  upstreamHeaders.delete("X-Slice-Offset");
  upstreamHeaders.delete("X-Slice-Length");

  const clientIP =
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Real-IP") ||
    (info.remoteAddr as Deno.NetAddr)?.hostname;

  if (clientIP) {
    upstreamHeaders.set("X-Real-IP", clientIP);
    const existingXff = request.headers.get("X-Forwarded-For");
    upstreamHeaders.set("X-Forwarded-For", existingXff ? `${existingXff}, ${clientIP}` : clientIP);
    upstreamHeaders.set("X-Forwarded-Proto", "https");
  }

  try {
    const upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: request.method,
      headers: upstreamHeaders,
      body: request.method !== "GET" && request.method !== "HEAD" ? request.body : undefined,
      redirect: "manual",
    });

    const fullBody = await upstreamResponse.arrayBuffer();

    // پشتیبانی از بایت‌رنج (Byte Slicing)[cite: 3]
    const sliceOffsetHeader = request.headers.get("X-Slice-Offset");
    const sliceLengthHeader = request.headers.get("X-Slice-Length");
    const rangeHeader = request.headers.get("Range");

    let finalBody: ArrayBuffer = fullBody;
    let statusCode = upstreamResponse.status;
    const responseHeaders = new Headers(upstreamResponse.headers);

    responseHeaders.delete("content-encoding");
    responseHeaders.delete("transfer-encoding");
    responseHeaders.delete("content-length");
    responseHeaders.delete("connection");
    responseHeaders.delete("keep-alive");
    responseHeaders.delete("server"); // حذف ردپای وب‌سرور نود

    if (sliceOffsetHeader !== null && sliceLengthHeader !== null) {
      const offset = parseInt(sliceOffsetHeader, 10) || 0;
      const length = parseInt(sliceLengthHeader, 10) || 4000;
      const totalSize = fullBody.byteLength;

      const end = Math.min(offset + length, totalSize);
      finalBody = fullBody.slice(offset, end);
      statusCode = 206;

      responseHeaders.set("Content-Range", `bytes ${offset}-${end - 1}/${totalSize}`);
    } else if (rangeHeader && rangeHeader.startsWith("bytes=")) {
      const parts = rangeHeader.replace("bytes=", "").split("-");
      const start = parseInt(parts[0], 10) || 0;
      const totalSize = fullBody.byteLength;
      const end = parts[1] ? parseInt(parts[1], 10) + 1 : totalSize;

      finalBody = fullBody.slice(start, Math.min(end, totalSize));
      statusCode = 206;
      responseHeaders.set("Content-Range", `bytes ${start}-${Math.min(end, totalSize) - 1}/${totalSize}`);
    }

    // هدایت ایمن سرفصل مشخصات اکانت کاربر[cite: 3]
    const subInfo = upstreamResponse.headers.get("Subscription-Userinfo");
    if (subInfo) {
      responseHeaders.set("Subscription-Userinfo", subInfo);
    }

    // هدرهای عمومی بهینه‌سازی
    responseHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    responseHeaders.set("Pragma", "no-cache");

    return new Response(finalBody, {
      status: statusCode,
      statusText: statusCode === 206 ? "Partial Content" : upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (_err: unknown) {
    // بازگرداندن صفحه وب‌سرور استاندارد در زمان خطای بالادست
    return new Response(renderWebserverErrorPage(502, "Bad Gateway"), {
      status: 502,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
}

function renderWebserverErrorPage(code: number, text: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>${code} ${text}</title>
  <style>
    body { font-family: Arial, sans-serif; text-align: center; padding: 15% 0; background: #fff; color: #222; }
    h1 { font-size: 24px; margin-bottom: 8px; }
    hr { max-width: 500px; border: 0; border-top: 1px solid #ccc; margin: 15px auto; }
    p { font-size: 14px; color: #666; }
  </style>
</head>
<body>
  <h1>${code} ${text}</h1>
  <p>The requested service is unreachable or returned an invalid response.</p>
  <hr>
  <p>LiteSpeed Web Server</p>
</body>
</html>`;
}

// ثبت وب‌سرور اصلی دینو
Deno.serve(async (request: Request, info: Deno.ServeHandlerInfo): Promise<Response> => {
  const url = new URL(request.url);
  const secretToken = Deno.env.get("SUB_AUTH_TOKEN") || DEFAULT_SECRET_TOKEN;

  // مرحله ۱: بررسی اعتبارسنجی
  const isAuthenticated = verifyAuthentication(request, url, secretToken);

  // مرحله ۲: هدایت پروب‌ها و درخواست‌های ناشناس به استتار
  if (!isAuthenticated) {
    return handleDecoyTraffic(request, url);
  }

  // مرحله ۳: عبور ترافیک معتبر و پروکسی به پنل X-UI
  return await handleProxyRequest(request, url, info);
});
