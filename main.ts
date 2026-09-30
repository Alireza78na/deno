/**
 * ==============================================================================
 * ApexEdge Gateway - High-Performance Edge API Mesh (Deno Deploy)
 * Dual-Mode: Enterprise Camouflage Decoy + Authenticated Upstream Proxy
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

  // ۱. استخراج شناسه نود
  let targetNode = request.headers.get("X-Target-Node")?.toLowerCase()?.trim();

  // بررسی مسیر در صورتی که هدر ست نشده باشد (مثلاً /s1/path)
  if (!targetNode) {
    const pathSegments = url.pathname.split("/").filter(Boolean);
    if (pathSegments.length > 0 && ALLOWED_NODES.has(pathSegments[0].toLowerCase())) {
      targetNode = pathSegments[0].toLowerCase();
      url.pathname = "/" + pathSegments.slice(1).join("/");
    }
  }

  // بررسی سابدامین درخواست در صورتی که دامنه Wildcard روی Deno ست شده باشد
  if (!targetNode) {
    const hostParts = url.hostname.split(".");
    if (hostParts.length > 2 && ALLOWED_NODES.has(hostParts[0].toLowerCase())) {
      targetNode = hostParts[0].toLowerCase();
    }
  }

  if (!targetNode || !ALLOWED_NODES.has(targetNode)) {
    return new Response(
      JSON.stringify({ error: "Invalid or missing upstream target node", code: "ROUTING_FAILED" }),
      {
        status: 502,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }
    );
  }

  // ۲. ساخت آدرس مقصد در سرور بالادستی
  const upstreamHostname = `${targetNode}.${targetDomain}`;
  const upstreamUrl = new URL(url.pathname + url.search, `https://${upstreamHostname}:443`);

  // ۳. پاکسازی و آماده‌سازی هدرها
  const upstreamHeaders = new Headers(request.headers);
  upstreamHeaders.set("Host", upstreamHostname);

  upstreamHeaders.delete("Authorization");
  upstreamHeaders.delete("X-API-Key");
  upstreamHeaders.delete("X-Sub-Auth");
  upstreamHeaders.delete("X-Target-Node");
  upstreamHeaders.delete("X-Slice-Offset");
  upstreamHeaders.delete("X-Slice-Length");

  // دریافت و فوروارد آی‌پی کاربر
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

    // پشتیبانی کامل از برش بایتی (Range Slicing)
    const sliceOffsetHeader = request.headers.get("X-Slice-Offset");
    const sliceLengthHeader = request.headers.get("X-Slice-Length");
    const rangeHeader = request.headers.get("Range");

    let finalBody: ArrayBuffer = fullBody;
    let statusCode = upstreamResponse.status;
    const responseHeaders = new Headers(upstreamResponse.headers);

    // حذف هدرهای اتصال و رمزنگاری بافر
    responseHeaders.delete("content-encoding");
    responseHeaders.delete("transfer-encoding");
    responseHeaders.delete("content-length");
    responseHeaders.delete("connection");
    responseHeaders.delete("keep-alive");

    if (sliceOffsetHeader !== null && sliceLengthHeader !== null) {
      const offset = parseInt(sliceOffsetHeader, 10) || 0;
      const length = parseInt(sliceLengthHeader, 10) || 4000;
      const totalSize = fullBody.byteLength;

      const end = Math.min(offset + length, totalSize);
      finalBody = fullBody.slice(offset, end);
      statusCode = 206; // Partial Content

      responseHeaders.set("Content-Range", `bytes ${offset}-${end - 1}/${totalSize}`);
      responseHeaders.set("X-Total-Bytes", totalSize.toString());
    } else if (rangeHeader && rangeHeader.startsWith("bytes=")) {
      const parts = rangeHeader.replace("bytes=", "").split("-");
      const start = parseInt(parts[0], 10) || 0;
      const totalSize = fullBody.byteLength;
      const end = parts[1] ? parseInt(parts[1], 10) + 1 : totalSize;

      finalBody = fullBody.slice(start, Math.min(end, totalSize));
      statusCode = 206;
      responseHeaders.set("Content-Range", `bytes ${start}-${Math.min(end, totalSize) - 1}/${totalSize}`);
      responseHeaders.set("X-Total-Bytes", totalSize.toString());
    }

    // حفظ سرفصل حیاتی مشخصات کاربر برای کلاینت‌ها
    const subInfo = upstreamResponse.headers.get("Subscription-Userinfo");
    if (subInfo) {
      responseHeaders.set("Subscription-Userinfo", subInfo);
    }

    // هدرهای بهینه‌سازی و عدم ذخیره در کش
    responseHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    responseHeaders.set("X-Edge-Origin", "Apex-Deno-Mesh");

    return new Response(finalBody, {
      status: statusCode,
      statusText: statusCode === 206 ? "Partial Content" : upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (err: unknown) {
    const errorDetails = err instanceof Error ? err.message : String(err);
    return new Response(
      JSON.stringify({
        error: "Upstream Proxy Exception",
        details: errorDetails,
        code: "GATEWAY_TIMEOUT",
      }),
      {
        status: 502,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }
    );
  }
}

// ثبت سرور بومی دینو با کارایی بالا
Deno.serve(async (request: Request, info: Deno.ServeHandlerInfo): Promise<Response> => {
  const url = new URL(request.url);
  const secretToken = Deno.env.get("SUB_AUTH_TOKEN") || DEFAULT_SECRET_TOKEN;

  // مرحله ۱: اعتبارسنجی توکن لایه امنیتی
  const isAuthenticated = verifyAuthentication(request, url, secretToken);

  // مرحله ۲: فعال‌سازی مود استتار در صورت عدم احراز هویت
  if (!isAuthenticated) {
    return handleDecoyTraffic(request, url);
  }

  // مرحله ۳: هدایت درخواست احراز هویت شده به نود مورد نظر
  return await handleProxyRequest(request, url, info);
});
