/**
 * ==============================================================================
 * ApexEdge Gateway - High-Performance Edge API Mesh (Deno Deploy)
 * Zero-Hardcoded Secrets, Active Probing Mitigation & Dynamic Byte Padding
 * ==============================================================================
 */

import { handleDecoyTraffic } from "./decoy.ts";

// استخراج لیست نودهای مجاز از متغیرهای محیطی
const rawAllowedNodes = Deno.env.get("ALLOWED_NODES") || "s1,s2,s3,s4,s5,s6,s7";
const ALLOWED_NODES = new Set(
  rawAllowedNodes.split(",").map((node) => node.trim().toLowerCase())
);

/**
 * اعتبارسنجی احراز هویت درخواست ورودی با کلیدهای امنیتی
 */
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

/**
 * تزریق نویز تصادفی به محتوای سابسکریپشن جهت تغییر پیوسته اندازه بسته و خنثی‌سازی آنالیز آماری DPI
 */
function injectSubscriptionPadding(bodyBytes: ArrayBuffer): ArrayBuffer {
  // تولید طول متغیر برای نویز بین ۲۵۶ تا ۱۲۸۰ بایت در هر درخواست
  const paddingLength = Math.floor(Math.random() * 1024) + 256;
  const randomHex = Array.from(
    crypto.getRandomValues(new Uint8Array(Math.ceil(paddingLength / 2)))
  )
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, paddingLength);

  const text = new TextDecoder().decode(bodyBytes).trim();

  // ۱. فرمت JSON (کانفیگ‌های Sing-box) - افزودن فضای خالی انتهایی طبق استاندارد RFC 8259
  if (text.startsWith("{") || text.startsWith("[")) {
    const paddedText = text + " ".repeat(paddingLength);
    return new TextEncoder().encode(paddedText).buffer;
  }

  // ۲. فرمت YAML (کانفیگ‌های Clash و Mihomo) - افزودن خط کامنت
  if (text.includes("proxies:") || text.includes("mixed-port:") || text.includes("rules:")) {
    const paddedText = text + `\n# padding: ${randomHex}\n`;
    return new TextEncoder().encode(paddedText).buffer;
  }

  // ۳. فرمت Base64 (کانفیگ‌های استاندارد V2Ray و Xray)
  try {
    const binString = atob(text.replace(/\s+/g, ""));
    const decodedBytes = Uint8Array.from(binString, (c) => c.charCodeAt(0));
    const decodedText = new TextDecoder().decode(decodedBytes);

    if (decodedText.includes("://")) {
      const paddedDecoded = decodedText.trimEnd() + `\n# padding: ${randomHex}\n`;
      const encodedBytes = new TextEncoder().encode(paddedDecoded);

      let encodedBinString = "";
      const chunkSize = 8192;
      for (let i = 0; i < encodedBytes.length; i += chunkSize) {
        encodedBinString += String.fromCharCode(
          ...encodedBytes.subarray(i, i + chunkSize)
        );
      }
      const reencodedBase64 = btoa(encodedBinString);

      return new TextEncoder().encode(reencodedBase64).buffer;
    }
  } catch (_e) {
    // در صورت وجود کاراکترهای خارج از محدوده دکود، داده اصلی بدون تغییر بازگردانده می‌شود
  }

  return bodyBytes;
}

/**
 * شبیه‌سازی صفحه خطای استاندارد وب‌سرور برای جلوگیری از افشای هویت سرور
 */
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

/**
 * پردازش و هدایت پروکسی به نودهای بالادست
 */
async function handleProxyRequest(
  request: Request,
  url: URL,
  info: Deno.ServeHandlerInfo
): Promise<Response> {
  const targetDomain = Deno.env.get("TARGET_DOMAIN");
  if (!targetDomain) {
    return new Response(renderWebserverErrorPage(502, "Bad Gateway"), {
      status: 502,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  // ۱. شناسایی شناسه نود
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

  // ۲. ساخت آدرس آپ‌استریم نود
  const upstreamHostname = `${targetNode}.${targetDomain.trim()}`;
  const upstreamUrl = new URL(url.pathname + url.search, `https://${upstreamHostname}:443`);

  // ۳. پالایش و استانداردسازی هدرها
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

    let fullBody = await upstreamResponse.arrayBuffer();

    // تزریق نویز تصادفی فقط بر روی پاسخ‌های موفق
    if (upstreamResponse.status === 200) {
      fullBody = injectSubscriptionPadding(fullBody);
    }

    // پشتیبانی از برش بایتی و استانداردهای HTTP Range
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
    responseHeaders.delete("server");

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

    // هدایت کنترل‌شده هدر مشخصات مصرف کلاینت
    const subInfo = upstreamResponse.headers.get("Subscription-Userinfo");
    if (subInfo) {
      responseHeaders.set("Subscription-Userinfo", subInfo);
    }

    responseHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    responseHeaders.set("Pragma", "no-cache");

    return new Response(finalBody, {
      status: statusCode,
      statusText: statusCode === 206 ? "Partial Content" : upstreamResponse.statusText,
      headers: responseHeaders,
    });
  } catch (_err: unknown) {
    return new Response(renderWebserverErrorPage(502, "Bad Gateway"), {
      status: 502,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }
}

// ثبت سرور بومی دینو
Deno.serve(async (request: Request, info: Deno.ServeHandlerInfo): Promise<Response> => {
  const url = new URL(request.url);
  const secretToken = Deno.env.get("SUB_AUTH_TOKEN");

  // هدایت پیش‌فرض به استتار در صورت تعریف نشدن متغیر توکن
  if (!secretToken) {
    return handleDecoyTraffic(request, url);
  }

  // ۱. اعتبارسنجی توکن
  const isAuthenticated = verifyAuthentication(request, url, secretToken);

  // ۲. هدایت کلیه پروب‌ها و اسکن‌ها به استتار
  if (!isAuthenticated) {
    return handleDecoyTraffic(request, url);
  }

  // ۳. ارسال درخواست اعتبارسنجی شده به نود
  return await handleProxyRequest(request, url, info);
});
