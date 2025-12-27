/**
 * Cloudflare Worker - Edge Security Demo
 * Handles request validation, security headers, and metadata endpoints
 * Only accessible from secure.alexsanchez.site
 */

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const referer = request.headers.get("Referer");

    // Parse Request Metadata
    const userAgent = request.headers.get("User-Agent") || "unknown";
    const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";
    const country = request.headers.get("CF-IPCountry") || "unknown";
    const cfRay = request.headers.get("CF-RAY") || "unknown";

    // Log Every Request
    console.log({
      event: "incoming_request",
      method: request.method,
      path: url.pathname,
      ip: clientIP,
      country: country,
      userAgent: userAgent,
      cfRay: cfRay,
      origin: origin,
      referer: referer
    });

    // Only allow requests from secure.alexsanchez.site
    const allowedOrigin = "https://secure.alexsanchez.site";
    const isAllowedOrigin = origin === allowedOrigin || referer?.startsWith(allowedOrigin);

    // Metadata endpoint - return request info as JSON with CORS headers
    if (url.searchParams.has("metadata")) {
      // Block if origin is not allowed
      if (!isAllowedOrigin) {
        console.log({
          event: "blocked_invalid_origin",
          origin: origin,
          ip: clientIP
        });
        return new Response("Unauthorized origin", {
          status: 403,
          headers: {
            "Content-Type": "application/json"
          }
        });
      }

      const response = new Response(
        JSON.stringify({
          ip: clientIP,
          country: country,
          ray: cfRay,
          userAgent: userAgent,
          securityHeaders: [
            "X-Frame-Options: DENY",
            "X-Content-Type-Options: nosniff",
            "Referrer-Policy: strict-origin",
            "Strict-Transport-Security: max-age=63072000; includeSubDomains; preload"
          ].join("\n")
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": allowedOrigin,
            "Access-Control-Allow-Methods": "GET, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
            "Access-Control-Allow-Credentials": "true"
          }
        }
      );
      return response;
    }

    // Handle CORS preflight requests
    if (request.method === "OPTIONS") {
      if (!isAllowedOrigin) {
        return new Response("Unauthorized origin", { status: 403 });
      }

      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": allowedOrigin,
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
          "Access-Control-Allow-Credentials": "true"
        }
      });
    }

    // Block Common Attack Paths
    const blockedPaths = [
      "/wp-admin",
      "/phpmyadmin",
      "/.env",
      "/config",
      "/backup",
      "/db"
    ];

    if (blockedPaths.includes(url.pathname)) {
      console.log({
        event: "blocked_path",
        path: url.pathname,
        ip: clientIP
      });
      return new Response("Blocked path", { status: 403 });
    }

    // Detect and Block Malicious Scanners
    const lowerUA = userAgent.toLowerCase();

    if (
      lowerUA.includes("sqlmap") ||
      lowerUA.includes("nikto") ||
      lowerUA.includes("nmap") ||
      lowerUA.includes("masscan")
    ) {
      console.log({
        event: "blocked_scanner",
        ip: clientIP,
        userAgent: userAgent
      });

      return new Response(
        "Blocked by Edge Security Worker (Scanner Detected)",
        { status: 403 }
      );
    }

    // Forward Clean Requests to Origin
    const response = await fetch(request);

    // Add Security Headers
    const secureHeaders = new Headers(response.headers);

    secureHeaders.set("X-Frame-Options", "DENY"); // Prevent clickjacking
    secureHeaders.set("X-Content-Type-Options", "nosniff"); // Prevent MIME type sniffing
    secureHeaders.set("Referrer-Policy", "strict-origin"); // Control referrer data leakage
    secureHeaders.set(
      // Enforce HTTPS
      "Strict-Transport-Security",
      "max-age=63072000; includeSubDomains; preload"
    );

    return new Response(response.body, {
      status: response.status,
      headers: secureHeaders
    });
  }
};
