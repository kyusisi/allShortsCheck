import { createServer } from "node:http";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

import {
  acceptInvitation,
  createInvitation,
  createSession,
  deleteSession,
  getInvitation,
  getSessionUser,
  getUserByLoginId,
  initializeDatabase
} from "./lib/database.js";
import {
  createOpaqueToken,
  hashToken,
  isValidEmail,
  isValidPassword,
  normalizeEmail,
  REMEMBER_ME_SESSION_MAX_AGE_SECONDS,
  SESSION_MAX_AGE_SECONDS,
  verifyPassword
} from "./lib/auth.js";

const currentDir = dirname(fileURLToPath(import.meta.url));
const publicDir = join(currentDir, "public");
const port = Number(process.env.PORT || 3000);
const host = process.env.HOST || "127.0.0.1";
const appOrigin = process.env.APP_ORIGIN || "";
const secureCookie = process.env.COOKIE_SECURE === "true";
const loginAttempts = new Map();

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml"
};

const securityHeaders = {
  "Content-Security-Policy":
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self'; script-src 'self'; style-src 'self'",
  "Referrer-Policy": "same-origin",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY"
};

class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function resolvePublicFile(requestUrl) {
  const url = new URL(requestUrl, `http://localhost:${port}`);
  const requestedPath = decodeURIComponent(url.pathname);
  const relativePath = requestedPath === "/" ? "index.html" : requestedPath.slice(1);
  const filePath = normalize(join(publicDir, relativePath));

  if (!filePath.startsWith(`${publicDir}/`) && filePath !== publicDir) {
    return null;
  }

  return filePath;
}

function sendJson(response, statusCode, payload, headers = {}) {
  response.writeHead(statusCode, {
    ...securityHeaders,
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8",
    ...headers
  });
  response.end(JSON.stringify(payload));
}

function redirect(response, location) {
  response.writeHead(302, { ...securityHeaders, Location: location, "Cache-Control": "no-store" });
  response.end();
}

function parseCookies(header = "") {
  return header.split(";").reduce((cookies, value) => {
    const separator = value.indexOf("=");

    if (separator > 0) {
      const key = value.slice(0, separator).trim();
      const cookieValue = value.slice(separator + 1).trim();
      cookies[key] = decodeURIComponent(cookieValue);
    }

    return cookies;
  }, {});
}

function sessionCookie(token, maxAge) {
  const parts = [
    `session_token=${encodeURIComponent(token)}`,
    "HttpOnly",
    "Path=/",
    "SameSite=Lax"
  ];

  if (Number.isInteger(maxAge)) {
    parts.push(`Max-Age=${maxAge}`);
  }

  if (secureCookie) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function sessionDuration(rememberMe) {
  return rememberMe ? REMEMBER_ME_SESSION_MAX_AGE_SECONDS : SESSION_MAX_AGE_SECONDS;
}

async function readJson(request) {
  const chunks = [];
  let totalLength = 0;

  for await (const chunk of request) {
    totalLength += chunk.length;

    if (totalLength > 16 * 1024) {
      throw new ApiError(413, "요청 본문이 너무 큽니다.");
    }

    chunks.push(chunk);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ApiError(400, "올바른 요청 형식이 아닙니다.");
  }
}

function clientIp(request) {
  const forwardedFor = request.headers["x-forwarded-for"];

  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",").at(-1).trim();
  }

  return request.socket.remoteAddress || "unknown";
}

function checkLoginAttempts(request) {
  const ip = clientIp(request);
  const attempt = loginAttempts.get(ip);

  if (attempt && attempt.until > Date.now()) {
    throw new ApiError(429, "잠시 후 다시 시도해주세요.");
  }

  if (attempt && attempt.until > 0) {
    loginAttempts.delete(ip);
  }
}

function recordFailedLogin(request) {
  const ip = clientIp(request);
  const attempt = loginAttempts.get(ip) || { count: 0, until: 0 };
  attempt.count += 1;

  if (attempt.count >= 5) {
    attempt.count = 0;
    attempt.until = Date.now() + 15 * 60 * 1000;
  }

  loginAttempts.set(ip, attempt);
}

function clearLoginAttempts(request) {
  loginAttempts.delete(clientIp(request));
}

async function getAuthenticatedUser(request) {
  const token = parseCookies(request.headers.cookie).session_token;

  if (!token) {
    return null;
  }

  return getSessionUser(hashToken(token));
}

function publicUser(user) {
  return {
    loginId: user.login_id || user.loginId,
    email: user.email,
    role: user.role
  };
}

function requestOrigin(request) {
  if (appOrigin) {
    return appOrigin;
  }

  const forwardedProtocol = request.headers["x-forwarded-proto"];
  const protocol = forwardedProtocol === "https" ? "https" : "http";
  const requestHost = request.headers.host || `localhost:${port}`;

  return `${protocol}://${requestHost}`;
}

async function requireAdmin(request) {
  const user = await getAuthenticatedUser(request);

  if (!user) {
    throw new ApiError(401, "로그인이 필요합니다.");
  }

  if (user.role !== "admin") {
    throw new ApiError(403, "관리자만 사용할 수 있습니다.");
  }

  return user;
}

async function handleApi(request, response, url) {
  const { pathname } = url;

  if (request.method === "GET" && pathname === "/api/auth/me") {
    const user = await getAuthenticatedUser(request);
    sendJson(response, 200, { authenticated: Boolean(user), user: user ? publicUser(user) : null });
    return;
  }

  if (request.method === "POST" && pathname === "/api/auth/login") {
    checkLoginAttempts(request);
    const body = await readJson(request);
    const rawLoginId = typeof body.loginId === "string" ? body.loginId.trim().toLowerCase() : "";
    const password = body.password;
    const rememberMe = body.rememberMe === true;
    const user = rawLoginId ? await getUserByLoginId(rawLoginId) : null;

    if (!user || typeof password !== "string" || !(await verifyPassword(password, user.password_salt, user.password_hash))) {
      recordFailedLogin(request);
      throw new ApiError(401, "아이디 또는 비밀번호를 확인하세요.");
    }

    clearLoginAttempts(request);
    const token = createOpaqueToken();
    const maxAge = sessionDuration(rememberMe);
    const expiresAt = new Date(Date.now() + maxAge * 1000);
    await createSession(user.id, hashToken(token), expiresAt);

    sendJson(
      response,
      200,
      { user: publicUser(user) },
      { "Set-Cookie": sessionCookie(token, rememberMe ? maxAge : undefined) }
    );
    return;
  }

  if (request.method === "POST" && pathname === "/api/auth/logout") {
    const token = parseCookies(request.headers.cookie).session_token;

    if (token) {
      await deleteSession(hashToken(token));
    }

    sendJson(response, 200, { success: true }, { "Set-Cookie": sessionCookie("", 0) });
    return;
  }

  if (request.method === "POST" && pathname === "/api/admin/invitations") {
    const admin = await requireAdmin(request);
    const body = await readJson(request);
    const email = normalizeEmail(body.email);

    if (!isValidEmail(email)) {
      throw new ApiError(400, "올바른 이메일 주소를 입력하세요.");
    }

    const token = createOpaqueToken();
    const invitation = await createInvitation({
      email,
      tokenHash: hashToken(token),
      invitedBy: admin.id,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 7)
    });

    if (invitation.alreadyRegistered) {
      throw new ApiError(409, "이미 등록된 이메일 주소입니다.");
    }

    sendJson(response, 201, {
      email,
      invitationUrl: `${requestOrigin(request)}/invite?token=${encodeURIComponent(token)}`
    });
    return;
  }

  const invitationMatch = pathname.match(/^\/api\/invitations\/([^/]+)$/);

  if (request.method === "GET" && invitationMatch) {
    const invitation = await getInvitation(hashToken(decodeURIComponent(invitationMatch[1])));

    if (!invitation) {
      throw new ApiError(404, "초대 링크가 유효하지 않거나 만료됐습니다.");
    }

    sendJson(response, 200, { email: invitation.email });
    return;
  }

  const acceptanceMatch = pathname.match(/^\/api\/invitations\/([^/]+)\/accept$/);

  if (request.method === "POST" && acceptanceMatch) {
    const body = await readJson(request);

    if (!isValidPassword(body.password)) {
      throw new ApiError(400, "비밀번호는 10자 이상 128자 이하로 설정하세요.");
    }

    const user = await acceptInvitation({
      tokenHash: hashToken(decodeURIComponent(acceptanceMatch[1])),
      password: body.password
    });

    if (!user) {
      throw new ApiError(404, "초대 링크가 유효하지 않거나 만료됐습니다.");
    }

    const token = createOpaqueToken();
    const expiresAt = new Date(Date.now() + SESSION_MAX_AGE_SECONDS * 1000);
    await createSession(user.id, hashToken(token), expiresAt);

    sendJson(
      response,
      201,
      { user },
      { "Set-Cookie": sessionCookie(token) }
    );
    return;
  }

  throw new ApiError(404, "요청한 API를 찾을 수 없습니다.");
}

async function servePublicFile(response, filePath, method) {
  const file = await readFile(filePath);
  const contentType = contentTypes[extname(filePath)] || "application/octet-stream";
  const cacheControl = contentType === "text/html; charset=utf-8" ? "no-store" : "public, max-age=3600";

  response.writeHead(200, { ...securityHeaders, "Cache-Control": cacheControl, "Content-Type": contentType });
  response.end(method === "HEAD" ? undefined : file);
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || "/", `http://localhost:${port}`);

    if (url.pathname.startsWith("/api/")) {
      await handleApi(request, response, url);
      return;
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      response.writeHead(405, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      response.end("Method Not Allowed");
      return;
    }

    if (url.pathname === "/" || url.pathname === "/index.html") {
      const user = await getAuthenticatedUser(request);

      if (!user) {
        redirect(response, "/login");
        return;
      }

      await servePublicFile(response, join(publicDir, "index.html"), request.method);
      return;
    }

    if (url.pathname === "/login" || url.pathname === "/login.html") {
      const user = await getAuthenticatedUser(request);

      if (user) {
        redirect(response, "/");
        return;
      }

      await servePublicFile(response, join(publicDir, "login.html"), request.method);
      return;
    }

    if (url.pathname === "/invite") {
      await servePublicFile(response, join(publicDir, "invite.html"), request.method);
      return;
    }

    const filePath = resolvePublicFile(request.url || "/");

    if (!filePath) {
      response.writeHead(403, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
      response.end("Forbidden");
      return;
    }

    await servePublicFile(response, filePath, request.method);
  } catch (error) {
    const statusCode = error instanceof ApiError ? error.statusCode : error.code === "ENOENT" || error.code === "EISDIR" ? 404 : 500;
    const message = error instanceof ApiError ? error.message : statusCode === 404 ? "Not Found" : "Internal Server Error";

    if (statusCode === 500) {
      console.error(`[${randomUUID()}]`, error);
    }

    if (urlIsApiRequest(request)) {
      sendJson(response, statusCode, { message });
      return;
    }

    response.writeHead(statusCode, { ...securityHeaders, "Content-Type": "text/plain; charset=utf-8" });
    response.end(message);
  }
});

function urlIsApiRequest(request) {
  return (request.url || "").startsWith("/api/");
}

try {
  await initializeDatabase();
} catch (error) {
  console.error("Database initialization failed.", error);
  process.exit(1);
}

server.listen(port, host, () => {
  console.log(`Server is running at http://${host}:${port}`);
});
