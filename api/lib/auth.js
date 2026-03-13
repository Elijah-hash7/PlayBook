const crypto = require("crypto");

const SESSION_COOKIE = "playbook_session";
const SESSION_TTL_SECONDS = 5 * 60;

function safeEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) {
    return false;
  }
  return crypto.timingSafeEqual(left, right);
}

function readCookie(req, name) {
  const header = req.headers.cookie || "";
  const parts = header.split(";").map((chunk) => chunk.trim());
  for (const part of parts) {
    if (!part.startsWith(name + "=")) {
      continue;
    }
    return decodeURIComponent(part.slice(name.length + 1));
  }
  return "";
}

function sign(payload, secret) {
  return crypto.createHmac("sha256", secret).update(payload).digest("hex");
}

function getSessionSecret() {
  return process.env.PLAYBOOK_SESSION_SECRET || "";
}

function getPassword() {
  return process.env.PLAYBOOK_PASSWORD || "";
}

function isLocalRequest(req) {
  const host = String(req.headers.host || "").toLowerCase();
  return host.startsWith("localhost:") || host === "localhost" || host.startsWith("127.0.0.1:") || host === "127.0.0.1";
}

function buildCookie(name, value, maxAge, req) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    "Path=/",
    `Max-Age=${maxAge}`,
    "HttpOnly",
    "SameSite=Lax"
  ];

  if (!isLocalRequest(req)) {
    parts.push("Secure");
  }

  return parts.join("; ");
}

function issueSessionCookie(req, res) {
  const secret = getSessionSecret();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payload = String(expiresAt);
  const signature = sign(payload, secret);
  const token = `${payload}.${signature}`;
  const cookie = buildCookie(SESSION_COOKIE, token, SESSION_TTL_SECONDS, req);
  res.setHeader("Set-Cookie", cookie);
}

function clearSessionCookie(req, res) {
  const cookie = buildCookie(SESSION_COOKIE, "", 0, req);
  res.setHeader("Set-Cookie", cookie);
}

function hasValidSession(req) {
  const token = readCookie(req, SESSION_COOKIE);
  const secret = getSessionSecret();
  if (!token || !secret) {
    return false;
  }

  const [payload, signature] = token.split(".");
  if (!payload || !signature) {
    return false;
  }

  const expected = sign(payload, secret);
  if (!safeEqual(expected, signature)) {
    return false;
  }

  const expiresAt = Number(payload);
  if (!Number.isFinite(expiresAt)) {
    return false;
  }

  return Date.now() < expiresAt;
}

module.exports = {
  SESSION_TTL_SECONDS,
  clearSessionCookie,
  getPassword,
  getSessionSecret,
  hasValidSession,
  issueSessionCookie,
  safeEqual
};
