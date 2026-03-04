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

function issueSessionCookie(res) {
  const secret = getSessionSecret();
  const expiresAt = Date.now() + SESSION_TTL_SECONDS * 1000;
  const payload = String(expiresAt);
  const signature = sign(payload, secret);
  const token = `${payload}.${signature}`;
  const cookie = `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`;
  res.setHeader("Set-Cookie", cookie);
}

function clearSessionCookie(res) {
  const cookie = `${SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
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
