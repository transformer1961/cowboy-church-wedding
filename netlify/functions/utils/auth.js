// netlify/functions/utils/auth.js
//
// Shared helpers for signing/verifying session JWTs and reading/writing
// the httpOnly session cookie. Keeping this in one place means every
// function (login, verify, logout, users, content) agrees on the exact
// same cookie name, signing secret, and expiry.

const jwt = require("jsonwebtoken");

const COOKIE_NAME = "cc_session";
const SESSION_HOURS = 8;

function parseCookie(header) {
  return String(header || "")
    .split(";")
    .reduce((acc, part) => {
      const index = part.indexOf("=");
      if (index === -1) return acc;
      const key = part.slice(0, index).trim();
      const value = part.slice(index + 1).trim();
      if (key) acc[key] = decodeURIComponent(value);
      return acc;
    }, {});
}

function serializeCookie(name, value, options = {}) {
  const segments = [`${name}=${encodeURIComponent(value)}`];
  if (options.maxAge !== undefined) segments.push(`Max-Age=${Math.floor(options.maxAge)}`);
  if (options.path) segments.push(`Path=${options.path}`);
  if (options.httpOnly) segments.push("HttpOnly");
  if (options.secure) segments.push("Secure");
  if (options.sameSite) segments.push(`SameSite=${options.sameSite}`);
  return segments.join("; ");
}

function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      "JWT_SECRET environment variable is not configured. " +
        "Add it in Netlify's Site settings > Environment variables (use a long random string)."
    );
  }
  return secret;
}

// Only put non-sensitive, small fields in the token itself. Anything
// else (bio, phone, etc.) is re-fetched live from MongoDB on verify.
function signSession(user) {
  return jwt.sign(
    {
      sub: String(user._id),
      username: user.username,
      role: user.role,
      sessionVersion: Number.isSafeInteger(user.sessionVersion) ? user.sessionVersion : 0,
      permissions: Array.isArray(user.permissions) ? user.permissions : [],
      // Older accounts do not have a permissions field. They keep their
      // role defaults, while an explicit empty array means "no access".
      permissionsConfigured: Array.isArray(user.permissions),
    },
    getSecret(),
    { expiresIn: `${SESSION_HOURS}h` }
  );
}

function verifySession(token) {
  try {
    return jwt.verify(token, getSecret());
  } catch (err) {
    return null;
  }
}

// Reads the session cookie from a Netlify Functions event and returns
// the decoded payload, or null if missing/invalid/expired.
function getSessionFromEvent(event) {
  const header = event.headers && (event.headers.cookie || event.headers.Cookie);
  if (!header) return null;
  const parsed = parseCookie(header);
  const token = parsed[COOKIE_NAME];
  if (!token) return null;
  return verifySession(token);
}

function buildSessionCookie(token) {
  return serializeCookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: SESSION_HOURS * 60 * 60,
  });
}

function buildLogoutCookie() {
  return serializeCookie(COOKIE_NAME, "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

function escapeForHtml(value) {
  if (typeof value === "string") {
    const decoded = value.replace(/&(amp|lt|gt|quot|#39);/g, (entity) => ({
      "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": "\"", "&#39;": "'",
    })[entity]);
    return decoded
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
  if (Array.isArray(value)) return value.map(escapeForHtml);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, escapeForHtml(item)]));
  }
  return value;
}

// Strips password hash and other internal fields before ever sending a
// user object back to the browser.
function toSafeUser(user) {
  if (!user) return null;
  const { passwordHash, _id, sessionVersion, ...rest } = user;
  return { id: String(_id), ...escapeForHtml(rest) };
}

module.exports = {
  COOKIE_NAME,
  signSession,
  verifySession,
  getSessionFromEvent,
  buildSessionCookie,
  buildLogoutCookie,
  toSafeUser,
};
