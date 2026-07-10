// netlify/functions/utils/auth.js
//
// Shared helpers for signing/verifying session JWTs and reading/writing
// the httpOnly session cookie. Keeping this in one place means every
// function (login, verify, logout, users, content) agrees on the exact
// same cookie name, signing secret, and expiry.

const jwt = require("jsonwebtoken");
const cookieModule = require("cookie");

const cookie = cookieModule.default || cookieModule;
const parseCookie = cookie.parse || cookieModule.parse;
const serializeCookie = cookie.serialize || cookieModule.serialize;

if (typeof parseCookie !== "function" || typeof serializeCookie !== "function") {
  throw new Error("The cookie package did not expose parse/serialize helpers.");
}

const COOKIE_NAME = "cc_session";
const SESSION_HOURS = 8;

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
    { sub: String(user._id), username: user.username, role: user.role },
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

// Strips password hash and other internal fields before ever sending a
// user object back to the browser.
function toSafeUser(user) {
  if (!user) return null;
  const { passwordHash, _id, ...rest } = user;
  return { id: String(_id), ...rest };
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
