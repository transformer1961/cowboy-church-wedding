// netlify/functions/login.js
//
// Real staff login. Verifies the submitted username/password against
// hashed passwords stored in MongoDB Atlas and, on success, issues a
// signed JWT in an httpOnly, Secure cookie. No credentials or session
// state ever live in localStorage/sessionStorage/client JS anymore.

const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { getDb } = require("./utils/db");
const { signSession, buildSessionCookie, toSafeUser } = require("./utils/auth");

const MAX_ATTEMPTS = 10;
const ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

function attemptKey(event, username) {
  const forwarded = event.headers?.["x-nf-client-connection-ip"] || event.headers?.["x-forwarded-for"] || "unknown";
  const ip = String(forwarded).split(",")[0].trim();
  return crypto.createHash("sha256").update(`${ip}:${username}`).digest("hex");
}

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "content-type": "application/json", Allow: "POST" },
      body: JSON.stringify({ error: "Method not allowed." }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Malformed request body." }),
    };
  }

  const username = String(body.username || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!username || !password) {
    return {
      statusCode: 400,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Username and password are required." }),
    };
  }

  try {
    const db = await getDb();
    const attempts = db.collection("login_attempts");
    const key = attemptKey(event, username);
    const now = new Date();
    const previous = await attempts.findOne({ _id: key });
    if (previous && now - previous.lastAttempt < ATTEMPT_WINDOW_MS && previous.count >= MAX_ATTEMPTS) {
      return {
        statusCode: 429,
        headers: { "content-type": "application/json", "cache-control": "no-store", "retry-after": "900" },
        body: JSON.stringify({ error: "Too many attempts. Please try again later." }),
      };
    }
    const user = await db.collection("users").findOne({ username });

    // Use a generic error for both "no such user" and "wrong password"
    // so we don't leak which usernames exist.
    const genericError = { error: "Incorrect username or password." };

    const recordFailure = async () => {
      const inWindow = previous && now - previous.lastAttempt < ATTEMPT_WINDOW_MS;
      await attempts.updateOne(
        { _id: key },
        { $set: { lastAttempt: now, count: inWindow ? (previous.count || 0) + 1 : 1 } },
        { upsert: true }
      );
    };

    if (!user || user.active === false) {
      await recordFailure();
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(genericError),
      };
    }

    const ok = await bcrypt.compare(password, user.passwordHash || "");
    if (!ok) {
      await recordFailure();
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(genericError),
      };
    }

    const token = signSession(user);
    await attempts.deleteOne({ _id: key });

    return {
      statusCode: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": buildSessionCookie(token),
        "cache-control": "no-store",
      },
      body: JSON.stringify({ user: toSafeUser(user) }),
    };
  } catch (err) {
    console.error("[login] error:", err);
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Server error. Please try again shortly." }),
    };
  }
};
