// netlify/functions/login.js
//
// Real staff login. Verifies the submitted username/password against
// hashed passwords stored in MongoDB Atlas and, on success, issues a
// signed JWT in an httpOnly, Secure cookie. No credentials or session
// state ever live in localStorage/sessionStorage/client JS anymore.

const bcrypt = require("bcryptjs");
const { getDb } = require("./utils/db");
const { signSession, buildSessionCookie, toSafeUser } = require("./utils/auth");

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
    const user = await db.collection("users").findOne({ username });

    // Use a generic error for both "no such user" and "wrong password"
    // so we don't leak which usernames exist.
    const genericError = { error: "Incorrect username or password." };

    if (!user) {
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(genericError),
      };
    }

    const ok = await bcrypt.compare(password, user.passwordHash || "");
    if (!ok) {
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify(genericError),
      };
    }

    const token = signSession(user);

    return {
      statusCode: 200,
      headers: {
        "content-type": "application/json",
        "set-cookie": buildSessionCookie(token),
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
