// netlify/functions/users.js
//
// CRUD for staff accounts, used by admin.html's "Staff Directory" and
// "My Profile" pages. Every request must have a valid session cookie.
// Creating/deleting/renaming/re-roling other accounts is restricted to
// the "sentinel" role; any logged-in user may update their own profile
// and password (with current-password verification for the password
// change specifically).
//
// Passwords are never stored or returned in plaintext — only a bcrypt
// hash (passwordHash) lives in MongoDB, and toSafeUser() strips it
// before any response leaves the server.

const bcrypt = require("bcryptjs");
const { ObjectId } = require("mongodb");
const { getDb } = require("./utils/db");
const { getSessionFromEvent, toSafeUser } = require("./utils/auth");

const SALT_ROUNDS = 12;

async function requireSession(event) {
  const session = getSessionFromEvent(event);
  if (!session) return null;
  return session;
}

exports.handler = async (event) => {
  const session = await requireSession(event);
  if (!session) {
    return {
      statusCode: 401,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Not authenticated." }),
    };
  }

  let db;
  try {
    db = await getDb();
  } catch (err) {
    console.error("[users] db error:", err);
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Server error." }),
    };
  }
  const users = db.collection("users");

  // ── GET: list all staff (safe fields only). Any logged-in user can
  // view the staff directory (it's also shown publicly on the site).
  if (event.httpMethod === "GET") {
    const all = await users.find({}).sort({ _id: 1 }).toArray();
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ users: all.map(toSafeUser) }),
    };
  }

  // ── POST: create a new staff account. Sentinel only.
  if (event.httpMethod === "POST") {
    if (session.role !== "sentinel") {
      return {
        statusCode: 403,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Only a Sentinel can add staff accounts." }),
      };
    }
    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "Malformed body." }) };
    }
    const username = String(body.username || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!username || !password || password.length < 8) {
      return {
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          error: "Username and a password of at least 8 characters are required.",
        }),
      };
    }
    const existing = await users.findOne({ username });
    if (existing) {
      return {
        statusCode: 409,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "That username is already taken." }),
      };
    }
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const doc = {
      username,
      passwordHash,
      role: body.role || "mom",
      name: body.name || username,
      title: body.title || "",
      email: body.email || "",
      phone: body.phone || "",
      avatar: body.avatar || username[0].toUpperCase(),
      color: body.color || "#C7745C",
      bio: body.bio || "",
    };
    const result = await users.insertOne(doc);
    const created = await users.findOne({ _id: result.insertedId });
    return {
      statusCode: 201,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: toSafeUser(created) }),
    };
  }

  // ── PUT: update a staff account. A user may update their own profile
  // and password (current password required to change the password).
  // Only a sentinel may edit other accounts, or change role/username.
  if (event.httpMethod === "PUT") {
    let body;
    try {
      body = JSON.parse(event.body || "{}");
    } catch {
      return { statusCode: 400, body: JSON.stringify({ error: "Malformed body." }) };
    }

    const targetId = String(body.id || "");
    if (!targetId) {
      return {
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Missing user id." }),
      };
    }

    const isSelf = targetId === session.sub;
    if (!isSelf && session.role !== "sentinel") {
      return {
        statusCode: 403,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Only a Sentinel can edit other staff accounts." }),
      };
    }

    const target = await users.findOne({ _id: new ObjectId(targetId) });
    if (!target) {
      return {
        statusCode: 404,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "User not found." }),
      };
    }

    const update = {};
    ["name", "title", "email", "phone", "avatar", "color", "bio"].forEach((field) => {
      if (typeof body[field] === "string") update[field] = body[field];
    });

    // Username/role changes: sentinel only (even for their own account,
    // to avoid accidentally locking themselves out of the role).
    if (session.role === "sentinel") {
      if (typeof body.username === "string" && body.username.trim()) {
        update.username = body.username.trim().toLowerCase();
      }
      if (typeof body.role === "string" && body.role.trim()) {
        update.role = body.role.trim();
      }
    }

    // Password change.
    if (typeof body.newPassword === "string" && body.newPassword) {
      if (body.newPassword.length < 8) {
        return {
          statusCode: 400,
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ error: "New password must be at least 8 characters." }),
        };
      }
      // If you're changing your OWN password, you must prove you know
      // the current one. A sentinel resetting someone else's password
      // does not need the old one.
      if (isSelf) {
        const currentOk = await bcrypt.compare(
          String(body.currentPassword || ""),
          target.passwordHash || ""
        );
        if (!currentOk) {
          return {
            statusCode: 401,
            headers: { "content-type": "application/json" },
            body: JSON.stringify({ error: "Current password is incorrect." }),
          };
        }
      }
      update.passwordHash = await bcrypt.hash(body.newPassword, SALT_ROUNDS);
    }

    await users.updateOne({ _id: target._id }, { $set: update });
    const updated = await users.findOne({ _id: target._id });
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: toSafeUser(updated) }),
    };
  }

  // ── DELETE: remove a staff account. Sentinel only, can't delete self.
  if (event.httpMethod === "DELETE") {
    if (session.role !== "sentinel") {
      return {
        statusCode: 403,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Only a Sentinel can remove staff accounts." }),
      };
    }
    const targetId = event.queryStringParameters && event.queryStringParameters.id;
    if (!targetId) {
      return {
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Missing user id." }),
      };
    }
    if (targetId === session.sub) {
      return {
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "You cannot delete your own account." }),
      };
    }
    await users.deleteOne({ _id: new ObjectId(targetId) });
    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: true }),
    };
  }

  return {
    statusCode: 405,
    headers: { "content-type": "application/json", Allow: "GET, POST, PUT, DELETE" },
    body: JSON.stringify({ error: "Method not allowed." }),
  };
};
