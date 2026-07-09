// netlify/functions/verify.js
//
// Called by admin.html on every load to check whether the visitor has a
// valid, unexpired session cookie AND still exists in the database with
// an active account. This is the actual access-control check — nothing
// in the browser is trusted. If this returns 401, admin.html redirects
// to login.html.

const { ObjectId } = require("mongodb");
const { getDb } = require("./utils/db");
const { getSessionFromEvent, toSafeUser } = require("./utils/auth");

exports.handler = async (event) => {
  if (event.httpMethod !== "GET") {
    return {
      statusCode: 405,
      headers: { "content-type": "application/json", Allow: "GET" },
      body: JSON.stringify({ error: "Method not allowed." }),
    };
  }

  const session = getSessionFromEvent(event);
  if (!session) {
    return {
      statusCode: 401,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Not authenticated." }),
    };
  }

  try {
    const db = await getDb();
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(session.sub) });

    if (!user) {
      // Account was deleted since the token was issued.
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Account no longer exists." }),
      };
    }

    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ user: toSafeUser(user) }),
    };
  } catch (err) {
    console.error("[verify] error:", err);
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Server error." }),
    };
  }
};
