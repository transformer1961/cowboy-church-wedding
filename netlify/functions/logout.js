// netlify/functions/logout.js
//
// Clears the session cookie server-side. Since the cookie is httpOnly,
// client JS can't delete it directly — it has to ask this endpoint to
// overwrite it with an already-expired one.

const { buildLogoutCookie } = require("./utils/auth");

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { "content-type": "application/json", Allow: "POST" },
      body: JSON.stringify({ error: "Method not allowed." }),
    };
  }

  return {
    statusCode: 200,
    headers: {
      "content-type": "application/json",
      "set-cookie": buildLogoutCookie(),
    },
    body: JSON.stringify({ ok: true }),
  };
};
