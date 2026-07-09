// netlify/functions/content.js
//
// Persists the site content the admin dashboard edits (hero text, about
// copy, venues, packages, bookings, inquiries, SEO settings, etc.) to a
// single MongoDB document instead of only browser localStorage. This is
// what makes admin edits visible to every visitor, not just the browser
// that made them, and is also what the public pages (index/about/contact)
// read on load to display current content.
//
// GET  is public (the public site needs it to render current content).
// PUT  requires a valid session (any logged-in staff role may edit).

const { getDb } = require("./utils/db");
const { getSessionFromEvent } = require("./utils/auth");

// Only these keys may be written. Keeps a logged-in-but-misbehaving
// client from writing arbitrary fields into the document.
const ALLOWED_KEYS = new Set([
  "hero", "about", "venues", "services", "packages", "sermons", "events",
  "weekly", "testimonials", "donation", "contact", "footer", "bookings",
  "inquiries", "branding", "seo", "settings",
]);

const DOC_ID = "site";

exports.handler = async (event) => {
  let db;
  try {
    db = await getDb();
  } catch (err) {
    console.error("[content] db error:", err);
    return {
      statusCode: 500,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ error: "Server error." }),
    };
  }
  const content = db.collection("content");

  if (event.httpMethod === "GET") {
    const doc = (await content.findOne({ _id: DOC_ID })) || {};
    const { _id, ...data } = doc;
    return {
      statusCode: 200,
      headers: {
        "content-type": "application/json",
        // Public content, but keep it fresh — the admin panel writes to
        // this frequently and pages shouldn't show stale cached copies.
        "cache-control": "no-store",
      },
      body: JSON.stringify(data),
    };
  }

  if (event.httpMethod === "PUT") {
    const session = getSessionFromEvent(event);
    if (!session) {
      return {
        statusCode: 401,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: "Not authenticated." }),
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

    const { key, data } = body;
    if (!key || !ALLOWED_KEYS.has(key)) {
      return {
        statusCode: 400,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ error: `Unknown or missing content key: ${key}` }),
      };
    }

    await content.updateOne(
      { _id: DOC_ID },
      { $set: { [key]: data, updatedAt: new Date().toISOString() } },
      { upsert: true }
    );

    return {
      statusCode: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ok: true }),
    };
  }

  return {
    statusCode: 405,
    headers: { "content-type": "application/json", Allow: "GET, PUT" },
    body: JSON.stringify({ error: "Method not allowed." }),
  };
};
