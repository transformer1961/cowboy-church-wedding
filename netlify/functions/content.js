const { ObjectId } = require("mongodb");
const { getDb } = require("./utils/db");
const { getSessionFromEvent } = require("./utils/auth");

const ALLOWED_KEYS = new Set([
  "hero", "about", "venues", "services", "packages", "sermons", "events",
  "weekly", "testimonials", "donation", "contact", "footer", "bookings",
  "inquiries", "branding", "seo", "settings",
]);
const PUBLIC_CONTENT_KEYS = new Set([
  "hero", "about", "venues", "services", "packages", "sermons", "events",
  "weekly", "testimonials", "donation", "contact", "footer", "branding", "seo",
]);
const ROLE_CONTENT_KEYS = {
  sentinel: new Set(ALLOWED_KEYS),
  pastor: new Set(["sermons", "events"]),
  mom: new Set(["venues", "packages", "testimonials", "bookings", "inquiries"]),
};
const DOC_ID = "site";
const MAX_CONTENT_BYTES = 250_000;

function response(statusCode, body) {
  return {
    statusCode,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: JSON.stringify(body),
  };
}

function canEditContent(user, key) {
  if (user.role === "sentinel") return true;
  if (Array.isArray(user.permissions)) return user.permissions.includes(key);
  return ROLE_CONTENT_KEYS[user.role]?.has(key) || false;
}

// Dashboard fields are plain text. Replace tag delimiters before storing so
// legacy innerHTML views cannot execute staff-supplied markup.
function sanitizeValue(value, depth = 0, fieldName = "") {
  if (depth > 12) throw new Error("Content is nested too deeply.");
  if (fieldName === "id" && (!Number.isSafeInteger(value) || value < 0)) {
    throw new Error("Content item IDs must be non-negative integers.");
  }
  if (typeof value === "string") {
    return value.replace(/</g, "‹").replace(/>/g, "›");
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(item, depth + 1));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [key, sanitizeValue(item, depth + 1, key)])
    );
  }
  if (["number", "boolean"].includes(typeof value) || value === null) return value;
  throw new Error("Content contains an unsupported value.");
}

function publicContent(data) {
  const safe = {};
  for (const key of PUBLIC_CONTENT_KEYS) {
    if (data[key] === undefined) continue;
    if (key === "donation" && data.donation && typeof data.donation === "object") {
      const { apikey, ein, ...donation } = data.donation;
      safe.donation = sanitizeValue(donation);
    } else {
      safe[key] = sanitizeValue(data[key]);
    }
  }
  return safe;
}

async function getLiveUser(users, event) {
  const session = getSessionFromEvent(event);
  if (!session?.sub || !ObjectId.isValid(session.sub)) return null;
  const user = await users.findOne({ _id: new ObjectId(session.sub), active: { $ne: false } });
  if (!user || (user.sessionVersion || 0) !== (session.sessionVersion || 0)) return null;
  return user;
}

exports.handler = async (event) => {
  let db;
  try {
    db = await getDb();
  } catch (err) {
    console.error("[content] db error:", err);
    return response(500, { error: "Server error." });
  }
  const content = db.collection("content");
  const users = db.collection("users");

  if (event.httpMethod === "GET") {
    const doc = (await content.findOne({ _id: DOC_ID })) || {};
    const { _id, updatedAt, ...data } = doc;
    const user = await getLiveUser(users, event);
    if (!user) return response(200, publicContent(data));

    const permitted = Object.fromEntries(
      Object.entries(data)
        .filter(([key]) => ALLOWED_KEYS.has(key) && canEditContent(user, key))
        .map(([key, value]) => [key, sanitizeValue(value)])
    );
    return response(200, permitted);
  }

  if (event.httpMethod !== "PUT") {
    return {
      statusCode: 405,
      headers: { "content-type": "application/json", Allow: "GET, PUT", "cache-control": "no-store" },
      body: JSON.stringify({ error: "Method not allowed." }),
    };
  }

  const user = await getLiveUser(users, event);
  if (!user) return response(401, { error: "Not authenticated." });
  if (Buffer.byteLength(event.body || "", "utf8") > MAX_CONTENT_BYTES) {
    return response(413, { error: "Content is too large." });
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch {
    return response(400, { error: "Malformed request body." });
  }

  const { key, data } = body;
  if (!key || !ALLOWED_KEYS.has(key)) {
    return response(400, { error: `Unknown or missing content key: ${key}` });
  }
  if (!canEditContent(user, key)) {
    return response(403, { error: "Your role cannot edit this section." });
  }

  let safeData;
  try {
    safeData = sanitizeValue(data);
  } catch (err) {
    return response(400, { error: err.message });
  }
  await content.updateOne(
    { _id: DOC_ID },
    { $set: { [key]: safeData, updatedAt: new Date().toISOString() } },
    { upsert: true }
  );
  return response(200, { ok: true });
};
