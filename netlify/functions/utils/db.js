// netlify/functions/utils/db.js
//
// Cached MongoDB Atlas connection for use across Netlify Function
// invocations. Netlify Functions run in a Lambda-like environment where
// the same container can be reused between requests, so we cache the
// client/connection on the module scope to avoid reconnecting on every
// call (which is slow and can exhaust your Atlas connection limit).

const { MongoClient } = require("mongodb");

const uri = process.env.MONGODB_URI;
const dbName = process.env.MONGODB_DB || "cowboychurch";

if (!uri) {
  // We don't throw here at module-load time because that would crash
  // every function's cold start with a confusing stack trace. Instead
  // getDb() below throws a clear, actionable error the first time a
  // function actually tries to use the database.
  console.warn(
    "[db] MONGODB_URI is not set. Set it in your Netlify environment variables " +
      "(Site settings > Environment variables) to your MongoDB Atlas connection string."
  );
}

let cachedClient = null;
let cachedDb = null;

async function getDb() {
  if (!uri) {
    throw new Error(
      "MONGODB_URI environment variable is not configured. " +
        "Add it in Netlify's Site settings > Environment variables."
    );
  }

  if (cachedDb) {
    return cachedDb;
  }

  if (!cachedClient) {
    cachedClient = new MongoClient(uri, {
      maxPoolSize: 5,
    });
  }

  await cachedClient.connect();
  cachedDb = cachedClient.db(dbName);
  return cachedDb;
}

module.exports = { getDb };
