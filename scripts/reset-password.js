#!/usr/bin/env node
// scripts/reset-password.js
//
// Resets one staff user's password by replacing the bcrypt hash in
// MongoDB. The new password is typed interactively and never printed.

const readline = require("readline");
const fs = require("fs");
const path = require("path");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 12;

function loadLocalEnv() {
  const envPath = path.join(__dirname, "..", ".env");
  if (!fs.existsSync(envPath)) return;

  const lines = fs.readFileSync(envPath, "utf8").split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const index = trimmed.indexOf("=");
    if (index === -1) continue;

    const key = trimmed.slice(0, index).trim();
    let value = trimmed.slice(index + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    if (key && process.env[key] === undefined) {
      process.env[key] = value;
    }
  }
}

function ask(rl, question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    if (!hidden) {
      rl.question(question, resolve);
      return;
    }

    const stdin = process.stdin;
    process.stdout.write(question);
    let value = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");

    const onData = (char) => {
      char = char.toString();
      if (char === "\n" || char === "\r" || char === "\u0004") {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(value);
        return;
      }
      if (char === "\u0003") process.exit(1);
      if (char === "\u007f") {
        value = value.slice(0, -1);
        return;
      }
      value += char;
    };

    stdin.on("data", onData);
  });
}

async function main() {
  loadLocalEnv();

  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("Set MONGODB_URI in .env before running this script.");
    process.exit(1);
  }

  const dbName = process.env.MONGODB_DB || "cowboychurch";
  const username = String(process.argv[2] || "sentinel").trim().toLowerCase();
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  let password = "";
  let confirm = "";
  do {
    password = await ask(rl, `New password for "${username}" (min 12 chars): `, {
      hidden: true,
    });
    if (password.length < 12) {
      console.log("  Too short. Try again.");
      continue;
    }
    confirm = await ask(rl, "Confirm password: ", { hidden: true });
    if (password !== confirm) console.log("  Passwords did not match. Try again.");
  } while (password.length < 12 || password !== confirm);

  rl.close();

  const client = new MongoClient(uri);
  try {
    console.log(`Connecting to MongoDB database "${dbName}"...`);
    await client.connect();
    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    const result = await client
      .db(dbName)
      .collection("users")
      .updateOne({ username }, { $set: { passwordHash } });

    if (!result.matchedCount) {
      console.log(`No user found for "${username}".`);
      process.exitCode = 1;
      return;
    }

    console.log(`Password reset for "${username}".`);
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
