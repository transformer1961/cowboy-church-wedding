#!/usr/bin/env node
// scripts/check-password.js
//
// Safely verifies a staff username/password against the bcrypt hash in
// MongoDB. It never prints the password or the stored hash.

const readline = require("readline");
const fs = require("fs");
const path = require("path");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");

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
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  const username = (await ask(rl, "Username: ")).trim().toLowerCase();
  const password = await ask(rl, "Password to check: ", { hidden: true });
  rl.close();

  const client = new MongoClient(uri);
  try {
    await client.connect();
    const user = await client.db(dbName).collection("users").findOne({ username });
    if (!user) {
      console.log(`No user found for "${username}".`);
      process.exitCode = 1;
      return;
    }

    const ok = await bcrypt.compare(password, user.passwordHash || "");
    console.log(ok ? "Password matches." : "Password does not match.");
    if (!ok) process.exitCode = 1;
  } finally {
    await client.close();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
