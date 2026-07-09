#!/usr/bin/env node
// scripts/seed-users.js
//
// Run this ONCE (locally, or from a trusted machine) to create the
// initial staff accounts in MongoDB Atlas. It never writes plaintext
// passwords to the database — only bcrypt hashes.
//
// Usage:
//   MONGODB_URI="mongodb+srv://..." node scripts/seed-users.js
//
// You will be prompted to set/confirm a password for each account
// interactively, so a real password never has to be committed to a
// file. After running this, delete/rotate the temporary passwords if
// you typed them anywhere insecure (e.g. shell history).
//
// Safe to re-run: existing usernames are skipped, not overwritten.

const readline = require("readline");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcryptjs");

const SALT_ROUNDS = 12;

const STAFF_TO_CREATE = [
  {
    username: "sentinel",
    role: "sentinel",
    name: "Sentinel",
    title: "Founder & Chief System Architect",
    email: "sentinel@cowboychurchmaplevalley.com",
    avatar: "S",
    color: "#C9A84C",
    bio: "Sentinel is the founder and technical architect behind Cowboy Church of Maple Valley's digital presence.",
  },
  {
    username: "pastor",
    role: "pastor",
    name: "Pastor",
    title: "Pastor",
    email: "pastor@cowboychurchmaplevalley.com",
    avatar: "P",
    color: "#7A9474",
    bio: "Our beloved pastor leads Sunday worship, Bible study, and officiates all ceremonies.",
  },
  {
    username: "mom",
    role: "mom",
    name: "Mom",
    title: "Wedding Planner",
    email: "mom@cowboychurchmaplevalley.com",
    avatar: "M",
    color: "#C7745C",
    bio: "Our dedicated wedding planner ensures every couple's special day is absolutely perfect.",
  },
];

function ask(rl, question, { hidden = false } = {}) {
  return new Promise((resolve) => {
    if (!hidden) {
      rl.question(question, resolve);
      return;
    }
    // Simple masked input for passwords typed at the terminal.
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
      if (char === "\u0003") process.exit(1); // Ctrl+C
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
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.error("Set MONGODB_URI before running this script.");
    process.exit(1);
  }
  const dbName = process.env.MONGODB_DB || "cowboychurch";

  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db(dbName);
  const users = db.collection("users");
  await users.createIndex({ username: 1 }, { unique: true });

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

  for (const staff of STAFF_TO_CREATE) {
    const existing = await users.findOne({ username: staff.username });
    if (existing) {
      console.log(`✓ "${staff.username}" already exists — skipping.`);
      continue;
    }
    let password = "";
    let confirm = "";
    do {
      password = await ask(rl, `Set a password for "${staff.username}" (min 8 chars): `, {
        hidden: true,
      });
      if (password.length < 8) {
        console.log("  Too short — try again.");
        continue;
      }
      confirm = await ask(rl, "  Confirm password: ", { hidden: true });
      if (password !== confirm) console.log("  Passwords didn't match — try again.");
    } while (password.length < 8 || password !== confirm);

    const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
    await users.insertOne({ ...staff, passwordHash });
    console.log(`✓ Created "${staff.username}".`);
  }

  rl.close();
  await client.close();
  console.log("Done.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
