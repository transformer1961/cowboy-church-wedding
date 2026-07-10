# Cowboy Church of Maple Valley — site + admin dashboard

Static Netlify site with a staff admin dashboard backed by Netlify
Functions and MongoDB Atlas.

## What changed in this pass

- **Fixed a critical bug:** `admin.html`'s entire dashboard script
  (~1,100 lines) was missing its opening `<script>` tag, so none of the
  admin panel's JavaScript ever ran in a browser. That's fixed.
- **Replaced fake client-side auth with real server-side auth.**
  Previously, staff usernames/passwords were hardcoded in plaintext in
  `login.html`'s JS and "sessions" were just a value in
  `sessionStorage` that anyone could set from devtools with zero
  credentials. Now:
  - Passwords are hashed with bcrypt and stored in MongoDB Atlas —
    never in the browser.
  - `netlify/functions/login.js` checks credentials server-side and
    issues a signed, **httpOnly, Secure** session cookie (JS on the
    page can't read or forge it).
  - `netlify/functions/verify.js` is the real gatekeeper — `admin.html`
    calls it on load and only renders if it returns 200.
  - `netlify/functions/logout.js` clears the cookie server-side.
  - `netlify/functions/users.js` handles staff profile/password
    changes and (for the `sentinel` role) managing other accounts.
- **Site content now persists to MongoDB Atlas**, not just one
  browser's `localStorage`. `netlify/functions/content.js` is a small
  key/value store for the content the dashboard edits (hero text,
  packages, bookings, inquiries, etc.). `localStorage` is still used
  as a fast local cache and offline fallback.
- Removed the `node_modules`, `.netlify` (local dev database dump +
  built function zips), and `deno.lock` from the delivered project —
  none of that belongs in source control; `.gitignore` already
  excluded it, it just needs to not be zipped up for delivery either.

## One-time setup

### 1. Create a MongoDB Atlas cluster

1. Sign up / log in at <https://www.mongodb.com/cloud/atlas>.
2. Create a free (M0) cluster.
3. Under **Database Access**, create a database user with a strong
   password (scoped to this project, not your Atlas account login).
4. Under **Network Access**, allow access from anywhere (`0.0.0.0/0`)
   — Netlify Functions run from rotating IPs, so this is the normal
   approach; the database user's password is what actually protects it.
5. Click **Connect > Drivers** and copy the connection string, e.g.
   `mongodb+srv://<user>:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority`

### 2. Set environment variables

Copy `.env.example` to `.env` for local dev, and set the same three
variables in **Netlify Site settings → Environment variables** for the
deployed site:

- `MONGODB_URI` — the connection string from above
- `MONGODB_DB` — any database name, e.g. `cowboychurch`
- `JWT_SECRET` — a long random string. Generate one with:
  ```
  node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
  ```

### 3. Install dependencies and create the staff accounts

```
npm install
MONGODB_URI="mongodb+srv://..." npm run seed
```

This prompts you to set a password of at least 12 characters for each of the three staff
accounts (`sentinel`, `pastor`, `mom`) interactively — no password is
ever written to a file or committed. Re-running the script later is
safe; it skips usernames that already exist.

### 4. Run locally / deploy

```
netlify dev      # local dev with functions + env vars from .env
netlify deploy    # or connect the repo in the Netlify dashboard
```

## Notes

- Only the three original roles (`sentinel`, `pastor`, `mom`) are
  seeded. A Sentinel can add, edit, remove, and assign per-section
  dashboard access to additional staff through **Staff Directory**.
- The public pages' `/api/content` calls now point at
  `/.netlify/functions/content`, which returns whatever's been saved
  under the dashboard's existing content keys (`hero`, `about`,
  `contact`, etc.). The specific flat fields those pages were reading
  (`statusText`, `contactEmail`) predate the current content-key
  structure and aren't populated by the dashboard today — that's a
  pre-existing gap, not something this pass introduced, and worth a
  follow-up if you want the header/footer bar and contact email to be
  editable from the dashboard too.
