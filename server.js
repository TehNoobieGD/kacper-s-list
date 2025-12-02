/**
 * server.js
 *
 * - Serves static files from /public
 * - Provides REST API endpoints for reading/writing JSON files:
 *     GET /api/users
 *     GET /api/submissions
 *     GET /api/leaderboard
 *     GET /api/terminated
 *
 * - POST /api/submissions  (authenticated via session cookie from Discord OAuth)
 * - Admin POST endpoints:
 *     POST /api/admin/approve   { submissionId, rank }
 *     POST /api/admin/decline   { submissionId }
 *     POST /api/admin/delete-user { username, reason }
 *     POST /api/admin/add-user  { username, optional passwordHash, mto }
 * - Discord OAuth:
 *     GET  /auth/discord -> redirect to Discord
 *     GET  /auth/discord/callback -> exchange code, get user, create local user record, set session cookie
 *     GET  /auth/logout -> clear cookie
 *
 * - Persists JSONs into data/*.json on disk.
 * - Optionally commits updated files to GitHub using GITHUB_TOKEN and GITHUB_REPO (owner/repo) + GITHUB_BRANCH.
 *
 * Required environment variables (see README section below):
 * - COOKIE_SECRET: secret to sign session JWT
 * - DISCORD_CLIENT_ID
 * - DISCORD_CLIENT_SECRET
 * - DISCORD_REDIRECT_URI (should match your registered Discord redirect URL)
 * - ADMIN_IDS (comma-separated Discord user IDs that are admins)
 * - GITHUB_TOKEN (optional — if provided, server will push JSON changes to repo via Octokit)
 * - GITHUB_REPO (owner/repo) e.g. myuser/myrepo  (optional)
 * - GITHUB_BRANCH (default "main")
 *
 * Deploy this somewhere public (Render, Railway, Fly, Heroku, VPS).
 */

require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs-extra');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');
const { Octokit } = require('@octokit/rest');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: '1mb' }));
app.use(cookieParser());

const DATA_DIR = path.join(__dirname, 'data');
fs.ensureDirSync(DATA_DIR);

const PATH_USERS = path.join(DATA_DIR, 'users.json');
const PATH_SUBMISSIONS = path.join(DATA_DIR, 'submissions.json');
const PATH_LEADERBOARD = path.join(DATA_DIR, 'leaderboard.json');
const PATH_TERMINATED = path.join(DATA_DIR, 'terminated.json');

const DEFAULT_FILES = [
  { p: PATH_USERS, v: [] },
  { p: PATH_SUBMISSIONS, v: [] },
  { p: PATH_LEADERBOARD, v: [] },
  { p: PATH_TERMINATED, v: {} }
];

for (const f of DEFAULT_FILES) {
  if (!fs.existsSync(f.p)) fs.writeFileSync(f.p, JSON.stringify(f.v, null, 2));
}

// Environment config
const PORT = process.env.PORT || 3000;
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'replace_this_with_a_real_secret';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID || '1445110495618269225';
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET || '';
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || (process.env.BASE_URL ? `${process.env.BASE_URL}/auth/discord/callback` : null);
const ADMIN_IDS = (process.env.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean); // list of discord IDs
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || null;
const GITHUB_REPO = process.env.GITHUB_REPO || null; // format owner/repo
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';

// Octokit if token provided
let octokit = null;
if (GITHUB_TOKEN && GITHUB_REPO) {
  octokit = new Octokit({ auth: GITHUB_TOKEN });
}

// Helpers for file ops
async function readJson(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = await fs.readFile(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('readJson error', filePath, e);
    return fallback;
  }
}
async function writeJsonAtomic(filePath, obj) {
  await fs.writeFile(filePath + '.tmp', JSON.stringify(obj, null, 2));
  await fs.move(filePath + '.tmp', filePath, { overwrite: true });
}

// Optional: commit file to GitHub
async function commitToGitHub(filePathOnRepo, contentStr, message) {
  if (!octokit || !GITHUB_REPO) {
    throw new Error('GitHub not configured (GITHUB_TOKEN and GITHUB_REPO required)');
  }
  const [owner, repo] = GITHUB_REPO.split('/');
  // get current sha if exists
  try {
    const getRes = await octokit.repos.getContent({
      owner, repo,
      path: filePathOnRepo,
      ref: GITHUB_BRANCH
    });
    const sha = getRes.data.sha;
    const encoded = Buffer.from(contentStr, 'utf8').toString('base64');
    const putRes = await octokit.repos.createOrUpdateFileContents({
      owner, repo,
      path: filePathOnRepo,
      message: message || `Update ${filePathOnRepo}`,
      content: encoded,
      branch: GITHUB_BRANCH,
      sha
    });
    return putRes.data;
  } catch (err) {
    // If file not found, create it
    if (err.status === 404) {
      const encoded = Buffer.from(contentStr, 'utf8').toString('base64');
      const putRes = await octokit.repos.createOrUpdateFileContents({
        owner, repo,
        path: filePathOnRepo,
        message: message || `Create ${filePathOnRepo}`,
        content: encoded,
        branch: GITHUB_BRANCH
      });
      return putRes.data;
    }
    throw err;
  }
}

// Session helpers: create JWT signed cookie
function createSessionToken(payload) {
  return jwt.sign(payload, COOKIE_SECRET, { expiresIn: '30d' });
}
function verifySessionToken(token) {
  try {
    return jwt.verify(token, COOKIE_SECRET);
  } catch (e) {
    return null;
  }
}

// Middleware: identify session user if cookie present
app.use(async (req, res, next) => {
  req.currentUser = null;
  const token = req.cookies && req.cookies.session;
  if (token) {
    const data = verifySessionToken(token);
    if (data && data.userId) {
      const users = await readJson(PATH_USERS, []);
      const u = users.find(x => x.id === data.userId);
      if (u) {
        req.currentUser = u;
        req.isAdmin = ADMIN_IDS.includes(String(u.discordId)) || !!u.isAdmin || (ADMIN_IDS.includes(String(u.id)));
      }
    }
  }
  next();
});

// Serve static files (client)
app.use(express.static(path.join(__dirname, 'public')));

// Simple API to read JSONs (public reads)
app.get('/api/users', async (req, res) => {
  const users = await readJson(PATH_USERS, []);
  // don't leak passwordHash
  const safe = users.map(u => {
    const copy = { ...u };
    delete copy.passwordHash;
    return copy;
  });
  res.json(safe);
});
app.get('/api/submissions', async (req, res) => {
  const subs = await readJson(PATH_SUBMISSIONS, []);
  res.json(subs);
});
app.get('/api/leaderboard', async (req, res) => {
  const lb = await readJson(PATH_LEADERBOARD, []);
  res.json(lb);
});
app.get('/api/terminated', async (req, res) => {
  const t = await readJson(PATH_TERMINATED, {});
  res.json(t);
});

// Session info
app.get('/api/session', async (req, res) => {
  if (!req.currentUser) return res.json({ user: null });
  const u = { ...req.currentUser };
  delete u.passwordHash;
  res.json({ user: u, isAdmin: req.isAdmin });
});

// Discord OAuth: redirect
app.get('/auth/discord', (req, res) => {
  const base = 'https://discord.com/api/oauth2/authorize';
  const client_id = DISCORD_CLIENT_ID;
  const redirect_uri = DISCORD_REDIRECT_URI;
  const scope = 'identify';
  const url = `${base}?client_id=${encodeURIComponent(client_id)}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=${encodeURIComponent(scope)}`;
  return res.redirect(url);
});

// Discord OAuth callback
app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Missing code');

  if (!DISCORD_CLIENT_SECRET || !DISCORD_CLIENT_ID || !DISCORD_REDIRECT_URI) {
    return res.status(500).send('Server not configured for Discord OAuth (set DISCORD_CLIENT_ID/SECRET/REDIRECT_URI)');
  }

  try {
    // exchange code for token
    const tokenRes = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        client_secret: DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code,
        redirect_uri: DISCORD_REDIRECT_URI
      })
    });
    const tokenJson = await tokenRes.json();
    if (!tokenJson.access_token) {
      console.error('discord token error', tokenJson);
      return res.status(500).send('Discord token exchange failed');
    }

    // get user info
    const userRes = await fetch('https://discord.com/api/users/@me', {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` }
    });
    const discordUser = await userRes.json();
    // discordUser fields: id, username, discriminator, avatar

    // upsert into users.json
    const users = await readJson(PATH_USERS, []);
    let user = users.find(u => String(u.discordId) === String(discordUser.id));
    if (!user) {
      // create new user
      user = {
        id: uuidv4(),
        discordId: String(discordUser.id),
        username: `${discordUser.username}#${discordUser.discriminator}`,
        avatar: discordUser.avatar || null,
        createdAt: Date.now(),
        isBanned: false,
        banReason: null,
        mto: false,
        isAdmin: ADMIN_IDS.includes(String(discordUser.id))
      };
      users.push(user);
      await writeJsonAtomic(PATH_USERS, users);
      if (octokit && GITHUB_REPO) {
        // optionally commit updated users.json
        try {
          await commitToGitHub('/users.json', JSON.stringify(users, null, 2), `Add/update user ${user.username}`);
        } catch (e) {
          console.warn('GitHub commit failed (users.json)', e.message);
        }
      }
    } else {
      // update username/avatar if changed
      let changed = false;
      const newName = `${discordUser.username}#${discordUser.discriminator}`;
      if (user.username !== newName) { user.username = newName; changed = true; }
      if (user.avatar !== discordUser.avatar) { user.avatar = discordUser.avatar; changed = true; }
      if (changed) {
        await writeJsonAtomic(PATH_USERS, users);
      }
    }

    // If user is banned, show special page or redirect with message
    if (user.isBanned) {
      // Set a short session token so client can show termination screen if needed (or simply redirect to home).
      // We'll not set a logged-in session — instead redirect to home; client will check /api/terminated.
      return res.redirect('/?terminated=1');
    }

    // create session cookie
    const token = createSessionToken({ userId: user.id });
    res.cookie('session', token, { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 30 });
    return res.redirect('/');
  } catch (e) {
    console.error('OAuth callback error', e);
    return res.status(500).send('OAuth error');
  }
});

// Logout
app.get('/auth/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('/');
});

/**
 * POST /api/submissions
 * body: { name, creator, youtube }
 * Requires logged in user via cookie
 */
app.post('/api/submissions', async (req, res) => {
  try {
    if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
    // check ban
    if (req.currentUser.isBanned) return res.status(403).json({ error: 'Account banned' });

    const { name, creator, youtube } = req.body || {};
    if (!name || !creator) return res.status(400).json({ error: 'Missing fields' });
    // Basic validation for youtube link optional
    const item = {
      id: uuidv4(),
      name: String(name).slice(0, 250),
      creator: String(creator).slice(0, 250),
      youtube: youtube ? String(youtube).slice(0, 500) : '',
      submittedBy: req.currentUser.username || req.currentUser.discordId,
      submittedAt: Date.now()
    };
    const subs = await readJson(PATH_SUBMISSIONS, []);
    subs.push(item);
    await writeJsonAtomic(PATH_SUBMISSIONS, subs);

    res.json({ ok: true, submission: item, persisted: !!(octokit && GITHUB_REPO) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Admin middleware
 */
async function requireAdmin(req, res, next) {
  if (!req.currentUser) return res.status(401).json({ error: 'Not authenticated' });
  // admin if their discord id present in ADMIN_IDS env or user.isAdmin true
  const isAdmin = ADMIN_IDS.includes(String(req.currentUser.discordId)) || !!req.currentUser.isAdmin;
  if (!isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

/**
 * Admin: approve submission => move to leaderboard with given rank
 * body: { submissionId, rank }
 */
app.post('/api/admin/approve', requireAdmin, async (req, res) => {
  try {
    const { submissionId, rank } = req.body || {};
    if (!submissionId || !rank) return res.status(400).json({ error: 'Missing submissionId or rank' });
    const subs = await readJson(PATH_SUBMISSIONS, []);
    const idx = subs.findIndex(s => s.id === submissionId);
    if (idx === -1) return res.status(404).json({ error: 'Submission not found' });
    const item = subs[idx];

    const lb = await readJson(PATH_LEADERBOARD, []);
    // bump ranks >= rank
    lb.forEach(e => {
      if (Number(e.rank) >= Number(rank)) e.rank = Number(e.rank) + 1;
    });
    const newEntry = {
      id: uuidv4(),
      name: item.name,
      creator: item.creator,
      youtube: item.youtube,
      submittedBy: item.submittedBy,
      rank: Number(rank),
      addedAt: Date.now()
    };
    lb.push(newEntry);
    lb.sort((a, b) => Number(a.rank) - Number(b.rank));

    // remove from submissions
    subs.splice(idx, 1);

    await writeJsonAtomic(PATH_LEADERBOARD, lb);
    await writeJsonAtomic(PATH_SUBMISSIONS, subs);

    // optionally commit to GitHub
    if (octokit && GITHUB_REPO) {
      try {
        await commitToGitHub('/leaderboard.json', JSON.stringify(lb, null, 2), `Admin approve: add ${newEntry.name}`);
        await commitToGitHub('/submissions.json', JSON.stringify(subs, null, 2), `Admin approve: remove submission ${submissionId}`);
      } catch (e) {
        console.warn('GitHub commit failed (approve)', e.message);
      }
    }

    res.json({ ok: true, added: newEntry });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Admin decline: remove submission
 * body: { submissionId }
 */
app.post('/api/admin/decline', requireAdmin, async (req, res) => {
  try {
    const { submissionId } = req.body || {};
    if (!submissionId) return res.status(400).json({ error: 'Missing submissionId' });
    const subs = await readJson(PATH_SUBMISSIONS, []);
    const idx = subs.findIndex(s => s.id === submissionId);
    if (idx === -1) return res.status(404).json({ error: 'Submission not found' });
    subs.splice(idx, 1);
    await writeJsonAtomic(PATH_SUBMISSIONS, subs);
    if (octokit && GITHUB_REPO) {
      try {
        await commitToGitHub('/submissions.json', JSON.stringify(subs, null, 2), `Admin decline submission ${submissionId}`);
      } catch (e) { console.warn('GitHub commit failed (decline)', e.message); }
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Admin delete user: remove user record and their submissions/leaderboard entries,
 * and add terminated note
 * body: { username, reason }
 */
app.post('/api/admin/delete-user', requireAdmin, async (req, res) => {
  try {
    const { username, reason } = req.body || {};
    if (!username || !reason) return res.status(400).json({ error: 'Missing fields' });

    const users = await readJson(PATH_USERS, []);
    const userIndex = users.findIndex(u => u.username.toLowerCase() === username.toLowerCase());
    if (userIndex === -1) return res.status(404).json({ error: 'User not found' });
    const removedUser = users.splice(userIndex, 1)[0];

    let subs = await readJson(PATH_SUBMISSIONS, []);
    subs = subs.filter(s => !(s.submittedBy && s.submittedBy.toLowerCase() === removedUser.username.toLowerCase()));

    let lb = await readJson(PATH_LEADERBOARD, []);
    lb = lb.filter(e => !(e.submittedBy && e.submittedBy.toLowerCase() === removedUser.username.toLowerCase()));

    const terminated = await readJson(PATH_TERMINATED, {});
    terminated[removedUser.username] = { reason, timestamp: Date.now() };

    await writeJsonAtomic(PATH_USERS, users);
    await writeJsonAtomic(PATH_SUBMISSIONS, subs);
    await writeJsonAtomic(PATH_LEADERBOARD, lb);
    await writeJsonAtomic(PATH_TERMINATED, terminated);

    if (octokit && GITHUB_REPO) {
      try {
        await commitToGitHub('/users.json', JSON.stringify(users, null, 2), `Admin remove user ${removedUser.username}`);
        await commitToGitHub('/submissions.json', JSON.stringify(subs, null, 2), `Admin remove submissions of ${removedUser.username}`);
        await commitToGitHub('/leaderboard.json', JSON.stringify(lb, null, 2), `Admin remove leaderboard entries of ${removedUser.username}`);
        await commitToGitHub('/terminated.json', JSON.stringify(terminated, null, 2), `Admin terminated ${removedUser.username}`);
      } catch (e) {
        console.warn('GitHub commit failed (delete-user)', e.message);
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

/**
 * Admin: add user (create account)
 * body: { username, mto (bool) }
 */
app.post('/api/admin/add-user', requireAdmin, async (req, res) => {
  try {
    const { username, mto } = req.body || {};
    if (!username) return res.status(400).json({ error: 'Missing username' });
    const users = await readJson(PATH_USERS, []);
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
      return res.status(400).json({ error: 'Username exists' });
    }
    const newUser = {
      id: uuidv4(),
      discordId: null,
      username: username,
      avatar: null,
      createdAt: Date.now(),
      isBanned: false,
      banReason: null,
      mto: !!mto,
      isAdmin: false
    };
    users.push(newUser);
    await writeJsonAtomic(PATH_USERS, users);
    if (octokit && GITHUB_REPO) {
      try {
        await commitToGitHub('/users.json', JSON.stringify(users, null, 2), `Admin add user ${username}`);
      } catch (e) { console.warn('GitHub commit failed (add-user)', e.message); }
    }
    res.json({ ok: true, user: newUser });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server error' });
  }
});

// Fallback for SPA: serve index.html
app.get('*', (req, res) => {
  // if request is for API, return 404
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/')) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Discord OAuth client id: ${DISCORD_CLIENT_ID}`);
  if (!DISCORD_CLIENT_SECRET) console.warn('DISCORD_CLIENT_SECRET not set — OAuth will fail.');
  if (!DISCORD_REDIRECT_URI) console.warn('DISCORD_REDIRECT_URI not set — set to your server callback URL.');
  if (!COOKIE_SECRET) console.warn('You should set COOKIE_SECRET in env.');
});
