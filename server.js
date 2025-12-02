// server.js
// Node/Express server for Kacper's List
// - Serves files from /public
// - Exposes /api/* endpoints that read/write JSON files in /data
// - Implements Discord OAuth code exchange (server-side) using provided CLIENT_ID and CLIENT_SECRET
//
// NOTE: This file stores secrets in plaintext (as requested). For production use, store secrets in env vars.

const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const fetch = require('node-fetch');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const morgan = require('morgan');

const app = express();
app.use(morgan('dev'));
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: '1mb' }));

// Session config (very basic)
app.use(session({
  secret: 'kacpers-list-secret-please-change', // change if you want
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 3600 * 1000 } // 7 days
}));

// --- CONFIG: replace these if you want or use env vars ---
const CLIENT_ID = 1445110495618269225;
const CLIENT_SECRET = 'LD-t0Y4N0KMg1oz9S_MWv44gKqc63Edt';

// If you deploy the server to a domain, set SERVER_BASE_URL accordingly (no trailing slash)
const SERVER_BASE_URL = process.env.SERVER_BASE_URL || 'http://localhost:3000';

// For Discord endpoints
const DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token';
const DISCORD_API_ME = 'https://discord.com/api/users/@me';

// Admin Discord IDs who can access submissions admin UI
const ADMIN_DISCORD_IDS = new Set([
  '1120387357292626053',
  '1008401746692931634'
]);

// Data file paths (in /data)
const DATA_DIR = path.join(__dirname, 'data');
const FILE_USERS = path.join(DATA_DIR, 'users.json');
const FILE_SUBMISSIONS = path.join(DATA_DIR, 'submissions.json');
const FILE_LEADERBOARD = path.join(DATA_DIR, 'leaderboard.json');
const FILE_TERMINATED = path.join(DATA_DIR, 'terminated.json');

// Ensure data dir exists and files exist
async function ensureFiles() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
    const files = [
      [FILE_USERS, '[]'],
      [FILE_SUBMISSIONS, '[]'],
      [FILE_LEADERBOARD, '[]'],
      [FILE_TERMINATED, '{}']
    ];
    for (const [p, initial] of files) {
      try {
        await fs.access(p);
      } catch (e) {
        await fs.writeFile(p, initial, 'utf8');
      }
    }
  } catch (e) {
    console.error('Failed to ensure data files', e);
  }
}

// Helpers to read/write JSON files
async function readJson(filePath) {
  try {
    const txt = await fs.readFile(filePath, 'utf8');
    return JSON.parse(txt || 'null') || (Array.isArray(JSON.parse(txt || '[]')) ? [] : {});
  } catch (e) {
    return Array.isArray(e) ? [] : [];
  }
}
async function writeJson(filePath, obj) {
  const str = JSON.stringify(obj, null, 2);
  await fs.writeFile(filePath, str, 'utf8');
}

// Middleware to expose session user
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// API endpoints ---------------------------------------------------

// GET /api/me - returns current logged-in session data (or null)
app.get('/api/me', async (req, res) => {
  if (!req.session.user) return res.json(null);
  // fetch fresh user data from users.json
  const users = await readJson(FILE_USERS);
  const u = users.find(x => x.username && (x.username.toLowerCase() === (req.session.user.username || '').toLowerCase() || x.discordId === req.session.user.discordId));
  if (!u) {
    // user removed server-side: clear session
    req.session.user = null;
    return res.json(null);
  }
  // return safe user object
  const safe = {
    username: u.username,
    tag: u.tag,
    mto: !!u.mto,
    isBanned: !!u.isBanned,
    discordId: u.discordId || null,
    displayName: u.displayName || null,
    avatar: u.avatar || null
  };
  res.json(safe);
});

// GET /api/users
app.get('/api/users', async (req, res) => {
  const users = await readJson(FILE_USERS);
  res.json(users);
});

// GET /api/submissions
app.get('/api/submissions', async (req, res) => {
  const subs = await readJson(FILE_SUBMISSIONS);
  res.json(subs);
});

// GET /api/leaderboard
app.get('/api/leaderboard', async (req, res) => {
  const lb = await readJson(FILE_LEADERBOARD);
  res.json(lb);
});

// GET /api/terminated
app.get('/api/terminated', async (req, res) => {
  const t = await readJson(FILE_TERMINATED);
  res.json(t);
});

// POST /api/signup - username & password (password is stored as SHA-256 hex)
app.post('/api/signup', async (req, res) => {
  const { username, passwordHash } = req.body;
  if (!username || !passwordHash) return res.status(400).json({ error: 'username & passwordHash required' });

  const users = await readJson(FILE_USERS);
  if (users.find(u => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'username taken' });
  }
  // generate tag
  const taken = new Set(users.map(u => u.tag));
  let tag = null;
  for (let i = 1; i < 10000; i++) {
    const t = String(i).padStart(4, '0');
    if (!taken.has(t)) { tag = t; break; }
  }
  if (!tag) tag = String(Date.now()).slice(-4);

  const newUser = {
    username,
    passwordHash,
    tag,
    createdAt: Date.now(),
    isBanned: false,
    mto: false
  };
  users.push(newUser);
  await writeJson(FILE_USERS, users);
  // set session
  req.session.user = { username: newUser.username };
  res.json({ ok: true, user: { username: newUser.username, tag: newUser.tag } });
});

// POST /api/login - username & passwordHash
app.post('/api/login', async (req, res) => {
  const { username, passwordHash } = req.body;
  if (!username || !passwordHash) return res.status(400).json({ error: 'username & passwordHash required' });
  const users = await readJson(FILE_USERS);
  const u = users.find(x => x.username.toLowerCase() === username.toLowerCase());
  if (!u) return res.status(401).json({ error: 'invalid' });
  if (u.passwordHash !== passwordHash) return res.status(401).json({ error: 'invalid' });
  if (u.isBanned) return res.status(403).json({ error: 'banned', reason: u.banReason || null });

  req.session.user = { username: u.username, discordId: u.discordId || null };
  res.json({ ok: true, user: { username: u.username, tag: u.tag } });
});

// POST /api/submissions - create a submission (must be logged in)
app.post('/api/submissions', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'not logged in' });
  const { name, creator, youtube } = req.body;
  if (!name || !creator) return res.status(400).json({ error: 'name & creator required' });

  const subs = await readJson(FILE_SUBMISSIONS);
  subs.push({
    id: Date.now() + '-' + Math.floor(Math.random() * 1000),
    name,
    creator,
    youtube: youtube || '',
    submittedBy: req.session.user.username || 'Unknown',
    submittedAt: Date.now()
  });
  await writeJson(FILE_SUBMISSIONS, subs);
  res.json({ ok: true });
});

// POST /api/approve - approve a submission (admin only)
// payload: { submissionId, rank }
app.post('/api/approve', async (req, res) => {
  const actor = req.session.user;
  if (!actor) return res.status(401).json({ error: 'not logged in' });

  // allow if actor is Discord admin ID or their discordId stored with user matches admin set
  const users = await readJson(FILE_USERS);
  const u = users.find(x => x.username === actor.username);
  const discordId = u && u.discordId ? u.discordId : (actor.discordId || null);
  if (!discordId || !ADMIN_DISCORD_IDS.has(String(discordId))) {
    return res.status(403).json({ error: 'forbidden' });
  }

  const { submissionId, rank } = req.body;
  if (!submissionId || !rank) return res.status(400).json({ error: 'submissionId & rank required' });

  const subs = await readJson(FILE_SUBMISSIONS);
  const idx = subs.findIndex(s => s.id === submissionId);
  if (idx === -1) return res.status(404).json({ error: 'submission not found' });

  const entry = subs[idx];

  let leaderboard = await readJson(FILE_LEADERBOARD);
  // bump entries at >= rank
  leaderboard.forEach(en => {
    if (Number(en.rank) >= Number(rank)) en.rank = Number(en.rank) + 1;
  });
  leaderboard.push({
    id: 'lb-' + Date.now() + '-' + Math.floor(Math.random() * 1000),
    name: entry.name,
    creator: entry.creator,
    youtube: entry.youtube,
    submittedBy: entry.submittedBy,
    rank: Number(rank)
  });
  leaderboard.sort((a, b) => Number(a.rank) - Number(b.rank));
  await writeJson(FILE_LEADERBOARD, leaderboard);

  // remove submission
  subs.splice(idx, 1);
  await writeJson(FILE_SUBMISSIONS, subs);

  res.json({ ok: true });
});

// POST /api/remove-leaderboard (admin) payload: { id }
app.post('/api/remove-leaderboard', async (req, res) => {
  const actor = req.session.user;
  if (!actor) return res.status(401).json({ error: 'not logged in' });
  const users = await readJson(FILE_USERS);
  const u = users.find(x => x.username === actor.username);
  const discordId = u && u.discordId ? u.discordId : (actor.discordId || null);
  if (!discordId || !ADMIN_DISCORD_IDS.has(String(discordId))) {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { id } = req.body;
  if (!id) return res.status(400).json({ error: 'id required' });
  let lb = await readJson(FILE_LEADERBOARD);
  lb = lb.filter(e => e.id !== id);
  await writeJson(FILE_LEADERBOARD, lb);
  res.json({ ok: true });
});

// POST /api/users/rename (admin) payload: { oldName, newName }
app.post('/api/users/rename', async (req, res) => {
  const actor = req.session.user;
  if (!actor) return res.status(401).json({ error: 'not logged in' });
  const users = await readJson(FILE_USERS);
  const me = users.find(x => x.username === actor.username);
  const discordId = me && me.discordId ? me.discordId : (actor.discordId || null);
  if (!discordId || !ADMIN_DISCORD_IDS.has(String(discordId))) return res.status(403).json({ error: 'forbidden' });

  const { oldName, newName } = req.body;
  if (!oldName || !newName) return res.status(400).json({ error: 'oldName & newName required' });

  const target = users.find(x => x.username.toLowerCase() === oldName.toLowerCase());
  if (!target) return res.status(404).json({ error: 'user not found' });
  if (users.find(x => x.username.toLowerCase() === newName.toLowerCase())) return res.status(409).json({ error: 'new name taken' });

  // rename
  for (const uu of users) {
    if (uu.username.toLowerCase() === oldName.toLowerCase()) uu.username = newName;
  }
  await writeJson(FILE_USERS, users);

  // update submissions and leaderboard submittedBy fields
  const subs = await readJson(FILE_SUBMISSIONS);
  subs.forEach(s => {
    if (s.submittedBy && s.submittedBy.toLowerCase() === oldName.toLowerCase()) s.submittedBy = newName;
  });
  await writeJson(FILE_SUBMISSIONS, subs);

  let lb = await readJson(FILE_LEADERBOARD);
  lb.forEach(e => {
    if (e.submittedBy && e.submittedBy.toLowerCase() === oldName.toLowerCase()) e.submittedBy = newName;
  });
  await writeJson(FILE_LEADERBOARD, lb);

  res.json({ ok: true });
});

// POST /api/users/remove (admin) payload: { username, reason }
// Will delete user, remove their submissions and leaderboard entries and store termination reason
app.post('/api/users/remove', async (req, res) => {
  const actor = req.session.user;
  if (!actor) return res.status(401).json({ error: 'not logged in' });
  const users = await readJson(FILE_USERS);
  const me = users.find(x => x.username === actor.username);
  const discordId = me && me.discordId ? me.discordId : (actor.discordId || null);
  if (!discordId || !ADMIN_DISCORD_IDS.has(String(discordId))) return res.status(403).json({ error: 'forbidden' });

  const { username, reason } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });

  let usersArr = users.filter(u => u.username.toLowerCase() !== username.toLowerCase());
  await writeJson(FILE_USERS, usersArr);

  // remove submissions
  let subs = await readJson(FILE_SUBMISSIONS);
  subs = subs.filter(s => !(s.submittedBy && s.submittedBy.toLowerCase() === username.toLowerCase()));
  await writeJson(FILE_SUBMISSIONS, subs);

  // remove leaderboard entries
  let lb = await readJson(FILE_LEADERBOARD);
  lb = lb.filter(e => !(e.submittedBy && e.submittedBy.toLowerCase() === username.toLowerCase()));
  await writeJson(FILE_LEADERBOARD, lb);

  // update terminated.json
  const t = await readJson(FILE_TERMINATED);
  t[username] = { reason: reason || 'No reason provided', timestamp: Date.now() };
  await writeJson(FILE_TERMINATED, t);

  res.json({ ok: true });
});

// POST /api/users/ban (admin) payload: { username, reason }
// Marks isBanned true in users.json and saves reason
app.post('/api/users/ban', async (req, res) => {
  const actor = req.session.user;
  if (!actor) return res.status(401).json({ error: 'not logged in' });
  const users = await readJson(FILE_USERS);
  const me = users.find(x => x.username === actor.username);
  const discordId = me && me.discordId ? me.discordId : (actor.discordId || null);
  if (!discordId || !ADMIN_DISCORD_IDS.has(String(discordId))) return res.status(403).json({ error: 'forbidden' });

  const { username, reason } = req.body;
  if (!username) return res.status(400).json({ error: 'username required' });
  const u = users.find(x => x.username.toLowerCase() === username.toLowerCase());
  if (!u) return res.status(404).json({ error: 'user not found' });

  u.isBanned = true;
  u.banReason = reason || 'No reason provided';
  await writeJson(FILE_USERS, users);

  // also add to terminated.json
  const t = await readJson(FILE_TERMINATED);
  t[username] = { reason: u.banReason, timestamp: Date.now() };
  await writeJson(FILE_TERMINATED, t);

  res.json({ ok: true });
});

// Discord OAuth endpoints ----------------------------------------

// GET /auth/discord -> redirect to Discord OAuth2 authorize (code)
app.get('/auth/discord', (req, res) => {
  const redirectUri = `${SERVER_BASE_URL}/auth/discord/callback`;
  // scope identify
  const scope = encodeURIComponent('identify');
  // always request code response_type=code
  const url = `https://discord.com/api/oauth2/authorize?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${scope}`;
  res.redirect(url);
});

// GET /auth/discord/callback?code=...
// Exchange code for token, fetch /users/@me, create/find user in users.json, set session
app.get('/auth/discord/callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('Code missing');

  const redirectUri = `${SERVER_BASE_URL}/auth/discord/callback`;

  // Exchange code for token
  const params = new URLSearchParams();
  params.append('client_id', String(CLIENT_ID));
  params.append('client_secret', String(CLIENT_SECRET));
  params.append('grant_type', 'authorization_code');
  params.append('code', code);
  params.append('redirect_uri', redirectUri);

  try {
    const tokenResp = await fetch(DISCORD_TOKEN_URL, {
      method: 'POST',
      body: params,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    if (!tokenResp.ok) {
      const txt = await tokenResp.text();
      console.error('Token error', tokenResp.status, txt);
      return res.status(500).send('Token exchange failed');
    }
    const tokenJson = await tokenResp.json();
    const accessToken = tokenJson.access_token;

    // fetch user
    const meResp = await fetch(DISCORD_API_ME, {
      headers: { Authorization: `Bearer ${accessToken}` }
    });
    if (!meResp.ok) {
      const txt = await meResp.text();
      console.error('Fetch me error', meResp.status, txt);
      return res.status(500).send('Failed to fetch Discord user');
    }
    const meJson = await meResp.json();

    // meJson contains: id, username, discriminator, avatar
    // Create or update local user in users.json
    const users = await readJson(FILE_USERS);
    let found = users.find(u => u.discordId === meJson.id);
    if (!found) {
      // If there's a user with same username, don't override — create a new account (append displayName)
      const tag = (() => {
        const taken = new Set(users.map(u => u.tag));
        for (let i = 1; i < 10000; i++) {
          const t = String(i).padStart(4, '0');
          if (!taken.has(t)) return t;
        }
        return String(Date.now()).slice(-4);
      })();
      const displayName = `${meJson.username}#${meJson.discriminator}`;
      found = {
        username: `${meJson.username}`, // allow name collisions — unique key is discordId
        tag,
        discordId: meJson.id,
        displayName,
        avatar: meJson.avatar || null,
        passwordHash: null,
        createdAt: Date.now(),
        isBanned: false,
        mto: false
      };
      users.push(found);
    } else {
      // update avatar/displayName if changed
      found.avatar = meJson.avatar || found.avatar;
      found.displayName = `${meJson.username}#${meJson.discriminator}` || found.displayName;
    }
    await writeJson(FILE_USERS, users);

    // Set session
    req.session.user = {
      username: found.username,
      discordId: found.discordId,
      displayName: found.displayName,
      avatar: found.avatar
    };

    // Redirect back to the public site (index)
    // If you host public files at /public/index.html, redirect accordingly.
    const redirectBack = `${SERVER_BASE_URL}/public/index.html`;
    return res.redirect(redirectBack);
  } catch (e) {
    console.error('OAuth callback error', e);
    return res.status(500).send('OAuth callback failed');
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  req.session.user = null;
  req.session.destroy && req.session.destroy(() => {});
  res.json({ ok: true });
});

// Administrative endpoints to directly read/write files (for convenience):
// GET /admin/read/:file  (allowed only for local requests) - not recommended, but included
app.get('/admin/read/:file', async (req, res) => {
  const allowed = ['users.json', 'submissions.json', 'leaderboard.json', 'terminated.json'];
  if (!allowed.includes(req.params.file)) return res.status(404).send('Not found');
  const fp = path.join(DATA_DIR, req.params.file);
  try {
    const js = await readJson(fp);
    return res.json(js);
  } catch (e) {
    return res.status(500).json({ error: 'read failed' });
  }
});

// Serve static site under /public
app.use('/public', express.static(path.join(__dirname, 'public')));

// Root redirect to public/index.html for convenience
app.get('/', (req, res) => {
  res.redirect('/public/index.html');
});

// ensure files and start
ensureFiles().then(() => {
  const port = process.env.PORT || 3000;
  app.listen(port, () => {
    console.log(`Server running on port ${port}`);
    console.log(`SERVER_BASE_URL = ${SERVER_BASE_URL}`);
  });
});
