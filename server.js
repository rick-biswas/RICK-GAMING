/* সাইট + অ্যাডমিন API সার্ভার (কোনো npm প্যাকেজ লাগে না) — চালান: node server.js */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const ROOT = __dirname;
const DATA = process.env.DATA_DIR || path.join(ROOT, 'data');
const UP = path.join(DATA, 'uploads'), DBF = path.join(DATA, 'db.json');
fs.mkdirSync(UP, { recursive: true });

let db = { orders: [], config: {}, pass: null };
try { db = Object.assign(db, JSON.parse(fs.readFileSync(DBF, 'utf8'))); } catch (e) {}
function save() { const t = DBF + '.tmp'; fs.writeFileSync(t, JSON.stringify(db)); fs.renameSync(t, DBF); }

const safeEq = (a, b) => { const x = Buffer.from(String(a)), y = Buffer.from(String(b)); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const hp = (p, salt) => crypto.scryptSync(p, salt, 32).toString('hex');
const hasPass = () => !!(process.env.ADMIN_PASSWORD || db.pass);
function checkPass(p) {
  if (process.env.ADMIN_PASSWORD) return safeEq(p, process.env.ADMIN_PASSWORD);
  return !!db.pass && safeEq(hp(p, db.pass.salt), db.pass.hash);
}
function setPass(p) { const salt = crypto.randomBytes(16).toString('hex'); db.pass = { salt, hash: hp(p, salt) }; save(); }

const tokens = new Map();   // token -> expiry
const tries = new Map();    // ip -> {n,t}
const orderRate = new Map();
function newToken() { const t = crypto.randomBytes(24).toString('hex'); tokens.set(t, Date.now() + 30 * 864e5); return t; }
function isAdmin(req) {
  const m = /^Bearer (\w+)$/.exec(req.headers.authorization || '');
  if (!m) return false;
  const e = tokens.get(m[1]);
  if (!e || e < Date.now()) { tokens.delete(m[1]); return false; }
  return true;
}
function limited(map, ip, max, ms) {
  const now = Date.now(); let r = map.get(ip);
  if (!r || now - r.t > ms) r = { n: 0, t: now };
  r.n++; map.set(ip, r); return r.n > max;
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json',
  '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon' };
const BLOCK = /^(server\.js|package(-lock)?\.json|data|node_modules|\.)/i;

function send(res, code, obj, extra) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra));
  res.end(JSON.stringify(obj));
}
function body(req, limit) {
  return new Promise((ok, no) => {
    let n = 0; const ch = [];
    req.on('data', c => { n += c.length; if (n > limit) { no(new Error('big')); req.destroy(); } else ch.push(c); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(ch).toString() || '{}')); } catch (e) { no(e); } });
    req.on('error', no);
  });
}
const str = (v, n) => String(v == null ? '' : v).slice(0, n);

async function api(req, res, url) {
  const ip = req.headers['x-forwarded-for'] ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress;
  const r = url.pathname;

  if (r === '/api/ping') return send(res, 200, { ok: true, setup: !hasPass() });
  if (r === '/api/config') return send(res, 200, db.config || {});

  if (r === '/api/order' && req.method === 'POST') {
    if (limited(orderRate, ip, 40, 36e5)) return send(res, 429, { error: 'slow' });
    const b = await body(req, 20000);
    const o = {
      id: str(b.id, 30), package: str(b.package, 140), price: Number(b.price) || 0, uid: str(b.uid, 24),
      method: b.method === 'Nagad' ? 'Nagad' : 'bKash', trx: str(b.trx, 40), status: 'Pending',
      createdAt: isNaN(new Date(b.createdAt)) ? new Date().toISOString() : new Date(b.createdAt).toISOString()
    };
    if (!/^[A-Za-z0-9]{6,30}$/.test(o.id) || !o.package || o.price < 0 || o.price > 1e6) return send(res, 400, { error: 'bad' });
    if (!db.orders.some(x => x.id === o.id)) { db.orders.push(o); save(); }
    return send(res, 200, { ok: true });
  }
  if (r === '/api/status' && req.method === 'POST') {
    const b = await body(req, 20000), out = {};
    (Array.isArray(b.ids) ? b.ids.slice(0, 300) : []).forEach(id => {
      const o = db.orders.find(x => x.id === id);
      if (o) out[id] = { status: o.status, d: o.updatedDate || '', t: o.updatedTime || '' };
    });
    return send(res, 200, out);
  }
  if (r === '/api/login' && req.method === 'POST') {
    if (limited(tries, ip, 8, 6e5)) return send(res, 429, { error: 'অনেকবার ভুল হয়েছে, ১০ মিনিট পরে চেষ্টা করুন' });
    const b = await body(req, 2000), p = str(b.password, 200);
    if (!hasPass()) {
      if (p.length < 4) return send(res, 400, { error: 'কমপক্ষে ৪ অক্ষর দিন' });
      setPass(p); return send(res, 200, { token: newToken() });
    }
    if (!checkPass(p)) return send(res, 401, { error: 'ভুল পাসওয়ার্ড' });
    tries.delete(ip); return send(res, 200, { token: newToken() });
  }

  if (!isAdmin(req)) return send(res, 401, { error: 'login' });

  if (r === '/api/admin/orders') return send(res, 200, { orders: db.orders });
  if (r === '/api/admin/order' && req.method === 'POST') {
    const b = await body(req, 5000), i = db.orders.findIndex(x => x.id === b.id);
    if (i < 0) return send(res, 404, { error: 'nf' });
    if (b.del) db.orders.splice(i, 1);
    else if (['Pending', 'Completed', 'Cancelled'].includes(b.status)) {
      db.orders[i].status = b.status; db.orders[i].updatedDate = str(b.d, 30); db.orders[i].updatedTime = str(b.t, 30);
    }
    save(); return send(res, 200, { ok: true });
  }
  if (r === '/api/admin/clear' && req.method === 'POST') { db.orders = []; save(); return send(res, 200, { ok: true }); }
  if (r === '/api/admin/config' && req.method === 'POST') {
    const b = await body(req, 200000);
    if (!b.config || typeof b.config !== 'object') return send(res, 400, { error: 'bad' });
    db.config = b.config; save(); return send(res, 200, { ok: true });
  }
  if (r === '/api/admin/upload' && req.method === 'POST') {
    const b = await body(req, 9e6), m = /^data:image\/(png|jpeg|webp|gif);base64,([A-Za-z0-9+/=]+)$/.exec(b.data || '');
    if (!m) return send(res, 400, { error: 'ছবি সঠিক নয়' });
    const buf = Buffer.from(m[2], 'base64');
    const name = crypto.createHash('sha1').update(buf).digest('hex').slice(0, 20) + '.' + (m[1] === 'jpeg' ? 'jpg' : m[1]);
    fs.writeFileSync(path.join(UP, name), buf);
    return send(res, 200, { url: '/uploads/' + name });
  }
  if (r === '/api/admin/password' && req.method === 'POST') {
    const b = await body(req, 2000), p = str(b.password, 200);
    if (p.length < 4) return send(res, 400, { error: 'কমপক্ষে ৪ অক্ষর' });
    if (process.env.ADMIN_PASSWORD) return send(res, 400, { error: 'পাসওয়ার্ড ADMIN_PASSWORD env থেকে সেট করা — সেখানে বদলান' });
    setPass(p); return send(res, 200, { ok: true });
  }
  send(res, 404, { error: 'nf' });
}

function serveFile(res, file, cache) {
  fs.readFile(file, (e, buf) => {
    if (e) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Cache-Control': cache });
    res.end(buf);
  });
}

http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    let p = decodeURIComponent(url.pathname);
    if (p.startsWith('/uploads/')) {
      const f = path.join(UP, path.basename(p));
      return serveFile(res, f, 'public, max-age=31536000, immutable');
    }
    if (p === '/') p = '/index.html';
    const rel = path.normalize(p).replace(/^[/\\]+/, '');
    if (rel.includes('..') || BLOCK.test(rel)) { res.writeHead(403); return res.end('Forbidden'); }
    serveFile(res, path.join(ROOT, rel), /\.html?$/.test(rel) || rel === 'account.js' ? 'no-store' : 'public, max-age=300');
  } catch (e) {
    if (!res.headersSent) send(res, 500, { error: 'server' });
  }
}).listen(process.env.PORT || 3000, () => console.log('Running on port ' + (process.env.PORT || 3000)));
