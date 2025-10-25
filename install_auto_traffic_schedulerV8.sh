#!/usr/bin/env bash
# install_auto_traffic_scheduler.sh
# 一键安装：Auto Traffic Platform with Scheduler (Redis queue + Playwright Workers + Web panel + hourly quotas)
# 适用于 Ubuntu / Debian
set -euo pipefail

# ------------- 可修改默认配置（在运行脚本前可以编辑这些变量） -------------
INSTALL_DIR="/opt/auto-traffic-scheduler"
PORT=8080
REDIS_PORT=6379
ADMIN_USER_DEFAULT="admin"
ADMIN_PASS_DEFAULT="admin"                # 部署后请尽快修改（面板可修改）
JWT_SECRET_DEFAULT="please_change_jwt"    # 部署后请尽快修改
DEFAULT_PROXY_CHECK_CONCURRENCY=300
PLAYWRIGHT_HEADLESS=true
# ------------------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 或 sudo 运行此脚本。"
  exit 1
fi

echo "安装目录：${INSTALL_DIR}"
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo "更新系统并安装基础依赖..."
apt update -y
apt install -y curl wget git build-essential ca-certificates redis-server python3

echo "安装 Node.js 18.x 与 pm2..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt install -y nodejs
npm install -g pm2

echo "生成 package.json 并安装 npm 依赖..."
cat > package.json <<'JSON'
{
  "name": "auto-traffic-scheduler",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "express":"^4.18.2",
    "multer":"^1.4.5-lts.1",
    "playwright":"^1.45.0",
    "sqlite3":"^5.1.6",
    "axios":"^1.4.0",
    "user-agents":"^1.0.710",
    "p-limit":"^4.0.0",
    "body-parser":"^1.20.2",
    "cors":"^2.8.5",
    "uuid":"^9.0.0",
    "redis":"^4.6.5",
    "bcrypt":"^5.1.0",
    "jsonwebtoken":"^9.0.0",
    "node-schedule":"^2.1.0"
  }
}
JSON

npm install --production

echo "安装 Playwright 浏览器二进制（耗时，可能较大）..."
if [ -n "${SUDO_USER:-}" ]; then
  su - "$SUDO_USER" -c "cd $INSTALL_DIR && npx playwright install --with-deps"
else
  npx playwright install --with-deps
fi

# 目录
mkdir -p uploads logs public

########################################
# server.js - 后端：API、上传代理、代理检测、任务提交、调度配置接口
########################################
cat > server.js <<'NODEJS'
/**
 * server.js
 * - Login (username/password) -> JWT
 * - Upload proxies (stream)
 * - Trigger proxy check (async)
 * - Clean bad proxies
 * - Start task (push to redis)
 * - Schedule configuration endpoints (set hourly quotas)
 * - Serve static panel (public/)
 *
 * Environment / PM2 env used:
 *  - PORT
 *  - REDIS_HOST, REDIS_PORT
 *  - ADMIN_USER, ADMIN_PASS_HASH, JWT_SECRET
 *  - DEFAULT_PROXY_CHECK_CONCURRENCY
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const multer = require('multer');
const bodyParser = require('body-parser');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const redis = require('redis');
const { spawn } = require('child_process');

const APP_ROOT = process.cwd();
const DB_FILE = path.join(APP_ROOT, 'data.db');
const UPLOAD_DIR = path.join(APP_ROOT, 'uploads');
const LOG_DIR = path.join(APP_ROOT, 'logs');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR,{recursive:true});
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR,{recursive:true});

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: '30mb' }));
app.use(express.static(path.join(APP_ROOT,'public')));

const PORT = process.env.PORT || ${PORT};
const REDIS_HOST = process.env.REDIS_HOST || '127.0.0.1';
const REDIS_PORT = process.env.REDIS_PORT || ${REDIS_PORT};
const DEFAULT_PROXY_CHECK_CONCURRENCY = parseInt(process.env.DEFAULT_PROXY_CHECK_CONCURRENCY || ${DEFAULT_PROXY_CHECK_CONCURRENCY}, 10);

const ADMIN_USER = process.env.ADMIN_USER || '${ADMIN_USER_DEFAULT}';
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH || bcrypt.hashSync('${ADMIN_PASS_DEFAULT}', 10);
const JWT_SECRET = process.env.JWT_SECRET || '${JWT_SECRET_DEFAULT}';

// sqlite init
const db = new sqlite3.Database(DB_FILE);
db.serialize(() => {
  db.run(\`CREATE TABLE IF NOT EXISTS proxies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    raw TEXT,
    ip TEXT,
    port INTEGER,
    protocol TEXT,
    user TEXT,
    pass TEXT,
    alive INTEGER DEFAULT 0,
    last_check TEXT
  )\`);
  db.run(\`CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT,
    url TEXT,
    selector TEXT,
    playStartDelayMs INTEGER,
    watchMs INTEGER,
    rounds INTEGER,
    concurrency TEXT,
    referers TEXT,
    created_at TEXT,
    status TEXT
  )\`);
  db.run(\`CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT,
    ts TEXT,
    proxy TEXT,
    ua TEXT,
    device TEXT,
    action TEXT,
    detail TEXT,
    screenshot TEXT
  )\`);
  db.run(\`CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    timezone TEXT,
    config_json TEXT,
    created_at TEXT
  )\`);
});

// redis client
const rclient = redis.createClient({ url: `redis://${REDIS_HOST}:${REDIS_PORT}` });
rclient.on('error', (e)=> console.error('Redis error', e));
(async ()=>{ await rclient.connect(); })();

// helpers
function signToken(payload){ return jwt.sign(payload, JWT_SECRET, { expiresIn: '12h' }); }
function authMiddleware(req,res,next){
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).send('unauthorized');
  try {
    const p = jwt.verify(m[1], JWT_SECRET);
    req.user = p; next();
  } catch(e){ return res.status(403).send('forbidden'); }
}

// login
app.post('/api/login', async (req,res)=>{
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'missing' });
  if (username !== (process.env.ADMIN_USER || '${ADMIN_USER_DEFAULT}')) return res.status(401).json({ error:'invalid' });
  const hash = process.env.ADMIN_PASS_HASH || '${ADMIN_PASS_HASH}';
  const ok = await bcrypt.compare(password, hash);
  if (!ok) return res.status(401).json({ error:'invalid' });
  const token = signToken({ username });
  res.json({ token });
});

// parse proxy line
function parseProxyLine(line){
  const s = line.trim();
  if (!s) return null;
  if (s.includes('@') && s.includes(':')) {
    const [left,right] = s.split('@');
    const [user, pass] = left.split(':');
    const parts = right.split(':');
    if (parts.length >= 2) return { raw:s, ip:parts[0], port:parseInt(parts[1]), protocol: parts[2]||'http', user, pass };
  }
  const parts = s.split(':');
  if (parts.length === 2) return { raw:s, ip:parts[0], port:parseInt(parts[1]), protocol:'http', user:null, pass:null };
  if (parts.length === 4) return { raw:s, ip:parts[0], port:parseInt(parts[1]), protocol: parts[3]||'http', user:parts[2]||null, pass:parts[3]||null };
  if (parts.length === 5) return { raw:s, ip:parts[0], port:parseInt(parts[1]), protocol: parts[4]||'http', user:parts[2]||null, pass:parts[3]||null };
  return null;
}

// upload proxies (stream)
const upload = multer({ dest: UPLOAD_DIR, limits: { fileSize: 1024 * 1024 * 1024 } });
app.post('/api/uploadProxies', authMiddleware, upload.single('proxyfile'), (req,res)=>{
  if (!req.file) return res.status(400).send('no file');
  const filepath = req.file.path;
  const rl = require('readline').createInterface({ input: fs.createReadStream(filepath), crlfDelay: Infinity });
  let inserted = 0;
  const stmt = db.prepare("INSERT INTO proxies (raw, ip, port, protocol, user, pass, alive) VALUES (?, ?, ?, ?, ?, ?, 0)");
  rl.on('line', line => {
    const p = parseProxyLine(line);
    if (p) { stmt.run(p.raw, p.ip, p.port, p.protocol||'http', p.user||'', p.pass||''); inserted++; }
  });
  rl.on('close', () => { stmt.finalize(); fs.unlinkSync(filepath); res.json({ inserted }); });
});

// list proxies
app.get('/api/proxies', authMiddleware, (req,res)=>{
  const limit = parseInt(req.query.limit || '1000',10);
  db.all("SELECT id, raw, ip, port, protocol, user, alive, last_check FROM proxies ORDER BY id DESC LIMIT ?", [limit], (err,rows)=> res.json(rows || []));
});

// delete dead
app.post('/api/cleanBad', authMiddleware, (req,res)=>{
  db.run("DELETE FROM proxies WHERE alive=0", function(err){ if (err) return res.status(500).send('error'); res.json({ deleted: this.changes }); });
});

// curl test helper (supports socks5 via curl args)
function curlTest(proxy, timeoutMs=6000){
  return new Promise((resolve) => {
    const target = 'https://httpbin.org/ip';
    const args = ['-sS','--max-time', String(Math.ceil(timeoutMs/1000)), '-I', target];
    if (proxy) {
      const proto = (proxy.protocol||'http').toLowerCase();
      if (proto.includes('socks')) args.unshift('--socks5-hostname', \`\${proxy.ip}:\${proxy.port}\`);
      else args.unshift('--proxy', \`\${proxy.ip}:\${proxy.port}\`);
      if (proxy.user) args.unshift('--proxy-user', \`\${proxy.user}:\${proxy.pass}\`);
    }
    const cp = spawn('curl', args, { stdio: 'ignore' });
    let done=false;
    const timer = setTimeout(()=>{ if(!done){ done=true; cp.kill('SIGKILL'); resolve(false); } }, timeoutMs+500);
    cp.on('exit', code => { if(done) return; done=true; clearTimeout(timer); resolve(code===0); });
    cp.on('error', ()=>{ if(!done){ done=true; clearTimeout(timer); resolve(false); } });
  });
}

// run proxy check async
async function runFullProxyCheck(concurrency = DEFAULT_PROXY_CHECK_CONCURRENCY){
  const pLimit = require('p-limit');
  const limit = pLimit(concurrency === 'unlimited' ? Infinity : concurrency);
  const proxies = await new Promise(r => db.all("SELECT * FROM proxies", (e,rows)=> r(rows || [])));
  let okCount = 0;
  const jobs = proxies.map(p => limit(async () => {
    const ok = await curlTest(p, 6000);
    db.run("UPDATE proxies SET alive=?, last_check=datetime('now') WHERE id=?", [ok?1:0, p.id]);
    if (ok) okCount++;
  }));
  await Promise.all(jobs);
  return { total: proxies.length, ok: okCount };
}

app.post('/api/runProxyCheck', authMiddleware, (req,res)=>{
  const c = parseInt(req.body.concurrency || DEFAULT_PROXY_
