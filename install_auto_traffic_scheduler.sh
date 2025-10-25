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
  const c = parseInt(req.body.concurrency || DEFAULT_PROXY_CHECK_CONCURRENCY,10);
  (async ()=>{ try { const s = await runFullProxyCheck(c); console.log('proxy check done', s); } catch(e){ console.error(e); } })();
  res.json({ status:'started' });
});

// start task -> push to redis queue
app.post('/api/startTask', authMiddleware, async (req,res)=>{
  const b = req.body || {};
  if (!b.url) return res.status(400).send('url required');
  const id = uuidv4();
  const now = new Date().toISOString();
  const task = {
    id,
    name: b.name || \`task-\${Date.now()}\`,
    url: b.url,
    selector: b.selector || '[data-video-test="true"]',
    playStartDelayMs: parseInt(b.playStartDelayMs || 1000, 10),
    watchMs: parseInt(b.watchMs || 15000, 10),
    rounds: parseInt(b.rounds || 1, 10),
    concurrency: (b.concurrency === 'unlimited' ? 'unlimited' : (b.concurrency || 1)),
    referers: Array.isArray(b.referers) ? b.referers : (b.referers ? [b.referers] : []),
    created_at: now,
    status: 'queued'
  };
  db.run("INSERT INTO tasks (id,name,url,selector,playStartDelayMs,watchMs,rounds,concurrency,referers,created_at,status) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
    [task.id,task.name,task.url,task.selector,task.playStartDelayMs,task.watchMs,task.rounds, String(task.concurrency), JSON.stringify(task.referers), now, 'queued']);
  await rclient.rPush('taskQueue', JSON.stringify(task));
  res.json({ status:'queued', taskId: id });
});

// schedule management endpoints
// schedule config format: { name: string, timezone: 'Europe/Berlin', config: { "0": 100, "1": 50, ... "23": 10 } }
// meaning: in each hour (0-23) push N visits per hour (these are quotas)
app.post('/api/schedule', authMiddleware, (req,res)=>{
  const body = req.body || {};
  if (!body.name || !body.config) return res.status(400).send('name and config required');
  const tz = body.timezone || 'UTC';
  const now = new Date().toISOString();
  db.run("INSERT INTO schedules (name, timezone, config_json, created_at) VALUES (?,?,?,?)", [body.name, tz, JSON.stringify(body.config), now], function(err){
    if (err) return res.status(500).send('db error');
    res.json({ id: this.lastID });
  });
});

app.get('/api/schedules', authMiddleware, (req,res)=>{
  db.all("SELECT * FROM schedules ORDER BY id DESC", (err,rows)=> res.json(rows || []));
});

// delete schedule
app.delete('/api/schedule/:id', authMiddleware, (req,res)=>{
  db.run("DELETE FROM schedules WHERE id=?", [req.params.id], function(err){ if (err) return res.status(500).send('error'); res.json({ deleted: this.changes }); });
});

// list tasks and logs
app.get('/api/tasks', authMiddleware, (req,res)=> {
  db.all("SELECT id,name,url,rounds,concurrency,created_at,status FROM tasks ORDER BY created_at DESC LIMIT 200", (err,rows)=> res.json(rows || []));
});
app.get('/api/logs', authMiddleware, (req,res)=> {
  db.all("SELECT * FROM logs ORDER BY ts DESC LIMIT 500", (err,rows)=> res.json(rows || []));
});

// settings update (store new pm2 env via pm2 set)
app.post('/api/updateCredentials', authMiddleware, async (req,res)=>{
  const { newUser, newPass, newJwt } = req.body || {};
  if (!newUser && !newPass && !newJwt) return res.status(400).send('no changes');
  const spawnSync = require('child_process').spawnSync;
  if (newUser) spawnSync('pm2', ['set', 'auto-traffic-server:ADMIN_USER', newUser]);
  if (newPass) { const h = await bcrypt.hash(newPass, 10); spawnSync('pm2', ['set', 'auto-traffic-server:ADMIN_PASS_HASH', h]); }
  if (newJwt) spawnSync('pm2', ['set', 'auto-traffic-server:JWT_SECRET', newJwt]);
  res.json({ status:'ok', note:'Run pm2 restart auto-traffic-server --update-env to apply env changes' });
});

app.get('/api/health', (req,res)=> res.json({ ok:true, ts: new Date().toISOString() }));

app.listen(PORT, ()=> console.log('Server listening on', PORT));
NODEJS

########################################
# scheduler.js - 定时器：按 schedule 表把配额转为小任务并推入 Redis
# 工作逻辑：
#  - 每分钟检查 schedules 表
#  - 根据当前小时（按 schedule.timezone）计算该小时已投放任务数与配额
#  - 将本轮需投放的访问次数均分成小任务推入 taskQueue（包含原任务模板的 URL/selector/watchMs）
########################################
cat > scheduler.js <<'NODEJS'
/**
 * scheduler.js
 * - Poll schedules in DB
 * - For each active schedule, for the current hour compute how many "visits" should be scheduled
 * - Push small task units to Redis taskQueue (each unit = 1 visit)
 * - Record minimal metadata in logs table (optionally)
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const redis = require('redis');
const { DateTime } = require('luxon');

const APP_ROOT = process.cwd();
const DB = new sqlite3.Database(path.join(APP_ROOT, 'data.db'));
const rclient = redis.createClient({ url: process.env.REDIS_URL || `redis://127.0.0.1:${process.env.REDIS_PORT || ${REDIS_PORT}}` });

(async ()=> {
  await rclient.connect();
  console.log('Scheduler connected to Redis');
  // loop every minute
  while (true) {
    try {
      // load schedules
      const schedules = await new Promise(r => DB.all("SELECT * FROM schedules", (e,rows)=> r(rows || [])));
      for (const s of schedules) {
        const cfg = JSON.parse(s.config_json || '{}'); // keys "0".."23"
        const tz = s.timezone || 'UTC';
        const now = DateTime.now().setZone(tz);
        const hour = String(now.hour);
        const quota = parseInt(cfg[hour] || 0, 10);
        if (quota <= 0) continue;
        // compute how many have been queued/executed for this schedule & hour
        // naive approach: check logs for task_id prefix schedule:<s.id>:<hour>:<seq>
        // We'll push `quota` units across the hour evenly. To avoid pushing all at once, push only small batches per minute.
        // For simplicity: push up to batchPerMinute = Math.ceil(quota / 60)
        const batchPerMinute = Math.max(1, Math.ceil(quota / 60));
        for (let i=0;i<batchPerMinute;i++) {
          // task unit format: we'll create simple visit tasks that must include url in config - but schedule doesn't hold URL
          // To allow generality, we expect the schedule config to include a "template" field: { "0": {"visits":100, "template": {url:..., selector:..., watchMs:..., referers: [...] } }, ... }
          const templ = cfg[hour] && cfg[hour].template ? cfg[hour].template : null;
          if (!templ) {
            // If no template, skip push (user must include template in schedule config)
            continue;
          }
          const task = {
            id: 'sched-'+s.id+'-'+Date.now()+'-'+Math.random().toString(36).substr(2,5),
            name: 'scheduled-'+s.id,
            url: templ.url,
            selector: templ.selector || '[data-video-test=\"true\"]',
            playStartDelayMs: templ.playStartDelayMs || 1000,
            watchMs: templ.watchMs || 15000,
            rounds: 1,
            concurrency: templ.concurrency || 1,
            referers: templ.referers || [],
            created_at: new Date().toISOString(),
            status: 'queued'
          };
          await rclient.rPush('taskQueue', JSON.stringify(task));
        }
      }
    } catch(e) {
      console.error('scheduler error', e);
    }
    await new Promise(r=>setTimeout(r, 60*1000)); // 1 min
  }
})();
NODEJS

########################################
# worker.js - 从 Redis taskQueue 弹出任务并执行（Playwright）
########################################
cat > worker.js <<'NODEJS'
/**
 * worker.js
 * - consume tasks from Redis (blPop)
 * - for each task, snapshot alive proxies and run `task.rounds` visits
 * - support per-task concurrency and 'unlimited' mode
 */

const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const { chromium, devices } = require('playwright');
const UserAgent = require('user-agents');
const pLimit = require('p-limit');
const redis = require('redis');
const { spawn } = require('child_process');

const APP_ROOT = process.cwd();
const DB = new sqlite3.Database(path.join(APP_ROOT, 'data.db'));
const rclient = redis.createClient({ url: process.env.REDIS_URL || `redis://127.0.0.1:${process.env.REDIS_PORT || ${REDIS_PORT}}` });
rclient.on('error', e => console.error('redis err', e));

(async ()=> {
  await rclient.connect();
  console.log('Worker connected to Redis');
  while (true) {
    try {
      const res = await rclient.blPop('taskQueue', 5);
      if (!res) { await new Promise(r=>setTimeout(r, 1000)); continue; }
      const payload = res.element || res[1] || res;
      const task = JSON.parse(payload);
      console.log('Worker got task', task.id);
      await executeTask(task);
    } catch (e) {
      console.error('worker loop err', e);
      await new Promise(r=>setTimeout(r, 3000));
    }
  }
})();

function saveLog(obj){
  const ts = new Date().toISOString();
  DB.run("INSERT INTO logs (task_id, ts, proxy, ua, device, action, detail, screenshot) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    [obj.taskId || null, ts, obj.proxy || null, obj.ua || null, obj.device || null, obj.action || null, obj.detail || null, obj.screenshot || null]);
}

function parseProxyRow(row){ if (!row) return null; return { ip: row.ip, port: row.port, protocol: row.protocol||'http', user: row.user||null, pass: row.pass||null }; }

async function getAliveProxies(){
  return new Promise(r => DB.all("SELECT * FROM proxies WHERE alive=1", (e,rows)=> r(rows || [])));
}

function isAdLink(href, text){
  if (!href && !text) return true;
  const low = (href||'').toLowerCase() + ' ' + (text||'').toLowerCase();
  const bad = ['ad','ads','banner','sponsor','affiliate','promo','clicktrack','doubleclick'];
  return bad.some(k => low.includes(k));
}

function curlTestProxy(proxy, timeoutMs=6000){
  return new Promise((resolve) => {
    const args = ['-sS','--max-time', String(Math.ceil(timeoutMs/1000)), '-I', 'https://httpbin.org/ip'];
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

async function tryVisit(proxyObj, task){
  const launchOptions = { headless: process.env.PLAYWRIGHT_HEADLESS !== 'false' };
  if (proxyObj && proxyObj.ip) {
    const proto = (proxyObj.protocol || 'http').toLowerCase();
    launchOptions.proxy = { server: \`\${proto}://\${proxyObj.ip}:\${proxyObj.port}\` };
    if (proxyObj.user) { launchOptions.proxy.username = proxyObj.user; launchOptions.proxy.password = proxyObj.pass; }
  }
  const browser = await chromium.launch(launchOptions);
  try {
    const deviceKeys = Object.keys(devices);
    const deviceKey = deviceKeys[Math.floor(Math.random()*deviceKeys.length)];
    const deviceDesc = devices[deviceKey] || {};
    const ua = new UserAgent().toString();
    const extraHeaders = {};
    if (task.referers && task.referers.length) extraHeaders['Referer'] = task.referers[Math.floor(Math.random()*task.referers.length)];
    const context = await browser.newContext({ ...deviceDesc, userAgent: ua, extraHTTPHeaders: extraHeaders });
    const page = await context.newPage();
    await page.goto(task.url, { waitUntil: 'domcontentloaded', timeout: 30000 }).catch(()=>null);
    const marker = await page.$(task.selector);
    if (!marker) {
      const ss = await page.screenshot({ path: path.join(APP_ROOT,'logs',\`nomarker-\${Date.now()}.png\`) }).catch(()=>null);
      saveLog({ taskId: task.id, proxy: proxyObj?`${proxyObj.ip}:${proxyObj.port}`:null, ua, device: deviceKey, action:'marker-missing', detail:`selector ${task.selector} missing`, screenshot: ss });
      await context.close(); await browser.close();
      throw new Error('marker missing');
    }
    await page.waitForTimeout(task.playStartDelayMs || 1000);
    const hasVideo = await page.$('video');
    if (hasVideo) {
      try {
        await page.evaluate(()=>{ const v=document.querySelector('video'); if (v){ v.muted=true; v.play(); }});
        const start = Date.now(); let playing=false;
        while (Date.now() - start < 8000) {
          playing = await page.evaluate(()=>{ const v=document.querySelector('video'); return v ? (!v.paused && v.readyState>=3) : false; });
          if (playing) break;
          await page.waitForTimeout(300);
        }
        if (!playing) {
          const pb = await page.$('button.play, .play, [aria-label="Play"], .play-button');
          if (pb) await pb.click().catch(()=>{});
        }
      } catch(e){}
    } else {
      await marker.click().catch(()=>{});
    }
    // click up to 2 non-ad links
    const links = await page.$$('a[href]');
    const candidateIdx = [];
    for (let i=0;i<links.length;i++){
      const href = await links[i].getAttribute('href').catch(()=>null);
      const text = await links[i].innerText().catch(()=>'');
      if (!isAdLink(href,text)) candidateIdx.push(i);
    }
    for (let k=0;k<Math.min(2, candidateIdx.length); k++){
      const i = candidateIdx[Math.floor(Math.random()*candidateIdx.length)];
      try {
        const [popup] = await Promise.all([
          context.waitForEvent('page').catch(()=>null),
          links[i].click().catch(()=>null)
        ]);
        if (popup) {
          await popup.waitForLoadState('domcontentloaded').catch(()=>{});
          await popup.waitForTimeout(Math.min(task.watchMs || 5000, 10000));
          await popup.screenshot({ path: path.join(APP_ROOT,'logs',\`popup-\${Date.now()}.png\`) }).catch(()=>null);
          await popup.close().catch(()=>null);
        } else {
          await page.waitForTimeout(1000 + Math.floor(Math.random()*2000));
        }
      } catch(e){}
    }
    // simulate watch with small mouse moves
    const endTime = Date.now() + (task.watchMs || 15000);
    while (Date.now() < endTime) {
      try {
        const vp = page.viewportSize() || { width:800, height:600 };
        const x = Math.floor(Math.random() * (vp.width || 800));
        const y = Math.floor(Math.random() * (vp.height || 600));
        await page.mouse.move(x,y,{steps:5});
      } catch(e){}
      await page.waitForTimeout(800 + Math.floor(Math.random()*1200));
    }
    const ss = await page.screenshot({ path: path.join(APP_ROOT,'logs',\`ss-\${Date.now()}.png\`) }).catch(()=>null);
    saveLog({ taskId: task.id, proxy: proxyObj?`${proxyObj.ip}:${proxyObj.port}`:null, ua, device: deviceKey, action:'played', detail:`watched ${task.watchMs}ms`, screenshot: ss });
    await context.close(); await browser.close();
    return true;
  } catch(err){
    try{ await browser.close(); }catch(e){}
    saveLog({ taskId: task.id, action:'error', detail: String(err) });
    throw err;
  }
}

async function executeTask(task){
  const proxies = await new Promise(r => DB.all("SELECT * FROM proxies WHERE alive=1", (e,rows)=> r(rows || [])));
  if (!proxies || proxies.length === 0) {
    console.log('No alive proxies for task', task.id);
    DB.run("UPDATE tasks SET status='failed' WHERE id=?", [task.id]);
    return;
  }
  const rounds = parseInt(task.rounds || 1, 10);
  const concurrencyParam = (task.concurrency === 'unlimited' ? Infinity : parseInt(task.concurrency || 1, 10));
  const limit = pLimit(concurrencyParam);
  let idx = 0;
  const jobFns = [];
  for (let i=0;i<rounds;i++){
    jobFns.push(limit(async ()=>{
      if (idx >= proxies.length) idx = 0;
      const p = proxies[idx++];
      const proxyObj = parseProxyRow(p);
      try { await tryVisit(proxyObj, task); } catch(e){}
    }));
  }
  await Promise.allSettled(jobFns);
  DB.run("UPDATE tasks SET status='done' WHERE id=?", [task.id]);
}

function parseProxyRow(row){ if (!row) return null; return { ip: row.ip, port: row.port, protocol: row.protocol||'http', user: row.user||null, pass: row.pass||null }; }
NODEJS

########################################
# 前端文件 public (index.html + main.js embedded + style.css)
########################################
cat > public/index.html <<'HTML'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Auto Traffic Scheduler - Panel</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<div id="login">
  <h2>登录</h2>
  <input id="username" placeholder="用户名"><br>
  <input id="password" placeholder="密码" type="password"><br>
  <button onclick="login()">登录</button>
  <p id="msg"></p>
</div>

<div id="panel" style="display:none;">
  <h2>控制面板</h2>
  <button onclick="logout()">退出</button>

  <section>
    <h3>设置（修改用户名/密码/JWT）</h3>
    新用户名：<input id="newUser"><br>
    新密码：<input id="newPass" type="password"><br>
    新 JWT Secret：<input id="newJwt"><br>
    <button onclick="updateCredentials()">保存设置 (Update PM2 env)</button>
    <p id="setmsg"></p>
  </section>

  <section>
    <h3>上传代理（TXT）</h3>
    <input type="file" id="proxyfile"><button onclick="uploadProxy()">上传</button>
    <div id="uploadRes"></div>
  </section>

  <section>
    <h3>代理检测与管理</h3>
    默认并发检测数：<input id="proxyConcurrency" value="${DEFAULT_PROXY_CHECK_CONCURRENCY}"><br>
    <button onclick="runProxyCheck()">开始检测（后台）</button>
    <button onclick="cleanBad()">清除无效 IP</button>
    <pre id="proxyList" style="height:120px;overflow:auto"></pre>
  </section>

  <section>
    <h3>创建任务（视频播放）</h3>
    名称：<input id="tname"><br>
    目标 URL：<input id="turl"><br>
    选择器：<input id="tselector" value='[data-video-test="true"]'><br>
    播放前延迟(ms)：<input id="tplaydelay" value="1000"><br>
    观看时长(ms)：<input id="twatch" value="15000"><br>
    访问轮数(rounds)：<input id="trounds" value="1"><br>
    并发(concurrency, 数字或 'unlimited')：<input id="tconcurrency" value="1"><br>
    Referer(逗号分隔)：<input id="treferers"><br>
    <button onclick="startTask()">开始任务</button>
    <div id="taskRes"></div>
  </section>

  <section>
    <h3>时间段计划（hourly quotas）</h3>
    说明：每个小时的配置需要包含 "visits" 与 "template"（template 包含 url/selector/watchMs/concurrency/referers）<br>
    示例 JSON （把下面粘入文本框）：
    <pre id="schedExample">{
  "0": {"visits": 50, "template": {"url":"https://example.com/video","selector":"[data-video-test=\"true\"]","watchMs":15000,"concurrency":1,"referers":["https://google.com"]}},
  "1": {"visits": 20, "template": {"url":"https://example.com/video","selector":"[data-video-test=\"true\"]","watchMs":15000,"concurrency":1}}
  // ... up to "23"
}</pre>
    计划名：<input id="sname" placeholder="My hourly plan"><br>
    时区（例如 Europe/Berlin）：<input id="stz" value="UTC"><br>
    配置（JSON）：<textarea id="sconfig" style="width:90%;height:200px">{}</textarea><br>
    <button onclick="createSchedule()">保存计划</button>
    <div id="schedRes"></div>
    <button onclick="loadSchedules()">刷新计划</button>
    <div id="schedList"></div>
  </section>

  <section>
    <h3>任务与日志</h3>
    <button onclick="loadTasks()">刷新任务</button>
    <div id="tasksArea"></div>
    <button onclick="loadLogs()">刷新日志</button>
    <pre id="logsArea" style="height:220px;overflow:auto"></pre>
  </section>
</div>

<script>
let token = localStorage.getItem('token') || '';
function headers(h={}){ if(token) h['Authorization']='Bearer '+token; return h; }

async function login(){
  const u=document.getElementById('username').value, p=document.getElementById('password').value;
  const r = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u,password:p}) });
  if (r.ok){ const j=await r.json(); token=j.token; localStorage.setItem('token', token); document.getElementById('login').style.display='none'; document.getElementById('panel').style.display='block'; loadProxies(); loadTasks(); loadSchedules(); loadLogs(); }
  else document.getElementById('msg').innerText='登录失败';
}

function logout(){ token=''; localStorage.removeItem('token'); document.getElementById('panel').style.display='none'; document.getElementById('login').style.display='block'; }

async function updateCredentials(){
  const newUser=document.getElementById('newUser').value;
  const newPass=document.getElementById('newPass').value;
  const newJwt=document.getElementById('newJwt').value;
  const r=await fetch('/api/updateCredentials', { method:'POST', headers: headers({'Content-Type':'application/json'}), body: JSON.stringify({ newUser, newPass, newJwt }) });
  const j=await r.json(); document.getElementById('setmsg').innerText = JSON.stringify(j);
  alert('已更新 PM2 env。请 SSH 到服务器并运行：pm2 restart auto-traffic-server --update-env');
}

async function uploadProxy(){ const f=document.getElementById('proxyfile').files[0]; if(!f) return alert('请选择文件'); const fd=new FormData(); fd.append('proxyfile', f); const r=await fetch('/api/uploadProxies', { method:'POST', headers: headers({}), body: fd }); const j=await r.json(); document.getElementById('uploadRes').innerText = 'Inserted: '+(j.inserted||0); loadProxies(); }

async function loadProxies(){ const r=await fetch('/api/proxies?limit=200', { headers: headers({}) }); const a=await r.json(); document.getElementById('proxyList').textContent = JSON.stringify(a, null, 2); }

async function runProxyCheck(){ const n = parseInt(document.getElementById('proxyConcurrency').value||'${DEFAULT_PROXY_CHECK_CONCURRENCY}',10); await fetch('/api/runProxyCheck', { method:'POST', headers: headers({'Content-Type':'application/json'}), body: JSON.stringify({ concurrency: n }) }); alert('Started proxy check (background)'); }

async function cleanBad(){ const r=await fetch('/api/cleanBad', { method:'POST', headers: headers({}) }); const j=await r.json(); alert('Deleted: '+(j.deleted||0)); loadProxies(); }

async function startTask(){
  const body = {
    name: document.getElementById('tname').value,
    url: document.getElementById('turl').value,
    selector: document.getElementById('tselector').value,
    playStartDelayMs: parseInt(document.getElementById('tplaydelay').value||1000),
    watchMs: parseInt(document.getElementById('twatch').value||15000),
    rounds: parseInt(document.getElementById('trounds').value||1),
    concurrency: document.getElementById('tconcurrency').value || 1,
    referers: document.getElementById('treferers').value ? document.getElementById('treferers').value.split(',').map(s=>s.trim()) : []
  };
  const r = await fetch('/api/startTask', { method:'POST', headers: headers({'Content-Type':'application/json'}), body: JSON.stringify(body) });
  const j = await r.json(); document.getElementById('taskRes').innerText = JSON.stringify(j); loadTasks();
}

async function createSchedule(){
  const name=document.getElementById('sname').value || 'hourly';
  const tz=document.getElementById('stz').value || 'UTC';
  let cfg;
  try { cfg = JSON.parse(document.getElementById('sconfig').value); } catch(e){ return alert('JSON parse error'); }
  const r = await fetch('/api/schedule', { method:'POST', headers: headers({'Content-Type':'application/json'}), body: JSON.stringify({ name, timezone: tz, config: cfg }) });
  const j = await r.json(); document.getElementById('schedRes').innerText = JSON.stringify(j); loadSchedules();
}

async function loadSchedules(){ const r = await fetch('/api/schedules', { headers: headers({}) }); const a = await r.json(); document.getElementById('schedList').innerText = JSON.stringify(a, null, 2); }

async function loadTasks(){ const r = await fetch('/api/tasks', { headers: headers({}) }); const a = await r.json(); let h='<table border=1 style="width:100%"><tr><th>id</th><th>name</th><th>url</th><th>rounds</th><th>concurrency</th><th>created</th><th>status</th></tr>'; for(const t of a){ h += \`<tr><td>\${t.id}</td><td>\${t.name}</td><td style="max-width:300px;overflow:hidden">\${t.url}</td><td>\${t.rounds}</td><td>\${t.concurrency}</td><td>\${t.created_at||''}</td><td>\${t.status||''}</td></tr>\`; } h += '</table>'; document.getElementById('tasksArea').innerHTML = h; }

async function loadLogs(){ const r = await fetch('/api/logs', { headers: headers({}) }); const a = await r.json(); document.getElementById('logsArea').textContent = JSON.stringify(a, null, 2); }

document.addEventListener('DOMContentLoaded', ()=>{ if(token){ document.getElementById('login').style.display='none'; document.getElementById('panel').style.display='block'; loadProxies(); loadTasks(); loadSchedules(); loadLogs(); }});
</script>
</body>
</html>
HTML

cat > public/style.css <<'CSS'
body{font-family:Arial, Helvetica, sans-serif; background:#f5f7fb; color:#222}
#login,#panel{width:1100px;margin:20px auto;padding:20px;background:#fff;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,0.08)}
input,textarea{padding:8px;margin:6px 0;width:90%}
button{padding:8px 12px;margin:6px;background:#007bff;color:#fff;border:none;border-radius:6px}
section{margin-top:12px;padding:10px;border:1px dashed #eee;border-radius:6px}
pre{white-space:pre-wrap}
CSS

########################################
# PM2 ecosystem and start services
########################################
cat > ecosystem.config.js <<'ECO'
module.exports = {
  apps: [
    {
      name: "auto-traffic-server",
      script: "server.js",
      env: {
        PORT: "${PORT}",
        REDIS_PORT: "${REDIS_PORT}",
        ADMIN_USER: "${ADMIN_USER_DEFAULT}",
        ADMIN_PASS_HASH: "${ADMIN_PASS_HASH}",
        JWT_SECRET: "${JWT_SECRET_DEFAULT}",
        DEFAULT_PROXY_CHECK_CONCURRENCY: "${DEFAULT_PROXY_CHECK_CONCURRENCY}"
      }
    },
    {
      name: "auto-traffic-scheduler",
      script: "scheduler.js",
      env: {
        REDIS_PORT: "${REDIS_PORT}"
      }
    },
    {
      name: "auto-traffic-worker",
      script: "worker.js",
      env: {
        REDIS_PORT: "${REDIS_PORT}",
        PLAYWRIGHT_HEADLESS: "${PLAYWRIGHT_HEADLESS}"
      }
    }
  ]
}
ECO

# fix ownership & perms
chown -R "$SUDO_USER":"$SUDO_USER" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

echo "启动 pm2 服务（server, scheduler, worker）..."
pm2 start ecosystem.config.js
pm2 save
pm2 startup | sed -n '1,200p'

echo "安装完成！"
echo "访问面板: http://<你的VPS-IP>:${PORT}"
echo "默认管理员: ${ADMIN_USER_DEFAULT} / ${ADMIN_PASS_DEFAULT}"
echo ""
echo "重要：请在面板或在服务器上立即更新 JWT_SECRET 与 管理员密码："
echo "  pm2 set auto-traffic-server:JWT_SECRET <newsecret>"
echo "  pm2 set auto-traffic-server:ADMIN_USER <username>"
echo "  pm2 set auto-traffic-server:ADMIN_PASS_HASH <bcrypt-hash>"
echo "然后运行： pm2 restart auto-traffic-server --update-env"
echo ""
echo "提示：要调整 Redis 地址，请设置 pm2 env REDIS_HOST / REDIS_PORT 并重启对应进程。"
echo "完成。"
