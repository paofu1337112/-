const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const os = require('os');
const WebSocket = require('ws');
const { AlertEngine, BackupManager, AuditLog, PerformanceMonitor, TaskScheduler, DataExporter, AdvancedSearch, WebhookManager, DeviceManager, SystemLogger, BulkOperationManager, AdvancedStatistics } = require('./enhancements');

const app = express();
const PORT = process.env.PORT || 3000;
// Vercel / Serverless 环境检测：文件系统只读，需挪到 /tmp（不持久），并跳过 setInterval
const IS_SERVERLESS = !!(process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY);
const DATA_DIR = process.env.DATA_DIR
  ? path.resolve(process.env.DATA_DIR)
  : (IS_SERVERLESS ? '/tmp/cardkey-data' : path.join(__dirname, 'data'));
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
const LOGS_FILE = path.join(DATA_DIR, 'logs.json');
const SERVER_START = Date.now();
const SERVER_VERSION = '2.6.0';

// ─── WebSocket 和缓存 ─────────────────────────────────────────────────────
const adminClients = new Set();
const allClients = new Set();
let realtimeSeq = 0;
const REALTIME_HISTORY_LIMIT = 200;
const realtimeHistory = [];

// ─── 文件写入串行化（防止并发写入丢失） ─────────────────────────────────────
const _writeQueue = new Map(); // filepath -> Promise chain tail
function serializedWrite(filepath, data) {
  const prev = _writeQueue.get(filepath) || Promise.resolve();
  const next = prev
    .catch(() => {})
    .then(() => new Promise((resolve) => {
      const tmp = filepath + '.tmp';
      fs.writeFile(tmp, data, (err) => {
        if (err) { console.error('[write]', filepath, err.message); return resolve({ ok: false, err }); }
        fs.rename(tmp, filepath, (err2) => {
          if (err2) { console.error('[rename]', filepath, err2.message); return resolve({ ok: false, err: err2 }); }
          resolve({ ok: true });
        });
      });
    }));
  _writeQueue.set(filepath, next);
  // Cleanup queue entries that are head of chain once done
  next.finally(() => { if (_writeQueue.get(filepath) === next) _writeQueue.delete(filepath); });
  return next;
}

class StatsCache {
  constructor(ttl = 30000) {
    this.data = null;
    this.timestamp = 0;
    this.ttl = ttl;
  }

  isValid() { return Date.now() - this.timestamp < this.ttl; }
  get() { return this.isValid() ? this.data : null; }
  set(data) { this.data = data; this.timestamp = Date.now(); }
  invalidate() { this.timestamp = 0; }
}

const statsCache = new StatsCache();
const appStatsCache = new StatsCache(60000);
let currentLogDate = new Date().toISOString().split('T')[0];

// 增强功能系统初始化
const alertEngine = new AlertEngine();
const backupManager = new BackupManager(DATA_DIR);
const auditLog = new AuditLog();
// 包装 record() 让每条审计同步 broadcast WS/SSE，方便多管理员实时看到
const _origAuditRecord = auditLog.record.bind(auditLog);
auditLog.record = function (action, details, userId = 'admin', ip = 'local') {
  const entry = _origAuditRecord(action, details, userId, ip);
  try { broadcastEvent('auditLog', entry, true); } catch {}
  return entry;
};
const performanceMonitor = new PerformanceMonitor();
const taskScheduler = new TaskScheduler();

// 新增功能系统
const advancedSearch = new AdvancedSearch();
const webhookManager = new WebhookManager();
const deviceManager = new DeviceManager();
const systemLogger = new SystemLogger();
const bulkOperationManager = new BulkOperationManager();

// 记录系统启动
systemLogger.log('SYSTEM', '系统启动');

function createRealtimeEnvelope(type, data) {
  return { type, timestamp: Date.now(), seq: ++realtimeSeq, data };
}

function rememberRealtimeEnvelope(envelope, isAdminOnly) {
  if (['liveMetrics', 'liveTraffic', 'pong', 'realtimeSnapshot'].includes(envelope.type)) return;
  realtimeHistory.unshift({
    ...envelope,
    scope: isAdminOnly ? 'admin' : 'all'
  });
  if (realtimeHistory.length > REALTIME_HISTORY_LIMIT) realtimeHistory.pop();
}

function deliverRealtimeEnvelope(client, envelope) {
  if (client.readyState !== WebSocket.OPEN) return false;
  client.send(JSON.stringify(envelope));
  return true;
}

function sendRealtimeEvent(client, type, data) {
  return deliverRealtimeEnvelope(client, createRealtimeEnvelope(type, data));
}

function broadcastEvent(type, data, isAdminOnly = false) {
  const clients = isAdminOnly ? adminClients : allClients;
  const envelope = createRealtimeEnvelope(type, data);
  rememberRealtimeEnvelope(envelope, isAdminOnly);
  clients.forEach(client => {
    if (!deliverRealtimeEnvelope(client, envelope)) {
      clients.delete(client);
      adminClients.delete(client);
      allClients.delete(client);
    }
  });
  // 同时推送到 SSE 订阅者
  pushSseEvent(type, envelope, isAdminOnly);
}

// ─── SSE 实时事件（WebSocket 不可用时的降级，Vercel 友好） ──────────────────
const _sseClients = new Set(); // { res, isAdmin, lastPing }
function pushSseEvent(type, envelope, isAdminOnly) {
  if (!_sseClients.size) return;
  const payload = `event: ${type}\ndata: ${JSON.stringify(envelope)}\n\n`;
  for (const c of Array.from(_sseClients)) {
    if (isAdminOnly && !c.isAdmin) continue;
    try {
      if (!c.res.writableEnded) c.res.write(payload);
      else _sseClients.delete(c);
    } catch { _sseClients.delete(c); }
  }
}

app.use(express.json({ limit: '10mb' }));
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ code: 400, message: '请求 JSON 格式无效' });
  }
  next(err);
});

// ─── 安全响应头 ────────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'no-referrer');
  // 请求追踪 ID：贯穿整个请求生命周期，写入响应头与日志，方便问题定位
  const reqId = crypto.randomBytes(6).toString('hex');
  req._reqId = reqId;
  res.setHeader('X-Request-ID', reqId);
  // Content-Security-Policy：允许 CDN 加载 Chart.js；禁止内联脚本（注意：index.html 用了 inline script，允许 unsafe-inline）
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data:; " +
    "connect-src 'self' ws: wss:; " +
    "font-src 'self' data:; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'"
  );
  next();
});

// ─── 登录接口独立频率限制（比全局更严格：每IP每分钟最多10次） ────────────────
const _loginRlMap = new Map();
const LOGIN_RL_MAX = 10;
const LOGIN_RL_WINDOW = 60000; // 1分钟
app.use('/admin/login', (req, res, next) => {
  if (req.method !== 'POST') return next();
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const now = Date.now();
  const bucket = _loginRlMap.get(ip) || [];
  const recent = bucket.filter(t => t > now - LOGIN_RL_WINDOW);
  if (recent.length >= LOGIN_RL_MAX) {
    return res.status(429).json({ code: 429, message: `登录请求过于频繁，请稍后再试`, retryAfter: Math.ceil((recent[0] + LOGIN_RL_WINDOW - now) / 1000) });
  }
  recent.push(now);
  _loginRlMap.set(ip, recent);
  // 定期清理（避免内存泄漏）
  if (_loginRlMap.size > 1000) {
    for (const [k, v] of _loginRlMap.entries()) {
      if (!v.some(t => t > now - LOGIN_RL_WINDOW)) _loginRlMap.delete(k);
    }
  }
  next();
});

// CORS（/admin/* 仅限本机来源/同源；/api/* 放开为 * 供客户端集成）
const _blockedAdminOriginLog = new Map();

function originHostname(origin) {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function requestHostname(req) {
  try {
    return new URL(`http://${req.headers.host || ''}`).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function isAllowedAdminOrigin(req, origin = req.headers.origin) {
  if (!origin) return true;
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;
  const host = originHostname(origin);
  if (['localhost', '127.0.0.1', '::1', '[::1]'].includes(host)) return true;
  return host && host === requestHostname(req);
}

function recordBlockedAdminOrigin(req, origin) {
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const key = `${ip}|${origin}|${req.path}`;
  const now = Date.now();
  const last = _blockedAdminOriginLog.get(key) || 0;
  if (now - last < 15000) return;
  _blockedAdminOriginLog.set(key, now);
  if (_blockedAdminOriginLog.size > 500) {
    for (const [k, t] of _blockedAdminOriginLog.entries()) {
      if (now - t > 60000) _blockedAdminOriginLog.delete(k);
    }
  }
  const safeOrigin = sanitizeTextField(origin, 180) || 'unknown';
  auditLog.record('admin_origin_blocked', { origin: safeOrigin, path: req.path }, 'security', ip);
  systemLogger.log('WARN', '已拦截异常管理端 Origin', { origin: safeOrigin, ip, path: req.path });
  broadcastEvent('securityEvent', { type: 'adminOriginBlocked', origin: safeOrigin, ip, path: req.path, timestamp: now }, true);
}

app.use((req, res, next) => {
  const origin = req.headers.origin || '';
  const isAdmin = req.path.startsWith('/admin/');
  const isLocalOrigin = isAllowedAdminOrigin(req, origin);

  if (isAdmin) {
    // 管理接口：只允许本机来源/同源（或无 Origin 的首次请求）
    if (isLocalOrigin) {
      res.setHeader('Access-Control-Allow-Origin', origin || '*');
      res.setHeader('Vary', 'Origin');
    } else {
      recordBlockedAdminOrigin(req, origin);
      return res.status(403).json({ code: 403, message: '管理端来源不被允许' });
    }
  } else {
    // /api/* 允许任意来源（但不携带 cookie，所以安全）
    res.setHeader('Access-Control-Allow-Origin', isLocalOrigin ? (origin || '*') : '*');
    if (!isLocalOrigin) res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,x-admin-token,Authorization,x-api-token');
  res.setHeader('Access-Control-Max-Age', '600');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ─── 响应时间跟踪中间件（实时性能监控） ────────────────────────────────────
const _rpsWindow = []; // 环形数组：近 60s 的请求时间戳
const _reqTimes = []; // 近 200 次响应时间
const _endpointStats = new Map(); // endpoint -> { count, totalMs, errors, maxMs }
app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    try {
      const durMs = Number(process.hrtime.bigint() - start) / 1e6;
      const now = Date.now();
      _rpsWindow.push(now);
      if (_rpsWindow.length > 5000) _rpsWindow.shift();
      _reqTimes.push(durMs);
      if (_reqTimes.length > 200) _reqTimes.shift();

      // 路径归一化（去除动态参数）以降低基数
      const ep = req.path.replace(/\/[A-Za-z0-9%_-]{20,}/g, '/:id').replace(/\/\d{4,}/g, '/:n');
      const rec = _endpointStats.get(ep) || { count: 0, totalMs: 0, errors: 0, maxMs: 0 };
      rec.count++;
      rec.totalMs += durMs;
      if (durMs > rec.maxMs) rec.maxMs = durMs;
      if (res.statusCode >= 400) rec.errors++;
      _endpointStats.set(ep, rec);

      // 交给性能监控器
      try { performanceMonitor.recordRequest(ep, Math.round(durMs), res.statusCode); } catch {}
    } catch {}
  });
  next();
});

function computeLiveMetrics() {
  const now = Date.now();
  while (_rpsWindow.length && _rpsWindow[0] < now - 60000) _rpsWindow.shift();
  const rps1m = _rpsWindow.length / 60;
  const rps5s = _rpsWindow.filter(t => t > now - 5000).length / 5;
  const avgRt = _reqTimes.length ? Math.round(_reqTimes.reduce((a, b) => a + b, 0) / _reqTimes.length) : 0;
  const sorted = [..._reqTimes].sort((a, b) => a - b);
  const p95 = sorted.length ? Math.round(sorted[Math.floor(sorted.length * 0.95)] || 0) : 0;
  const p50 = sorted.length ? Math.round(sorted[Math.floor(sorted.length * 0.5)] || 0) : 0;
  const mem = process.memoryUsage();
  const la = typeof os.loadavg === 'function' ? os.loadavg() : [0, 0, 0];
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  return {
    rps1m: Math.round(rps1m * 10) / 10,
    rps5s: Math.round(rps5s * 10) / 10,
    avgResponseMs: avgRt,
    p50ResponseMs: p50,
    p95ResponseMs: p95,
    heapUsedMB: Math.round(mem.heapUsed / 1048576),
    heapTotalMB: Math.round(mem.heapTotal / 1048576),
    rssMB: Math.round(mem.rss / 1048576),
    systemMemUsedPct: Math.round((1 - freeMem / totalMem) * 100),
    loadAvg: la.map(x => Math.round(x * 100) / 100),
    cpuCount: os.cpus().length,
    wsConnections: adminClients.size,
    uptime: Math.floor((Date.now() - SERVER_START) / 1000),
    timestamp: now
  };
}

app.use(express.static(path.join(__dirname, 'public')));
app.use('/test', express.static(path.join(__dirname, 'test-client')));

// ─── Init ─────────────────────────────────────────────────────────────────────
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Serverless 环境下，从打包目录里的 seed 数据恢复（每次冷启动）
if (IS_SERVERLESS) {
  const SEED_DIR = path.join(__dirname, 'data');
  ['config.json', 'keys.json', 'logs.json'].forEach(f => {
    const target = path.join(DATA_DIR, f);
    const source = path.join(SEED_DIR, f);
    if (!fs.existsSync(target) && fs.existsSync(source)) {
      try { fs.copyFileSync(source, target); } catch {}
    }
  });
}

const DEFAULT_CONFIG = {
  adminPassword: 'admin123',
  adminToken: null,
  globalRequireSign: false,
  rateLimitPerMin: 60,
  apps: [],
  blacklist: [],
  ipBlacklist: [],
  announcement: null,
  maintenanceMode: false,
  maintenanceMessage: '',
  webhooks: [],
  webhookDeliveries: [],
  apiTokens: [],
  // 自动补货：当未使用卡密少于阈值时自动生成
  autoStock: {
    enabled: false,
    threshold: 50,    // 未使用数低于此值触发
    refillTo: 200,    // 触发后补到此数量
    type: 'days',     // 生成的卡密类型
    value: 30,        // 天数或次数
    prefix: 'KM',
    group: 'auto'
  }
};

// ─── IP 规范化 ────────────────────────────────────────────────────────────────
function normalizeIp(ip) {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1').trim();
}

function sanitizeTextField(value, maxLen = 200) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[<>"'`]/g, '')
    .trim()
    .slice(0, maxLen);
}

function sanitizeKeyField(value, maxLen = 128) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[<>"'`\s]/g, '')
    .trim()
    .slice(0, maxLen);
}

function safeEqualString(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) {
    const dummy = Buffer.alloc(Math.max(aa.length, bb.length, 1));
    crypto.timingSafeEqual(dummy, dummy);
    return false;
  }
  return crypto.timingSafeEqual(aa, bb);
}

function hashApiToken(token) {
  return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function normalizeApiTokenRecord(t = {}) {
  const rawToken = t.token || '';
  const tokenHash = t.tokenHash || (rawToken ? hashApiToken(rawToken) : '');
  return {
    id: String(t.id || Date.now()),
    name: sanitizeTextField(t.name || 'API Token', 50) || 'API Token',
    tokenHash,
    tokenPrefix: t.tokenPrefix || String(rawToken).slice(0, 8),
    tokenSuffix: t.tokenSuffix || String(rawToken).slice(-4),
    scope: t.scope === 'write' ? 'write' : 'read',
    createdAt: t.createdAt || Date.now(),
    expiresAt: t.expiresAt || null,
    lastUsed: t.lastUsed || null,
    useCount: parseInt(t.useCount) || 0,
    enabled: t.enabled !== false
  };
}

function apiTokenMatches(record, token) {
  if (!record || !token) return false;
  if (record.tokenHash) return safeEqualString(record.tokenHash, hashApiToken(token));
  return safeEqualString(record.token, token);
}

// ─── Config Cache ───────────────────────────────────────────────────────────────
let _configCache = null;
let _configCacheTime = 0;
const CONFIG_CACHE_TTL = 5000;

function loadConfig() {
  const now = Date.now();
  if (_configCache && now - _configCacheTime < CONFIG_CACHE_TTL) return _configCache;
  if (!fs.existsSync(CONFIG_FILE)) {
    const cfg = { ...DEFAULT_CONFIG };
    cfg.apps = [{ appid: 'demo-app', name: '演示应用', secret: crypto.randomBytes(24).toString('hex'), enabled: true, requireSign: false, createdAt: Date.now() }];
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
    _configCache = cfg; _configCacheTime = now;
    return cfg;
  }
  try {
    const stored = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    const merged = { ...DEFAULT_CONFIG, ...stored };
    if (Array.isArray(merged.apps)) {
      merged.apps = merged.apps
        .filter(a => a && /^[a-zA-Z0-9_-]{2,32}$/.test(String(a.appid || '')))
        .map(a => ({
          ...a,
          appid: String(a.appid),
          name: sanitizeTextField(a.name || a.appid, 80) || String(a.appid),
          enabled: a.enabled !== false,
          requireSign: !!a.requireSign
        }));
    } else {
      merged.apps = [];
    }
    _configCache = merged; _configCacheTime = now;
    return merged;
  } catch { return { ...DEFAULT_CONFIG }; }
}

function saveConfig(cfg) {
  _configCache = cfg; _configCacheTime = Date.now(); // 立即更新内存缓存
  statsCache.invalidate();
  appStatsCache.invalidate();
  serializedWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2)).then((r) => {
    if (r.ok) {
      broadcastEvent('configUpdated', {
        appsCount: (cfg.apps || []).length,
        blacklistCount: (cfg.blacklist || []).length,
        ipBlacklistCount: (cfg.ipBlacklist || []).length,
        globalRequireSign: !!cfg.globalRequireSign,
        rateLimitPerMin: cfg.rateLimitPerMin,
        maintenanceMode: !!cfg.maintenanceMode
      }, true);
    }
  });
}

// ─── 密码哈希 (scrypt) ─────────────────────────────────────────────────────
let _webhookPersistTimer = null;
function persistWebhookState(state = webhookManager.getState()) {
  if (_webhookPersistTimer) clearTimeout(_webhookPersistTimer);
  _webhookPersistTimer = setTimeout(() => {
    const cfg = loadConfig();
    cfg.webhooks = state.webhooks || [];
    cfg.webhookDeliveries = state.deliveries || [];
    _configCache = cfg;
    _configCacheTime = Date.now();
    serializedWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  }, 150);
}

function hydrateWebhookState() {
  const cfg = loadConfig();
  webhookManager.loadState({
    webhooks: cfg.webhooks || [],
    deliveries: cfg.webhookDeliveries || []
  });
  webhookManager.onChange = persistWebhookState;
}

hydrateWebhookState();

function hashPassword(password) {
  return new Promise((resolve, reject) => {
    const salt = crypto.randomBytes(16).toString('hex');
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) reject(err);
      else resolve(`scrypt:${salt}:${key.toString('hex')}`);
    });
  });
}

function verifyPassword(password, stored) {
  if (!stored) return Promise.resolve(false);
  if (!stored.startsWith('scrypt:')) {
    return Promise.resolve(safeEqualString(password, stored));
  }
  const parts = stored.split(':');
  if (parts.length !== 3) return Promise.resolve(false);
  const [, salt, storedKey] = parts;
  return new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (err, key) => {
      if (err) return reject(err);
      try {
        resolve(crypto.timingSafeEqual(Buffer.from(storedKey, 'hex'), key));
      } catch { resolve(false); }
    });
  });
}

function saveKeys(keys) {
  // 写入前就把最新数据塞进缓存，保证同一事件循环内的 loadKeys 读到新值
  _keysCache = { mtime: Date.now(), data: keys };
  serializedWrite(KEYS_FILE, JSON.stringify(keys, null, 2)).then((r) => {
    if (!r.ok) return;
    statsCache.invalidate();
    appStatsCache.invalidate();
    try {
      const stat = fs.statSync(KEYS_FILE);
      _keysCache = { mtime: stat.mtimeMs, data: keys };
    } catch {}
    broadcastEvent('keysUpdated', { count: keys.length }, true);
    const freshStats = computeKeyStats(keys);
    statsCache.set(freshStats);
    broadcastEvent('statsUpdated', freshStats, true);
  });
}

// loadKeys() 带 mtime 缓存，高并发下避免重复解析大 JSON
let _keysCache = { mtime: 0, data: null };
function loadKeys() {
  if (!fs.existsSync(KEYS_FILE)) { fs.writeFileSync(KEYS_FILE, '[]'); _keysCache = { mtime: Date.now(), data: [] }; return []; }
  try {
    const stat = fs.statSync(KEYS_FILE);
    const m = stat.mtimeMs;
    if (_keysCache.data && _keysCache.mtime === m) return _keysCache.data;
    const data = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
    _keysCache = { mtime: m, data };
    return data;
  } catch { return _keysCache.data || []; }
}
function invalidateKeysCache() { _keysCache = { mtime: 0, data: null }; }

function computeKeyStats(keys = loadKeys()) {
  const now = Date.now();
  let unused = 0, active = 0, expired = 0;
  keys.forEach(k => {
    const s = keyStatus(k);
    if (s === 'unused') unused++;
    else if (s === 'expired') expired++;
    else active++;
  });
  const todayRequests = reqLogs.filter(l => l.t > now - 86400000).length;
  const yesterdayRequests = reqLogs.filter(l => l.t > now - 172800000 && l.t <= now - 86400000).length;
  const todayOk = reqLogs.filter(l => l.t > now - 86400000 && l.status === 200).length;
  const todayErr = reqLogs.filter(l => l.t > now - 86400000 && l.status >= 400).length;
  const expiringSoon = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime > now && k.expireTime <= now + 7 * 86400000).length;
  return {
    total: keys.length,
    unused,
    active,
    expired,
    expiringSoon,
    todayRequests,
    yesterdayRequests,
    todayOk,
    todayErr,
    onlineCount: countOnlineClients()
  };
}

// ─── Request Logs ─────────────────────────────────────────────────────────────
let reqLogs = [];
try { if (fs.existsSync(LOGS_FILE)) reqLogs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8')); } catch {}

let _logWriteScheduled = false;
function addLog(entry) {
  reqLogs.unshift(entry);
  if (reqLogs.length > 1000) reqLogs = reqLogs.slice(0, 1000);
  appStatsCache.invalidate(); // invalidate app stats on new log

  // 广播立即；文件批量写入（合并 200ms 内的多条日志）
  broadcastEvent('newLog', entry, true);
  if (!_logWriteScheduled) {
    _logWriteScheduled = true;
    setTimeout(() => {
      _logWriteScheduled = false;
      serializedWrite(LOGS_FILE, JSON.stringify(reqLogs)).then(() => archiveLogs());
    }, 200);
  }
}

// 日志归档：通过 serializedWrite 排队在日志写入之后，避免竞争
function archiveLogs() {
  const today = new Date().toISOString().split('T')[0];
  if (currentLogDate === today) return;
  const dateToArchive = currentLogDate;
  currentLogDate = today; // 立即更新防止重入
  const oldPath = path.join(DATA_DIR, `logs-${dateToArchive}.json`);
  // 先把当前内存内"归档日期之前"的日志拷贝到归档文件，再清空当日 LOGS_FILE
  const prev = _writeQueue.get(LOGS_FILE) || Promise.resolve();
  const task = prev.catch(() => {}).then(() => new Promise(resolve => {
    // 从内存中抽出归档日期之前的条目
    const cutoff = new Date(today + 'T00:00:00').getTime();
    const archived = reqLogs.filter(l => l.t < cutoff);
    if (!archived.length) return resolve();
    // 追加/合并到归档文件（若存在）
    let existing = [];
    try { if (fs.existsSync(oldPath)) existing = JSON.parse(fs.readFileSync(oldPath, 'utf8')); } catch {}
    const merged = existing.concat(archived);
    fs.writeFile(oldPath, JSON.stringify(merged), () => resolve());
  }));
  _writeQueue.set(LOGS_FILE, task);
  task.finally(() => { if (_writeQueue.get(LOGS_FILE) === task) _writeQueue.delete(LOGS_FILE); });
}

// ─── Rate Limiter（IP 维度 + 应用维度双层） ──────────────────────────────
const rlMap = new Map();      // ip -> { count, reset }
const rlAppMap = new Map();   // appid -> { count, reset }
const RL_MAX_KEYS = 50000;    // 防止恶意 IP 池撑爆内存

function rateLimiter(req, res, next) {
  const cfg = loadConfig();
  const limit = cfg.rateLimitPerMin || 60;
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const now = Date.now();
  // 内存上限保护：超过 RL_MAX_KEYS 时清掉 1/4 最早的
  if (rlMap.size > RL_MAX_KEYS) {
    let i = 0; for (const k of rlMap.keys()) { rlMap.delete(k); if (++i > RL_MAX_KEYS / 4) break; }
  }
  let e = rlMap.get(ip);
  if (!e || e.reset < now) e = { count: 0, reset: now + 60000 };
  e.count++;
  rlMap.set(ip, e);
  if (e.count > limit) {
    addLog({ t: now, ip, m: req.method, p: req.path, status: 429, msg: '速率限制(IP)', key: req.query.key || req.body?.key || '', rid: req._reqId });
    return res.status(429).json({ code: 429, message: '请求过于频繁，请稍后再试', valid: false });
  }

  // 应用维度限流（如果应用配置了 rateLimitPerMin）
  const appid = req.query.appid || req.body?._appid || req.body?.appid || '';
  if (appid) {
    const appObj = (cfg.apps || []).find(a => a.appid === appid);
    const appLimit = appObj && appObj.rateLimitPerMin > 0 ? parseInt(appObj.rateLimitPerMin) : 0;
    if (appLimit > 0) {
      let ae = rlAppMap.get(appid);
      if (!ae || ae.reset < now) ae = { count: 0, reset: now + 60000 };
      ae.count++;
      rlAppMap.set(appid, ae);
      if (ae.count > appLimit) {
        addLog({ t: now, ip, m: req.method, p: req.path, appid, status: 429, msg: '速率限制(应用)', key: req.query.key || req.body?.key || '', rid: req._reqId });
        return res.status(429).json({ code: 429, message: '该应用已达每分钟请求上限', valid: false });
      }
    }
  }
  next();
}
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of rlMap) if (v.reset < n) rlMap.delete(k);
  for (const [k, v] of rlAppMap) if (v.reset < n) rlAppMap.delete(k);
}, 60000);

// ─── Nonce Store (anti-replay) ────────────────────────────────────────────────
const nonceMap = new Map();
function useNonce(nonce) {
  if (nonceMap.has(nonce)) return false;
  nonceMap.set(nonce, Date.now() + 600000);
  return true;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of nonceMap) if (v < n) nonceMap.delete(k); }, 300000);

// ─── Utilities ────────────────────────────────────────────────────────────────
function genKey(prefix = 'KM') {
  const c = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const s = () => Array.from({ length: 4 }, () => c[Math.floor(Math.random() * c.length)]).join('');
  return `${prefix}-${s()}-${s()}-${s()}-${s()}`;
}

function keyStatus(k) {
  if (k.status === 'unused') return 'unused';
  if (k.type === 'days' && k.expireTime && k.expireTime < Date.now()) return 'expired';
  if (k.type === 'times' && k.usedCount >= k.value) return 'expired';
  return 'active';
}

function verifyHMAC(secret, appid, key, timestamp, nonce, sign) {
  const now = Math.floor(Date.now() / 1000);
  const ts = parseInt(timestamp);
  const nonceValue = String(nonce || '');
  const signValue = String(sign || '').toLowerCase();
  if (!nonceValue || nonceValue.length > 128) return { ok: false, reason: 'nonce invalid' };
  if (!/^[a-f0-9]{64}$/.test(signValue)) return { ok: false, reason: 'signature invalid' };
  if (isNaN(ts) || Math.abs(now - ts) > 300) return { ok: false, reason: 'timestamp expired' };
  const payloadValue = `${appid}:${key}:${timestamp}:${nonceValue}`;
  const expectedValue = crypto.createHmac('sha256', secret).update(payloadValue).digest('hex');
  if (!safeEqualString(expectedValue, signValue)) return { ok: false, reason: 'signature invalid' };
  if (!useNonce(nonceValue)) return { ok: false, reason: 'nonce already used' };
  return { ok: true };
}

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const TOKEN_TTL_MS = 24 * 3600 * 1000; // 24 hours

// 多会话表：token -> { token, createdAt, expiresAt, ip, userAgent, lastActive }
const _sessions = new Map();

function createSession(ip, userAgent) {
  const token = crypto.randomBytes(32).toString('hex');
  const sess = {
    token,
    createdAt: Date.now(),
    expiresAt: Date.now() + TOKEN_TTL_MS,
    ip: ip || 'unknown',
    userAgent: (userAgent || '').slice(0, 200),
    lastActive: Date.now()
  };
  _sessions.set(token, sess);
  return sess;
}

function revokeSession(token) {
  return _sessions.delete(token);
}

function cleanupSessions() {
  const now = Date.now();
  for (const [t, s] of _sessions.entries()) if (s.expiresAt < now) _sessions.delete(t);
}

function getSession(token) {
  if (!token) return null;
  const s = _sessions.get(token);
  if (!s) return null;
  if (s.expiresAt < Date.now()) { _sessions.delete(token); return null; }
  return s;
}

function adminAuth(req, res, next) {
  const token = req.headers['x-admin-token'];
  // 优先走会话表（支持多端同时登录）
  const sess = getSession(token);
  if (sess) {
    sess.lastActive = Date.now();
    req._session = sess;
    return next();
  }
  // 向后兼容：config.adminToken（老数据）
  const cfg = loadConfig();
  if (token && cfg.adminToken && safeEqualString(token, cfg.adminToken)) {
    if (cfg.adminTokenExpiry && Date.now() > cfg.adminTokenExpiry) {
      cfg.adminToken = null;
      cfg.adminTokenExpiry = null;
      saveConfig(cfg);
      return res.status(401).json({ code: 401, message: '会话已过期，请重新登录' });
    }
    return next();
  }
  return res.status(401).json({ code: 401, message: '未授权，请重新登录' });
}

function clientAuth(req, res, next) {
  const cfg = loadConfig();
  const key = req.query.key || req.body?.key || '';
  const appid = req.query.appid || req.query._appid || req.body?._appid || req.body?.appid || '';
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');

  // IP blacklist
  if (cfg.ipBlacklist && cfg.ipBlacklist.includes(ip)) {
    addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 403, msg: 'IP已被封禁' });
    return res.status(403).json({ code: 403, message: '该 IP 已被封禁', valid: false, success: false });
  }

  // Key blacklist
  if (cfg.blacklist && key && cfg.blacklist.includes(key)) {
    addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 403, msg: '卡密已被封禁' });
    return res.status(403).json({ code: 403, message: '该卡密已被封禁', valid: false, success: false });
  }

  if (cfg.maintenanceMode) {
    const msg = cfg.maintenanceMessage || 'System is under maintenance';
    addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 503, msg: 'maintenance' });
    return res.status(503).json({ code: 503, message: msg, valid: false, success: false, maintenance: true });
  }

  const appObj = cfg.apps.find(a => a.appid === appid);
  if (appObj && !appObj.enabled) {
    addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 403, msg: 'app disabled' });
    return res.status(403).json({ code: 403, message: '搴旂敤宸茶绂佺敤', valid: false, success: false });
  }
  const needSign = (appObj ? appObj.requireSign : false) || cfg.globalRequireSign;

  if (needSign) {
    if (!appObj) {
      addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 401, msg: 'AppID不存在' });
      return res.status(401).json({ code: 401, message: 'AppID未注册', valid: false, success: false });
    }
    if (!appObj.enabled) {
      addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 403, msg: '应用已禁用' });
      return res.status(403).json({ code: 403, message: '应用已被禁用', valid: false, success: false });
    }
    const ts = req.query._timestamp || req.body?._timestamp;
    const nc = req.query._nonce || req.body?._nonce;
    const sg = req.query._sign || req.body?._sign;
    if (!ts || !nc || !sg) {
      addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 401, msg: '缺少签名参数' });
      return res.status(401).json({ code: 401, message: '此应用需要HMAC签名，缺少参数 _timestamp/_nonce/_sign', valid: false, success: false });
    }
    const r = verifyHMAC(appObj.secret, appid, key, ts, nc, sg);
    if (!r.ok) {
      addLog({ t: Date.now(), ip, m: req.method, p: req.path, appid, key, status: 401, msg: r.reason });
      return res.status(401).json({ code: 401, message: r.reason, valid: false, success: false });
    }
  }

  req._appObj = appObj;
  req._clientIp = ip;
  req._clientKey = key;
  req._clientAppid = appid;
  next();
}

function logAfter(req, status, msg) {
  addLog({ t: Date.now(), ip: req._clientIp || 'unknown', m: req.method, p: req.path, appid: req._clientAppid || '', key: req._clientKey || '', status, msg, rid: req._reqId });
}

// ─── 登录锁定机制 ──────────────────────────────────────────────────────────────
const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 10 * 60 * 1000; // 10分钟
const loginAttempts = new Map(); // ip -> { count, firstAttempt, lockedUntil }

function getLoginState(ip) {
  return loginAttempts.get(ip) || { count: 0, firstAttempt: 0, lockedUntil: 0 };
}

function recordLoginFail(ip) {
  const now = Date.now();
  const state = getLoginState(ip);
  // 如果距离首次失败超过10分钟，重置计数
  if (now - state.firstAttempt > LOGIN_LOCKOUT_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now, lockedUntil: 0 });
    return { locked: false, remaining: LOGIN_MAX_ATTEMPTS - 1 };
  }
  state.count++;
  if (state.count >= LOGIN_MAX_ATTEMPTS) {
    state.lockedUntil = now + LOGIN_LOCKOUT_MS;
    systemLogger.log('WARN', `登录锁定: IP ${ip} 连续失败 ${state.count} 次`);
    broadcastEvent('loginLocked', { ip, lockedUntil: state.lockedUntil }, true);
  }
  loginAttempts.set(ip, state);
  return { locked: state.count >= LOGIN_MAX_ATTEMPTS, remaining: Math.max(0, LOGIN_MAX_ATTEMPTS - state.count), lockedUntil: state.lockedUntil };
}

function checkLoginLocked(ip) {
  const state = getLoginState(ip);
  if (state.lockedUntil && Date.now() < state.lockedUntil) {
    return { locked: true, remainingMs: state.lockedUntil - Date.now() };
  }
  return { locked: false };
}

// 定期清理过期的锁定记录（每5分钟）
setInterval(() => {
  const now = Date.now();
  for (const [ip, state] of loginAttempts.entries()) {
    if (now - state.firstAttempt > LOGIN_LOCKOUT_MS * 2) loginAttempts.delete(ip);
  }
}, 5 * 60 * 1000);

// ─── Admin: Auth ──────────────────────────────────────────────────────────────
app.post('/admin/login', async (req, res) => {
  const { password } = req.body || {};
  if (!password || typeof password !== 'string') return res.status(400).json({ code: 400, message: '请输入密码' });
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');

  // 检查是否被锁定
  const lockStatus = checkLoginLocked(ip);
  if (lockStatus.locked) {
    const mins = Math.ceil(lockStatus.remainingMs / 60000);
    return res.status(429).json({ code: 429, message: `账号已锁定，请 ${mins} 分钟后重试`, lockedFor: lockStatus.remainingMs });
  }

  const cfg = loadConfig();
  let passwordOk = false;
  try {
    passwordOk = await verifyPassword(password, cfg.adminPassword);
  } catch (e) {
    console.error('[Login] verifyPassword error:', e.message);
    return res.status(500).json({ code: 500, message: '服务器内部错误' });
  }

  if (!passwordOk) {
    const result = recordLoginFail(ip);
    auditLog.record('login_fail', { reason: '密码错误', attempts: LOGIN_MAX_ATTEMPTS - result.remaining }, 'admin', ip);
    if (result.locked) {
      broadcastEvent('loginLocked', { ip }, true);
      return res.status(429).json({ code: 429, message: `密码错误次数过多，账号已锁定10分钟`, lockedFor: LOGIN_LOCKOUT_MS });
    }
    return res.status(401).json({ code: 401, message: `密码错误，还可尝试 ${result.remaining} 次` });
  }

  // 登录成功，清除失败记录
  loginAttempts.delete(ip);

  // 自动将明文密码升级为 scrypt 哈希（首次使用时）
  if (!cfg.adminPassword.startsWith('scrypt:')) {
    try {
      cfg.adminPassword = await hashPassword(password);
      saveConfig(cfg);
      console.log('[Login] 密码已自动升级为 scrypt 哈希');
    } catch (e) {
      console.error('[Login] 密码升级失败:', e.message);
    }
  }

  // 多会话：创建一个新会话（不再覆盖 config.adminToken，允许多端同时登录）
  const sess = createSession(ip, req.headers['user-agent']);

  // 登录异地检测：对比最近 10 次成功登录的 IP，如果出现新 IP 就报警
  try {
    const recentLogins = auditLog.getLogs({ action: 'login', limit: 10 });
    const knownIps = new Set(recentLogins.map(l => l.ip).filter(Boolean));
    if (knownIps.size > 0 && !knownIps.has(ip)) {
      const newLocationAlert = {
        id: 'login_new_ip_' + Date.now(),
        name: '异地登录',
        severity: 'warning',
        description: `检测到来自新 IP 的登录：${ip}（已知 IP：${Array.from(knownIps).slice(0, 3).join(', ')}）`,
        timestamp: Date.now(),
        ip,
        knownIps: Array.from(knownIps).slice(0, 5)
      };
      systemLogger.log('WARN', `异地登录：${ip}`, { knownIps: Array.from(knownIps) });
      broadcastEvent('loginNewLocation', newLocationAlert, true);
    }
  } catch {}

  auditLog.record('login', { success: true, token: sess.token.slice(0, 8) + '...' }, 'admin', ip);
  systemLogger.log('INFO', `管理员登录成功: ${ip}`);
  broadcastEvent('sessionCreated', { ip, createdAt: sess.createdAt, totalSessions: _sessions.size }, true);
  res.json({ code: 200, message: '登录成功', token: sess.token, expiresAt: sess.expiresAt });
});

// 查询当前 IP 锁定状态（前端轮询）
app.get('/admin/login-status', (req, res) => {
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const lockStatus = checkLoginLocked(ip);
  const state = getLoginState(ip);
  res.json({ locked: lockStatus.locked, remainingMs: lockStatus.remainingMs || 0, attempts: state.count, maxAttempts: LOGIN_MAX_ATTEMPTS });
});

app.post('/admin/logout', adminAuth, (req, res) => {
  const token = req.headers['x-admin-token'];
  if (token && _sessions.has(token)) {
    _sessions.delete(token);
  } else {
    // 兼容：清旧的 config.adminToken
    const cfg = loadConfig();
    cfg.adminToken = null;
    cfg.adminTokenExpiry = null;
    saveConfig(cfg);
  }
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('logout', {}, 'admin', ip);
  broadcastEvent('sessionRevoked', { totalSessions: _sessions.size }, true);
  res.json({ code: 200, message: '已退出' });
});

// 令牌续期（无需重新登录，延长 TTL）
app.post('/admin/refresh-token', adminAuth, (req, res) => {
  const token = req.headers['x-admin-token'];
  const sess = _sessions.get(token);
  if (sess) {
    sess.expiresAt = Date.now() + TOKEN_TTL_MS;
    sess.lastActive = Date.now();
    return res.json({ code: 200, message: '令牌已续期', expiresAt: sess.expiresAt });
  }
  const cfg = loadConfig();
  cfg.adminTokenExpiry = Date.now() + TOKEN_TTL_MS;
  saveConfig(cfg);
  res.json({ code: 200, message: '令牌已续期', expiresAt: cfg.adminTokenExpiry });
});

// ─── 多会话管理 ──────────────────────────────────────────────────────────────
app.get('/admin/sessions', adminAuth, (req, res) => {
  const currentToken = req.headers['x-admin-token'];
  const list = Array.from(_sessions.values()).map(s => ({
    id: s.token.slice(0, 12),
    createdAt: s.createdAt,
    expiresAt: s.expiresAt,
    lastActive: s.lastActive,
    ip: s.ip,
    userAgent: s.userAgent,
    current: s.token === currentToken
  }));
  list.sort((a, b) => b.lastActive - a.lastActive);
  res.json({ code: 200, data: list, total: list.length });
});

// 撤销某个会话（通过 session id 前缀）
app.delete('/admin/sessions/:id', adminAuth, (req, res) => {
  const id = req.params.id;
  if (!/^[a-f0-9]{12,}$/i.test(id)) return res.status(400).json({ code: 400, message: '会话 ID 至少 12 位十六进制' });
  const matches = [];
  for (const s of _sessions.values()) if (s.token.startsWith(id)) matches.push(s);
  if (!matches.length) return res.status(404).json({ code: 404, message: '会话不存在' });
  if (matches.length > 1) return res.status(409).json({ code: 409, message: 'ID 前缀冲突，请提供更多位数' });
  _sessions.delete(matches[0].token);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('session_revoke', { sessionId: id }, 'admin', ip);
  broadcastEvent('sessionRevoked', { totalSessions: _sessions.size }, true);
  res.json({ code: 200, message: '会话已撤销' });
});

// 撤销除当前会话外的所有其它会话
app.post('/admin/sessions/revoke-others', adminAuth, (req, res) => {
  const currentToken = req.headers['x-admin-token'];
  let revoked = 0;
  for (const t of Array.from(_sessions.keys())) {
    if (t !== currentToken) { _sessions.delete(t); revoked++; }
  }
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('session_revoke_others', { revoked }, 'admin', ip);
  broadcastEvent('sessionRevoked', { totalSessions: _sessions.size }, true);
  res.json({ code: 200, message: `已撤销其它 ${revoked} 个会话`, revoked });
});

// ─── API 令牌（供程序化访问，作用域 read/write） ──────────────────────────
// 持久化到 config.apiTokens 中
function loadApiTokens() {
  const cfg = loadConfig();
  return Array.isArray(cfg.apiTokens) ? cfg.apiTokens.map(normalizeApiTokenRecord) : [];
}
function saveApiTokens(tokens, options = {}) {
  const cfg = loadConfig();
  cfg.apiTokens = tokens.map(normalizeApiTokenRecord);
  _configCache = cfg;
  _configCacheTime = Date.now();
  serializedWrite(CONFIG_FILE, JSON.stringify(cfg, null, 2)).then((r) => {
    if (r.ok && options.realtime !== false) {
      broadcastEvent('apiTokensUpdated', { count: cfg.apiTokens.length }, true);
    }
  });
}
function apiTokenAuth(requiredScope) {
  return function (req, res, next) {
    // 先支持管理员 session
    const sessToken = req.headers['x-admin-token'];
    if (getSession(sessToken)) return next();
    const cfg = loadConfig();
    if (sessToken && cfg.adminToken && safeEqualString(sessToken, cfg.adminToken)) return next();
    // 再支持 API 令牌（Authorization: Bearer xxx 或 x-api-token）
    const bearer = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '').trim();
    const apiTok = bearer || req.headers['x-api-token'] || '';
    if (!apiTok) return res.status(401).json({ code: 401, message: '需要有效令牌' });
    const tokens = loadApiTokens();
    const tok = tokens.find(t => apiTokenMatches(t, apiTok) && t.enabled !== false);
    if (!tok) return res.status(401).json({ code: 401, message: '令牌无效或已撤销' });
    if (tok.expiresAt && tok.expiresAt < Date.now()) return res.status(401).json({ code: 401, message: '令牌已过期' });
    if (requiredScope === 'write' && tok.scope !== 'write') return res.status(403).json({ code: 403, message: '令牌无写权限' });
    // 异步更新 lastUsed（避免每次请求同步写盘）
    tok.lastUsed = Date.now();
    tok.useCount = (tok.useCount || 0) + 1;
    if ((tok.useCount % 20) === 1) saveApiTokens(tokens, { realtime: false }); // 每 20 次落盘一次
    req._apiToken = tok;
    next();
  };
}

app.get('/admin/api-tokens', adminAuth, (req, res) => {
  const tokens = loadApiTokens().map(t => ({
    id: t.id,
    name: t.name,
    scope: t.scope,
    createdAt: t.createdAt,
    expiresAt: t.expiresAt,
    lastUsed: t.lastUsed,
    useCount: t.useCount,
    enabled: t.enabled,
    token: `${t.tokenPrefix || 'kat_****'}…${t.tokenSuffix || '****'}`
  }));
  res.json({ code: 200, data: tokens });
});

app.post('/admin/api-tokens', adminAuth, (req, res) => {
  const { name, scope = 'read', expiresInDays } = req.body || {};
  if (!name || typeof name !== 'string' || name.length > 50) return res.status(400).json({ code: 400, message: '名称必填且不超过 50 字' });
  if (!['read', 'write'].includes(scope)) return res.status(400).json({ code: 400, message: '作用域必须是 read 或 write' });
  const exp = parseInt(expiresInDays);
  const tokens = loadApiTokens();
  const token = 'kat_' + crypto.randomBytes(24).toString('hex');
  const entry = {
    id: Date.now().toString(),
    name: sanitizeTextField(name, 50),
    tokenHash: hashApiToken(token),
    tokenPrefix: token.slice(0, 8),
    tokenSuffix: token.slice(-4),
    scope,
    createdAt: Date.now(),
    expiresAt: (exp && exp > 0) ? Date.now() + exp * 86400000 : null,
    lastUsed: null,
    useCount: 0,
    enabled: true
  };
  tokens.push(entry);
  saveApiTokens(tokens);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('api_token_create', { name, scope }, 'admin', ip);
  // 返回明文令牌仅此一次
  res.json({
    code: 200,
    message: '令牌已创建（请妥善保存，密文将不再显示）',
    data: {
      id: entry.id,
      name: entry.name,
      scope: entry.scope,
      createdAt: entry.createdAt,
      expiresAt: entry.expiresAt,
      enabled: entry.enabled,
      token
    }
  });
});

app.patch('/admin/api-tokens/:id', adminAuth, (req, res) => {
  const tokens = loadApiTokens();
  const idx = tokens.findIndex(t => t.id === req.params.id);
  if (idx === -1) return res.status(404).json({ code: 404, message: '令牌不存在' });
  const { enabled, name } = req.body || {};
  if (enabled !== undefined) tokens[idx].enabled = !!enabled;
  if (name && typeof name === 'string' && name.length <= 50) tokens[idx].name = sanitizeTextField(name, 50);
  saveApiTokens(tokens);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('api_token_update', { id: req.params.id, enabled }, 'admin', ip);
  res.json({ code: 200, message: '已更新' });
});

app.delete('/admin/api-tokens/:id', adminAuth, (req, res) => {
  const tokens = loadApiTokens();
  const before = tokens.length;
  const kept = tokens.filter(t => t.id !== req.params.id);
  if (kept.length === before) return res.status(404).json({ code: 404, message: '令牌不存在' });
  saveApiTokens(kept);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('api_token_delete', { id: req.params.id }, 'admin', ip);
  res.json({ code: 200, message: '令牌已撤销' });
});

// 用 API 令牌调用的只读数据（示例端点，方便外部面板/监控脚本）
app.get('/api/stats', apiTokenAuth('read'), (req, res) => {
  const keys = loadKeys();
  const now = Date.now();
  let unused = 0, active = 0, expired = 0;
  keys.forEach(k => { const s = keyStatus(k); if (s === 'unused') unused++; else if (s === 'expired') expired++; else active++; });
  res.json({ code: 200, data: { total: keys.length, unused, active, expired, onlineClients: countOnlineClients(), serverTime: now } });
});

app.post('/admin/change-password', adminAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  const cfg = loadConfig();
  let valid = false;
  try { valid = await verifyPassword(oldPassword, cfg.adminPassword); } catch {}
  if (!valid) return res.status(400).json({ code: 400, message: '原密码错误' });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ code: 400, message: '新密码至少6位' });
  try {
    cfg.adminPassword = await hashPassword(newPassword);
  } catch { return res.status(500).json({ code: 500, message: '密码加密失败' }); }
  saveConfig(cfg);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('change_password', {}, 'admin', ip);
  res.json({ code: 200, message: '密码已修改' });
});

// ─── Admin: Stats ─────────────────────────────────────────────────────────────
app.get('/admin/stats', adminAuth, (req, res) => {
  const cached = statsCache.get();
  if (cached) return res.json({ code: 200, data: cached });

  const keys = loadKeys();
  const data = computeKeyStats(keys);
  statsCache.set(data);
  broadcastEvent('statsUpdated', data, true);

  res.json({ code: 200, data });
});

app.get('/admin/stats/chart', adminAuth, (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 7, 30);
  const now = Date.now();
  const daily = [];
  for (let i = days - 1; i >= 0; i--) {
    const start = now - (i + 1) * 86400000;
    const end = now - i * 86400000;
    const slice = reqLogs.filter(l => l.t >= start && l.t < end);
    const d = new Date(end);
    daily.push({
      label: `${d.getMonth() + 1}/${d.getDate()}`,
      count: slice.length,
      ok: slice.filter(l => l.status === 200).length,
      err: slice.filter(l => l.status >= 400).length
    });
  }
  res.json({ code: 200, data: { daily } });
});

// SSE 实时事件流（WebSocket 的降级方案，Serverless 友好）
// 使用 query 参数 token=xxx 认证（EventSource 不支持自定义 header）
const SSE_MAX_CLIENTS = 200;
app.get('/admin/events', (req, res) => {
  const token = req.query.token;
  const sess = getSession(token);
  const cfg = loadConfig();
  const isAdmin = !!sess || (token && cfg.adminToken && safeEqualString(token, cfg.adminToken));
  if (!isAdmin) return res.status(401).json({ code: 401, message: '需要登录令牌（query: token=...）' });
  if (_sseClients.size >= SSE_MAX_CLIENTS) {
    return res.status(503).json({ code: 503, message: 'SSE 连接已达上限，请稍后再试' });
  }

  res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();
  res.write(`retry: 5000\n\n`);
  res.write(`event: connected\ndata: ${JSON.stringify({ time: Date.now(), version: SERVER_VERSION, mode: IS_SERVERLESS ? 'serverless' : 'long-running' })}\n\n`);

  const client = { res, isAdmin: true, connectedAt: Date.now(), token: token.slice(0, 8) };
  _sseClients.add(client);
  broadcastEvent('sseStats', { count: _sseClients.size }, true);

  // 心跳，避免反向代理超时（Vercel/Cloudflare/Nginx 默认 30-60s）
  const ping = setInterval(() => {
    if (res.writableEnded) { clearInterval(ping); return; }
    try { res.write(`: ping ${Date.now()}\n\n`); } catch { clearInterval(ping); }
  }, 25000);

  const cleanup = () => {
    clearInterval(ping);
    if (_sseClients.delete(client)) broadcastEvent('sseStats', { count: _sseClients.size }, true);
  };
  req.on('close', cleanup);
  req.on('error', cleanup);
  res.on('error', cleanup);
});

app.get('/admin/sysinfo', adminAuth, (req, res) => {
  const keys = loadKeys();
  const cfg = loadConfig();
  const uptimeMs = Date.now() - SERVER_START;
  const h = Math.floor(uptimeMs / 3600000);
  const m = Math.floor((uptimeMs % 3600000) / 60000);
  res.json({
    code: 200, data: {
      version: SERVER_VERSION,
      uptime: `${h}h ${m}m`,
      keysTotal: keys.length,
      logsTotal: reqLogs.length,
      appsTotal: cfg.apps.length,
      blacklistTotal: (cfg.blacklist || []).length,
      ipBlacklistTotal: (cfg.ipBlacklist || []).length,
      nodeVersion: process.version,
      platform: process.platform,
      wsConnections: adminClients.size
    }
  });
});

// ─── 系统健康检查（公开端点，供监控系统使用） ─────────────────────────────────
app.get('/health', (req, res) => {
  const uptimeMs = Date.now() - SERVER_START;
  const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
  res.json({
    status: 'ok',
    uptime: Math.floor(uptimeMs / 1000),
    memory: { heapUsedMB: memMB },
    timestamp: Date.now()
  });
});

// ─── 管理员健康检查（详细，需认证） ──────────────────────────────────────────
app.get('/admin/health', adminAuth, (req, res) => {
  const keys = loadKeys();
  const cfg = loadConfig();
  const uptimeMs = Date.now() - SERVER_START;
  const mem = process.memoryUsage();
  const checks = [];

  // 检查文件存储
  const dataFilesOk = fs.existsSync(CONFIG_FILE) && fs.existsSync(KEYS_FILE);
  checks.push({ name: '数据文件', status: dataFilesOk ? 'ok' : 'error', detail: dataFilesOk ? '所有数据文件正常' : '数据文件缺失' });

  // 检查卡密库存
  const unusedCount = keys.filter(k => keyStatus(k) === 'unused').length;
  const stockOk = unusedCount > 100;
  checks.push({ name: '卡密库存', status: stockOk ? 'ok' : unusedCount > 0 ? 'warn' : 'error', detail: `未使用卡密 ${unusedCount} 张` });

  // 检查内存使用
  const heapPct = Math.round(mem.heapUsed / mem.heapTotal * 100);
  checks.push({ name: '内存使用', status: heapPct < 85 ? 'ok' : 'warn', detail: `堆内存 ${Math.round(mem.heapUsed/1024/1024)}MB / ${Math.round(mem.heapTotal/1024/1024)}MB (${heapPct}%)` });

  // 检查 WebSocket 连接
  checks.push({ name: 'WebSocket', status: 'ok', detail: `当前 ${adminClients.size} 个管理员连接` });

  // 检查近5分钟错误率
  const recentLogs = reqLogs.filter(l => l.t > Date.now() - 5 * 60000);
  const errorRate = recentLogs.length > 0 ? Math.round(recentLogs.filter(l => l.status >= 500).length / recentLogs.length * 100) : 0;
  checks.push({ name: '错误率(5分钟)', status: errorRate < 10 ? 'ok' : errorRate < 30 ? 'warn' : 'error', detail: `近5分钟错误率 ${errorRate}% (共 ${recentLogs.length} 请求)` });

  const overall = checks.some(c => c.status === 'error') ? 'error' : checks.some(c => c.status === 'warn') ? 'warn' : 'ok';

  res.json({
    code: 200,
    data: {
      status: overall,
      uptime: Math.floor(uptimeMs / 1000),
      uptimeHuman: `${Math.floor(uptimeMs / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m`,
      checks,
      stats: {
        keysTotal: keys.length,
        unusedKeys: unusedCount,
        logsTotal: reqLogs.length,
        wsConnections: adminClients.size,
        appsTotal: cfg.apps.length
      },
      memory: {
        heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
        heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
        rssMB: Math.round(mem.rss / 1024 / 1024)
      },
      timestamp: Date.now()
    }
  });
});

// ─── 高级分析端点 ────────────────────────────────────────────────────────────
app.get('/admin/analytics/daily-summary', adminAuth, (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 30, 90);
  const summary = [];

  for (let i = days - 1; i >= 0; i--) {
    const start = Date.now() - (i + 1) * 86400000;
    const end = Date.now() - i * 86400000;
    const dayLogs = reqLogs.filter(l => l.t >= start && l.t < end);

    const appCounts = {};
    dayLogs.forEach(l => {
      appCounts[l.appid] = (appCounts[l.appid] || 0) + 1;
    });
    const topApp = Object.entries(appCounts).length > 0
      ? Object.entries(appCounts).sort((a, b) => b[1] - a[1])[0][0]
      : 'unknown';

    summary.push({
      date: new Date(end).toISOString().split('T')[0],
      total: dayLogs.length,
      success: dayLogs.filter(l => l.status === 200).length,
      errors: dayLogs.filter(l => l.status >= 400).length,
      topApp: topApp
    });
  }

  res.json({ code: 200, data: summary });
});

app.get('/admin/analytics/key-distribution', adminAuth, (req, res) => {
  const keys = loadKeys();
  const distribution = {
    unused: 0, active: 0, expired: 0,
    byType: { days: 0, times: 0 },
    byStatus: {}
  };

  keys.forEach(k => {
    const st = keyStatus(k);
    distribution[st]++;
    distribution.byType[k.type]++;
    distribution.byStatus[st] = (distribution.byStatus[st] || 0) + 1;
  });

  res.json({ code: 200, data: distribution });
});

app.get('/admin/analytics/top-apps', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const appStats = {};

  reqLogs.forEach(l => {
    if (!appStats[l.appid]) appStats[l.appid] = { total: 0, success: 0, errors: 0 };
    appStats[l.appid].total++;
    if (l.status === 200) appStats[l.appid].success++;
    else if (l.status >= 400) appStats[l.appid].errors++;
  });

  const sorted = Object.entries(appStats)
    .map(([appid, stats]) => ({ appid, ...stats, rate: (stats.success / stats.total * 100).toFixed(1) }))
    .sort((a, b) => b.total - a.total)
    .slice(0, limit);

  res.json({ code: 200, data: sorted });
});

// ─── 告警系统 ────────────────────────────────────────────────────────────────────
app.get('/admin/alerts', adminAuth, (req, res) => {
  const keys = loadKeys();
  const context = {
    keyStats: { unused: keys.filter(k => keyStatus(k) === 'unused').length },
    logs: reqLogs,
    rateLimitTriggered: rlMap.size
  };
  const newAlerts = alertEngine.check(context);
  res.json({ code: 200, data: alertEngine.getAlerts(), new: newAlerts.length });
});

app.post('/admin/alerts/:alertId/acknowledge', adminAuth, (req, res) => {
  alertEngine.acknowledgeAlert(req.params.alertId);
  broadcastEvent('alertsUpdated', { action: 'acknowledged', id: req.params.alertId, total: alertEngine.getAlerts().length }, true);
  res.json({ code: 200, message: '告警已确认' });
});

app.get('/admin/alerts/severity/:severity', adminAuth, (req, res) => {
  const alerts = alertEngine.getAlerts(req.params.severity);
  res.json({ code: 200, data: alerts });
});

// ─── 备份管理 ────────────────────────────────────────────────────────────────────
app.get('/admin/backups/list', adminAuth, (req, res) => {
  const backups = backupManager.listBackups();
  res.json({ code: 200, data: backups });
});

app.post('/admin/backups/create', adminAuth, async (req, res) => {
  try {
    const cfg = loadConfig();
    const keys = loadKeys();
    const backup = await backupManager.createBackup(cfg, keys, reqLogs);
    res.json({ code: 200, message: '备份创建成功', data: backup });
    broadcastEvent('backupCreated', backup, true);
  } catch (err) {
    res.status(500).json({ code: 500, message: '备份失败' });
  }
});

app.get('/admin/backups/download/:filename', adminAuth, (req, res) => {
  const filename = path.basename(req.params.filename); // prevent path traversal
  if (!/^backup-\d+\.json$/.test(filename)) return res.status(400).json({ code: 400, message: '无效的备份文件名' });
  const backup = backupManager.getBackup(filename);
  if (!backup) return res.status(404).json({ code: 404, message: '备份不存在' });

  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json(backup);
});

app.delete('/admin/backups/:filename', adminAuth, (req, res) => {
  const filename = path.basename(req.params.filename); // prevent path traversal
  if (!/^backup-\d+\.json$/.test(filename)) return res.status(400).json({ code: 400, message: '无效的备份文件名' });
  const backupPath = path.join(backupManager.backupDir, filename);
  if (!fs.existsSync(backupPath)) return res.status(404).json({ code: 404, message: '备份不存在' });

  fs.unlink(backupPath, (err) => {
    if (!err) broadcastEvent('backupDeleted', { filename }, true);
    if (err) return res.status(500).json({ code: 500, message: '删除失败' });
    res.json({ code: 200, message: '备份已删除' });
  });
});

// ─── 操作审计日志 ────────────────────────────────────────────────────────────────
app.get('/admin/audit-logs', adminAuth, (req, res) => {
  const logs = auditLog.getLogs({
    action: req.query.action,
    limit: parseInt(req.query.limit) || 100
  });
  res.json({ code: 200, data: logs, total: auditLog.logs.length });
});

// 审计日志导出 CSV
app.get('/admin/audit-logs/export', adminAuth, (req, res) => {
  const logs = auditLog.getLogs({ limit: 10000 });
  const headers = ['时间', '操作', '用户', 'IP', '状态', '详情'];
  const rows = [headers.join(',')];
  for (const l of logs) {
    const row = [
      new Date(l.timestamp).toLocaleString('zh-CN'),
      l.action || '',
      l.userId || 'admin',
      l.ip || '',
      l.status || '',
      JSON.stringify(l.details || {}).replace(/"/g, '""')
    ].map(v => `"${String(v).replace(/"/g, '""').replace(/\n/g, ' ')}"`);
    rows.push(row.join(','));
  }
  res.setHeader('Content-Disposition', `attachment; filename="audit-logs-${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send('﻿' + rows.join('\r\n'));
});

// ─── 24×7 流量热力图 ────────────────────────────────────────────────────────
app.get('/admin/analytics/heatmap', adminAuth, (req, res) => {
  const days = Math.min(Math.max(parseInt(req.query.days) || 7, 1), 30);
  const cutoff = Date.now() - days * 86400000;
  // 7×24 矩阵：dayOfWeek(0=周日..6=周六) × hour(0..23)
  const grid = Array.from({ length: 7 }, () => new Array(24).fill(0));
  let maxCell = 0;
  for (const l of reqLogs) {
    if (l.t < cutoff) continue;
    const d = new Date(l.t);
    const dow = d.getDay();
    const h = d.getHours();
    grid[dow][h]++;
    if (grid[dow][h] > maxCell) maxCell = grid[dow][h];
  }
  res.json({ code: 200, data: { grid, days, maxCell, total: reqLogs.filter(l => l.t >= cutoff).length } });
});

// 状态码分布
app.get('/admin/analytics/status-codes', adminAuth, (req, res) => {
  const hours = Math.min(Math.max(parseInt(req.query.hours) || 24, 1), 24 * 30);
  const cutoff = Date.now() - hours * 3600000;
  const dist = {};
  for (const l of reqLogs) {
    if (l.t < cutoff) continue;
    const k = String(l.status || 0);
    dist[k] = (dist[k] || 0) + 1;
  }
  res.json({ code: 200, data: dist, hours });
});

// 近 24 小时分钟级流量（用于 UI 细粒度趋势）
app.get('/admin/analytics/per-minute', adminAuth, (req, res) => {
  const mins = Math.min(Math.max(parseInt(req.query.mins) || 60, 1), 1440);
  const now = Date.now();
  const cutoff = now - mins * 60000;
  const buckets = new Array(mins).fill(0);
  for (const l of reqLogs) {
    if (l.t < cutoff) continue;
    const idx = mins - 1 - Math.floor((now - l.t) / 60000);
    if (idx >= 0 && idx < mins) buckets[idx]++;
  }
  res.json({ code: 200, data: { buckets, mins } });
});

// ─── 性能监控 ────────────────────────────────────────────────────────────────────
app.get('/admin/performance/metrics', adminAuth, (req, res) => {
  const metrics = performanceMonitor.getMetrics();
  res.json({ code: 200, data: metrics });
});

app.get('/admin/performance/slow-requests', adminAuth, (req, res) => {
  const threshold = parseInt(req.query.threshold) || 100;
  const slowRequests = performanceMonitor.getSlowRequests(threshold);
  res.json({ code: 200, data: slowRequests });
});

// 实时系统指标快照（给轮询用，WebSocket 也会主动推送 liveMetrics 事件）
app.get('/admin/performance/live', adminAuth, (req, res) => {
  res.json({ code: 200, data: computeLiveMetrics() });
});

// 按端点聚合统计（计算出 QPS/平均响应/错误率）
app.get('/admin/performance/endpoints', adminAuth, (req, res) => {
  const rows = [];
  for (const [ep, rec] of _endpointStats.entries()) {
    rows.push({
      endpoint: ep,
      count: rec.count,
      avgMs: Math.round(rec.totalMs / rec.count),
      maxMs: Math.round(rec.maxMs),
      errors: rec.errors,
      errorRate: Math.round(rec.errors * 10000 / rec.count) / 100
    });
  }
  rows.sort((a, b) => b.count - a.count);
  res.json({ code: 200, data: rows.slice(0, 50) });
});

app.delete('/admin/performance/endpoints', adminAuth, (req, res) => {
  _endpointStats.clear();
  res.json({ code: 200, message: '端点统计已重置' });
});

// ─── 数据导出 ────────────────────────────────────────────────────────────────────
app.get('/admin/export/keys', adminAuth, (req, res) => {
  let keys = loadKeys();
  // 支持按分组/状态筛选导出
  const { group, status, format = 'csv' } = req.query;
  if (group) keys = keys.filter(k => k.group === group);
  if (status) keys = keys.filter(k => keyStatus(k) === status);

  const now = Date.now();
  const tag = [group && `grp-${group}`, status].filter(Boolean).join('-') || 'all';

  if (format === 'txt') {
    // 纯文本格式：每行一个卡密
    res.setHeader('Content-Disposition', `attachment; filename="keys-${tag}-${now}.txt"`);
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    return res.send(keys.map(k => k.key).join('\r\n'));
  }
  if (format === 'json') {
    res.setHeader('Content-Disposition', `attachment; filename="keys-${tag}-${now}.json"`);
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    return res.send(JSON.stringify(keys, null, 2));
  }

  const csv = DataExporter.exportKeys(keys);
  res.setHeader('Content-Disposition', `attachment; filename="keys-${tag}-${now}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send('\ufeff' + csv);
});

app.get('/admin/export/logs', adminAuth, (req, res) => {
  const logs = reqLogs.slice(0, parseInt(req.query.limit) || 1000);
  const csv = DataExporter.exportLogs(logs);

  res.setHeader('Content-Disposition', `attachment; filename="logs-${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send('\ufeff' + csv);
});

app.get('/admin/export/stats', adminAuth, (req, res) => {
  const keys = loadKeys();
  const stats = {
    '卡密总数': keys.length,
    '未使用': keys.filter(k => keyStatus(k) === 'unused').length,
    '已激活': keys.filter(k => keyStatus(k) === 'active').length,
    '已过期': keys.filter(k => keyStatus(k) === 'expired').length,
    '总请求数': reqLogs.length,
    '成功请求': reqLogs.filter(l => l.status === 200).length,
    '错误请求': reqLogs.filter(l => l.status >= 400).length
  };

  const csv = DataExporter.exportStats(stats);
  res.setHeader('Content-Disposition', `attachment; filename="stats-${Date.now()}.csv"`);
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.send('\ufeff' + csv);
});

// ─── Webhook 管理 ──────────────────────────────────────────────────────────────
app.get('/admin/webhooks', adminAuth, (req, res) => {
  res.json({ code: 200, data: webhookManager.getWebhooks() });
});

app.post('/admin/webhooks', adminAuth, (req, res) => {
  const { url, events } = req.body || {};
  if (!url || !events) return res.status(400).json({ code: 400, message: '参数不完整' });

  let webhook;
  try {
    webhook = webhookManager.addWebhook(url, events);
  } catch (err) {
    return res.status(400).json({ code: 400, message: err.message || 'Webhook URL invalid' });
  }
  broadcastEvent('webhooksUpdated', { action: 'created', id: webhook.id }, true);
  res.json({ code: 200, message: 'Webhook 创建成功', data: webhook });
  systemLogger.log('INFO', 'Webhook 已创建', { url, events });
});

app.get('/admin/webhooks/:id/deliveries', adminAuth, (req, res) => {
  const deliveries = webhookManager.getDeliveries(req.params.id);
  res.json({ code: 200, data: deliveries });
});

app.delete('/admin/webhooks/:id', adminAuth, (req, res) => {
  webhookManager.deleteWebhook(req.params.id);
  broadcastEvent('webhooksUpdated', { action: 'deleted', id: req.params.id }, true);
  res.json({ code: 200, message: 'Webhook 已删除' });
  systemLogger.log('INFO', 'Webhook 已删除', { id: req.params.id });
});

app.patch('/admin/webhooks/:id', adminAuth, (req, res) => {
  const wh = webhookManager.webhooks.find(w => w.id === req.params.id);
  if (!wh) return res.status(404).json({ code: 404, message: 'Webhook 不存在' });
  const { active, events, url } = req.body || {};
  if (active !== undefined) wh.active = !!active;
  if (Array.isArray(events)) wh.events = events;
  if (url && typeof url === 'string') {
    try {
      webhookManager.validateUrl(url);
      const parsed = new URL(url);
      if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ code: 400, message: 'URL 必须以 http/https 开头' });
      wh.url = url;
    } catch { return res.status(400).json({ code: 400, message: 'URL 格式无效' }); }
  }
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('webhook_update', { id: req.params.id, active, events }, 'admin', ip);
  persistWebhookState();
  broadcastEvent('webhooksUpdated', { action: 'updated', id: req.params.id }, true);
  res.json({ code: 200, message: '已更新', data: wh });
});

// webhook 测试接口频率限制（防止 SSRF 滥用：每 IP 每分钟最多 5 次）
const _whTestRlMap = new Map();
app.post('/admin/webhooks/:id/test', adminAuth, async (req, res) => {
  // 速率检查
  const testIp = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const testNow = Date.now();
  const testBucket = (_whTestRlMap.get(testIp) || []).filter(t => t > testNow - 60000);
  if (testBucket.length >= 5) return res.status(429).json({ code: 429, message: 'Webhook 测试请求过于频繁，请稍后再试' });
  testBucket.push(testNow);
  _whTestRlMap.set(testIp, testBucket);
  if (_whTestRlMap.size > 500) { for (const [k, v] of _whTestRlMap.entries()) if (!v.some(t => t > testNow - 60000)) _whTestRlMap.delete(k); }

  const wh = webhookManager.webhooks.find(w => w.id === req.params.id);
  if (!wh) return res.status(404).json({ code: 404, message: 'Webhook 不存在' });
  const event = req.body?.event || 'test';
  try {
    await webhookManager._sendWebhook(wh, event, { message: '这是一条来自卡密管理系统的 Webhook 测试请求', timestamp: Date.now(), event });
    const lastDelivery = webhookManager.deliveries.find(d => d.webhookId === wh.id);
    if (lastDelivery?.success) {
      res.json({ code: 200, message: `测试成功 (${lastDelivery.responseTime}ms)`, data: lastDelivery });
    } else {
      res.status(502).json({ code: 502, message: `测试失败: ${lastDelivery?.error || '未知错误'}`, data: lastDelivery });
    }
  } catch (err) {
    res.status(500).json({ code: 500, message: `测试请求异常: ${err.message}` });
  }
});

// ─── 设备管理 ──────────────────────────────────────────────────────────────────
app.get('/admin/devices', adminAuth, (req, res) => {
  const appid = req.query.appid;
  const devices = appid
    ? deviceManager.getDevicesByApp(appid)
    : deviceManager.devices;

  res.json({ code: 200, data: devices, stats: deviceManager.getDeviceStats() });
});

app.post('/admin/devices/:id/disable', adminAuth, (req, res) => {
  deviceManager.disableDevice(req.params.id);
  broadcastEvent('devicesUpdated', { action: 'disabled', id: req.params.id, stats: deviceManager.getDeviceStats() }, true);
  res.json({ code: 200, message: '设备已禁用' });
  systemLogger.log('INFO', '设备已禁用', { deviceId: req.params.id });
});

// ─── 系统日志 ──────────────────────────────────────────────────────────────────
app.get('/admin/system-logs', adminAuth, (req, res) => {
  const logs = systemLogger.getLogs({
    category: req.query.category,
    search: req.query.search,
    limit: parseInt(req.query.limit) || 100
  });
  const stats = systemLogger.getStats();

  res.json({ code: 200, data: logs, stats });
});

app.delete('/admin/system-logs', adminAuth, (req, res) => {
  const daysOld = parseInt(req.query.days) || 7;
  systemLogger.clearOldLogs(daysOld);
  broadcastEvent('systemLogsCleared', { daysOld, stats: systemLogger.getStats() }, true);
  res.json({ code: 200, message: `已删除 ${daysOld} 天前的日志` });
});

// ─── 高级统计 ──────────────────────────────────────────────────────────────────
app.get('/admin/stats/advanced', adminAuth, (req, res) => {
  const keys = loadKeys();
  const keyStats = AdvancedStatistics.getKeyUsageStats(keys, reqLogs);
  const appStats = AdvancedStatistics.getAppUsageStats(reqLogs);
  const dailyTrends = AdvancedStatistics.getDailyTrends(reqLogs, 30);

  res.json({
    code: 200,
    data: {
      keyStats,
      appStats,
      dailyTrends
    }
  });
});

// ─── 批量操作 ──────────────────────────────────────────────────────────────────
app.post('/admin/bulk-operations/create', adminAuth, (req, res) => {
  const { operationType, itemCount } = req.body || {};
  const opId = Date.now().toString();

  const operation = bulkOperationManager.createOperation(opId, operationType, itemCount);
  broadcastEvent('bulkOperationCreated', { operationId: opId, operation }, true);
  res.json({ code: 200, data: { operationId: opId, operation } });
});

app.get('/admin/bulk-operations/:id/progress', adminAuth, (req, res) => {
  const progress = bulkOperationManager.getProgress(req.params.id);
  if (!progress) return res.status(404).json({ code: 404, message: '操作不存在' });

  res.json({ code: 200, data: progress });
});

app.post('/admin/bulk-operations/:id/update', adminAuth, (req, res) => {
  const { processed, error } = req.body || {};
  bulkOperationManager.updateProgress(req.params.id, processed, error);

  const progress = bulkOperationManager.getProgress(req.params.id);
  broadcastEvent(progress?.status === 'completed' ? 'bulkComplete' : 'bulkProgress', { requestId: req.params.id, ...(progress || {}) }, true);
  res.json({ code: 200, data: progress });
});

// ─── 高级搜索 ──────────────────────────────────────────────────────────────────
app.post('/admin/search/keys', adminAuth, (req, res) => {
  const { conditions } = req.body || {};
  const keys = loadKeys();

  const results = advancedSearch.search(keys, conditions || []);
  res.json({ code: 200, data: results, count: results.length });
});

app.get('/admin/search/history', adminAuth, (req, res) => {
  const history = advancedSearch.getHistory();
  res.json({ code: 200, data: history });
});
app.get('/admin/keys', adminAuth, (req, res) => {
  let keys = loadKeys();
  const { q, status, group, type, limit, offset } = req.query;

  // Server-side filtering
  if (q) {
    const lq = q.toLowerCase();
    keys = keys.filter(k =>
      k.key.toLowerCase().includes(lq) ||
      (k.note && k.note.toLowerCase().includes(lq)) ||
      (k.group && k.group.toLowerCase().includes(lq))
    );
  }
  if (group) keys = keys.filter(k => k.group === group);
  if (type) keys = keys.filter(k => k.type === type);
  if (status && status !== 'all') {
    if (status === 'expiring') {
      const thresh = Date.now() + 7 * 86400000;
      keys = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime > Date.now() && k.expireTime <= thresh);
    } else {
      keys = keys.filter(k => keyStatus(k) === status);
    }
  }

  const total = keys.length;
  const lim = limit ? Math.min(parseInt(limit) || 200, 1000) : undefined;
  const off = parseInt(offset) || 0;
  const paginated = lim !== undefined ? keys.slice(off, off + lim) : keys;

  res.json({
    code: 200,
    data: paginated.map(k => ({ ...k, status: keyStatus(k) })),
    total,
    offset: off,
    limit: lim
  });
});

app.get('/admin/keys/groups', adminAuth, (req, res) => {
  const keys = loadKeys();
  const groups = [...new Set(keys.map(k => k.group).filter(Boolean))];
  res.json({ code: 200, data: groups });
});

// 分组详细统计
app.get('/admin/keys/groups/stats', adminAuth, (req, res) => {
  const keys = loadKeys();
  const map = {};
  keys.forEach(k => {
    const g = k.group || '（未分组）';
    if (!map[g]) map[g] = { group: g, total: 0, unused: 0, active: 0, expired: 0 };
    const s = keyStatus(k);
    map[g].total++;
    map[g][s]++;
  });
  const data = Object.values(map).sort((a, b) => b.total - a.total);
  res.json({ code: 200, data });
});

// 批量修改分组
app.post('/admin/keys/set-group', adminAuth, (req, res) => {
  const { keyList, group } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  const keys = loadKeys();
  const cleanGroup = sanitizeTextField(group, 50);
  let changed = 0;
  keys.forEach(k => { if (keyList.includes(k.key)) { k.group = cleanGroup || ''; changed++; } });
  saveKeys(keys);
  res.json({ code: 200, message: `已更新 ${changed} 个卡密的分组`, changed });
});

app.get('/admin/keys/expiring', adminAuth, (req, res) => {
  const days = Math.min(parseInt(req.query.days) || 7, 90);
  const threshold = Date.now() + days * 86400000;
  const keys = loadKeys();
  const expiring = keys
    .filter(k => k.status !== 'unused' && k.type === 'days' && k.expireTime && k.expireTime > Date.now() && k.expireTime <= threshold)
    .map(k => ({ ...k, status: keyStatus(k), daysLeft: Math.ceil((k.expireTime - Date.now()) / 86400000) }));
  res.json({ code: 200, data: expiring, total: expiring.length });
});

app.post('/admin/keys/add', adminAuth, (req, res) => {
  let { key, type, value, note, group, prefix } = req.body || {};
  const keys = loadKeys();
  note = sanitizeTextField(note, 200);
  group = sanitizeTextField(group, 50);

  // 如果卡密为空，自动生成
  if (!key || !key.trim()) {
    let generatedKey, attempts = 0;
    const maxAttempts = 200;
    do {
      generatedKey = genKey((prefix || 'KM').toUpperCase().slice(0, 8));
      attempts++;
    } while (keys.find(k => k.key === generatedKey) && attempts < maxAttempts);

    if (attempts >= maxAttempts) {
      return res.status(400).json({ code: 400, message: '生成卡密失败，已达到最大重试次数' });
    }
    key = generatedKey;
  } else {
    key = sanitizeKeyField(key);
    if (!key) return res.status(400).json({ code: 400, message: '卡密格式无效' });
    if (!VALID_KEY_RE.test(key)) return res.status(400).json({ code: 400, message: '卡密仅支持 3-64 位字母、数字、点、下划线和短横线' });
    if (keys.find(k => k.key === key)) {
      return res.status(400).json({ code: 400, message: '卡密已存在' });
    }
  }

  const obj = { key: key, type: type || 'days', value: parseInt(value) || 30, status: 'unused', note: note || '', group: group || '', createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 };
  keys.push(obj);
  saveKeys(keys);
  res.json({ code: 200, message: '添加成功', data: obj });
});

app.post('/admin/keys/generate', adminAuth, (req, res) => {
  const { count = 10, type = 'days', value = 30, prefix = 'KM' } = req.body || {};
  const note = sanitizeTextField(req.body?.note, 200);
  const group = sanitizeTextField(req.body?.group, 50);
  if (!['days', 'times'].includes(type)) return res.status(400).json({ code: 400, message: '类型无效' });
  if (typeof note === 'string' && note.length > 200) return res.status(400).json({ code: 400, message: '备注不能超过200字符' });
  if (typeof group === 'string' && group.length > 50) return res.status(400).json({ code: 400, message: '分组名不能超过50字符' });
  const safePrefix = (String(prefix || 'KM')).replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8) || 'KM';
  const n = Math.min(Math.max(parseInt(count) || 10, 1), 500);
  const keys = loadKeys();
  const generated = [];
  for (let i = 0; i < n; i++) {
    let k, t = 0;
    do { k = genKey(safePrefix); t++; } while (keys.find(x => x.key === k) && t < 200);
    const obj = { key: k, type, value: parseInt(value) || 30, status: 'unused', note, group, createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 };
    keys.push(obj);
    generated.push(obj);
  }
  saveKeys(keys);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_generate', { count: generated.length, type: req.body?.type, value: req.body?.value, prefix: safePrefix, group: req.body?.group }, 'admin', ip);
  res.json({ code: 200, message: `成功生成 ${generated.length} 个卡密`, data: generated });
});

const MAX_IMPORT_KEYS = 10000;
const VALID_KEY_RE = /^[A-Za-z0-9._-]{3,64}$/;

app.post('/admin/keys/import', adminAuth, (req, res) => {
  const { keys: importList, type = 'days', value = 30 } = req.body || {};
  const note = sanitizeTextField(req.body?.note, 200);
  const group = sanitizeTextField(req.body?.group, 50);
  if (!Array.isArray(importList) || !importList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  if (importList.length > MAX_IMPORT_KEYS) return res.status(400).json({ code: 400, message: `一次最多导入 ${MAX_IMPORT_KEYS} 条` });
  if (!['days', 'times'].includes(type)) return res.status(400).json({ code: 400, message: '类型无效' });
  if (typeof note === 'string' && note.length > 200) return res.status(400).json({ code: 400, message: '备注不能超过 200 字符' });
  if (typeof group === 'string' && group.length > 50) return res.status(400).json({ code: 400, message: '分组名不能超过 50 字符' });
  const v = parseInt(value) || 30;
  const safeVal = Math.max(1, Math.min(100000, v));
  const keys = loadKeys();
  const existing = new Set(keys.map(k => k.key));
  const added = [], skipped = [];
  for (const k of importList) {
    const keyStr = sanitizeKeyField(typeof k === 'string' ? k : (k?.key || ''));
    if (!keyStr) continue;
    if (!VALID_KEY_RE.test(keyStr)) { skipped.push(keyStr); continue; }
    if (existing.has(keyStr)) { skipped.push(keyStr); continue; }
    const obj = { key: keyStr, type, value: safeVal, status: 'unused', note, group, createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 };
    keys.push(obj);
    existing.add(keyStr);
    added.push(obj);
  }
  if (added.length) saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_import', { added: added.length, skipped: skipped.length, group }, 'admin', ip);
  res.json({ code: 200, message: `导入 ${added.length} 个，跳过 ${skipped.length} 个`, data: { added: added.length, skipped: skipped.length, skippedKeys: skipped.slice(0, 100) } });
});

// 文本格式导入（每行一个卡密，支持 TXT 粘贴）
app.post('/admin/keys/import-text', adminAuth, (req, res) => {
  const { text, type = 'days', value = 30 } = req.body || {};
  const note = sanitizeTextField(req.body?.note, 200);
  const group = sanitizeTextField(req.body?.group, 50);
  if (!text || typeof text !== 'string') return res.status(400).json({ code: 400, message: '请提供文本内容' });
  if (text.length > 2 * 1024 * 1024) return res.status(400).json({ code: 400, message: '文本过大（> 2MB）' });
  if (!['days', 'times'].includes(type)) return res.status(400).json({ code: 400, message: '类型无效' });
  if (typeof note === 'string' && note.length > 200) return res.status(400).json({ code: 400, message: '备注不能超过 200 字符' });
  if (typeof group === 'string' && group.length > 50) return res.status(400).json({ code: 400, message: '分组名不能超过 50 字符' });
  const importList = text.split(/\r?\n/).map(l => sanitizeKeyField(l)).filter(l => l && !l.startsWith('#'));
  if (!importList.length) return res.status(400).json({ code: 400, message: '未发现有效卡密' });
  if (importList.length > MAX_IMPORT_KEYS) return res.status(400).json({ code: 400, message: `一次最多导入 ${MAX_IMPORT_KEYS} 条` });
  const safeVal = Math.max(1, Math.min(100000, parseInt(value) || 30));
  const keys = loadKeys();
  const existing = new Set(keys.map(k => k.key));
  const added = [], skipped = [];
  for (const keyStr of importList) {
    if (!VALID_KEY_RE.test(keyStr)) { skipped.push(keyStr); continue; }
    if (existing.has(keyStr)) { skipped.push(keyStr); continue; }
    keys.push({ key: keyStr, type, value: safeVal, status: 'unused', note, group, createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 });
    existing.add(keyStr);
    added.push(keyStr);
  }
  if (added.length) saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_import_text', { added: added.length, skipped: skipped.length, group }, 'admin', ip);
  res.json({ code: 200, message: `导入 ${added.length} 个，跳过 ${skipped.length} 个`, data: { added: added.length, skipped: skipped.length } });
});

app.post('/admin/keys/bulk-action', adminAuth, (req, res) => {
  const { action, keyList } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  if (!['delete', 'reset', 'blacklist'].includes(action)) return res.status(400).json({ code: 400, message: '无效操作' });

  if (action === 'delete') {
    let keys = loadKeys();
    const before = keys.length;
    keys = keys.filter(k => !keyList.includes(k.key));
    saveKeys(keys);
    return res.json({ code: 200, message: `已删除 ${before - keys.length} 个卡密` });
  }

  if (action === 'reset') {
    const keys = loadKeys();
    let count = 0;
    keys.forEach((k, i) => {
      if (keyList.includes(k.key)) {
        keys[i] = { ...k, status: 'unused', activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 };
        count++;
      }
    });
    saveKeys(keys);
    return res.json({ code: 200, message: `已重置 ${count} 个卡密` });
  }

  if (action === 'blacklist') {
    const cfg = loadConfig();
    if (!cfg.blacklist) cfg.blacklist = [];
    let added = 0;
    keyList.forEach(k => { if (!cfg.blacklist.includes(k)) { cfg.blacklist.push(k); added++; } });
    saveConfig(cfg);
    return res.json({ code: 200, message: `已将 ${added} 个卡密加入黑名单` });
  }
});

// 删除所有过期卡密（literal路由必须在 :key 参数路由之前）
app.delete('/admin/keys/expired', adminAuth, (req, res) => {
  let keys = loadKeys();
  const before = keys.length;
  keys = keys.filter(k => keyStatus(k) !== 'expired');
  const deleted = before - keys.length;
  if (deleted > 0) saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_delete_expired', { count: deleted }, 'admin', ip);
  res.json({ code: 200, message: `已删除 ${deleted} 个过期卡密`, deleted });
});

// 批量续期
app.post('/admin/keys/bulk-renew', adminAuth, (req, res) => {
  const { keyList, days } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  const d = parseInt(days);
  if (!d || d <= 0 || d > 36500) return res.status(400).json({ code: 400, message: '请提供有效的续期天数（1-36500）' });
  const keys = loadKeys();
  const now = Date.now();
  let renewed = 0, skipped = 0;
  keys.forEach(k => {
    if (!keyList.includes(k.key)) return;
    if (k.type !== 'days' || k.status === 'unused') { skipped++; return; }
    const base = Math.max(k.expireTime || now, now);
    k.expireTime = base + d * 86400000;
    renewed++;
  });
  if (renewed > 0) saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_bulk_renew', { count: renewed, skipped, days: d }, 'admin', ip);
  res.json({ code: 200, message: `已续期 ${renewed} 个卡密，跳过 ${skipped} 个`, data: { renewed, skipped } });
});

app.patch('/admin/keys/:key', adminAuth, (req, res) => {
  const keys = loadKeys();
  const idx = keys.findIndex(k => k.key === req.params.key);
  if (idx === -1) return res.status(404).json({ code: 404, message: '卡密不存在' });
  const { value, note, group, resetStatus } = req.body || {};
  if (value !== undefined) keys[idx].value = parseInt(value);
  if (note !== undefined) keys[idx].note = sanitizeTextField(note, 200);
  if (group !== undefined) keys[idx].group = sanitizeTextField(group, 50);
  if (resetStatus) { keys[idx].status = 'unused'; keys[idx].activatedAt = null; keys[idx].expireTime = null; keys[idx].deviceId = null; keys[idx].appId = null; keys[idx].usedCount = 0; }
  saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_edit', { key: req.params.key, changes: { value, note, group, resetStatus } }, 'admin', ip);
  res.json({ code: 200, message: '更新成功', data: { ...keys[idx], status: keyStatus(keys[idx]) } });
});

// 删除回收站：保留 5 分钟内被删的卡密，可撤销
const _trashBin = []; // { undoId, deletedAt, expiresAt, items: [{...key}], deletedBy }
const TRASH_TTL_MS = 5 * 60 * 1000;
function pruneTrash() {
  const now = Date.now();
  for (let i = _trashBin.length - 1; i >= 0; i--) {
    if (_trashBin[i].expiresAt < now) _trashBin.splice(i, 1);
  }
  if (_trashBin.length > 50) _trashBin.splice(0, _trashBin.length - 50); // 上限 50 批
}

function pushTrash(items, deletedBy) {
  pruneTrash();
  const undoId = crypto.randomBytes(6).toString('hex');
  const entry = {
    undoId,
    deletedAt: Date.now(),
    expiresAt: Date.now() + TRASH_TTL_MS,
    items: items.map(k => ({ ...k })),
    deletedBy
  };
  _trashBin.push(entry);
  broadcastEvent('trashUpdated', { count: _trashBin.length, latest: { undoId, count: items.length, deletedAt: entry.deletedAt, expiresAt: entry.expiresAt } }, true);
  return entry;
}

app.delete('/admin/keys/:key', adminAuth, (req, res) => {
  const keys = loadKeys();
  const idx = keys.findIndex(k => k.key === req.params.key);
  if (idx === -1) return res.status(404).json({ code: 404, message: '卡密不存在' });
  const removed = keys.splice(idx, 1);
  saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const trash = pushTrash(removed, ip);
  auditLog.record('key_delete', { key: req.params.key, undoId: trash.undoId }, 'admin', ip);
  res.json({ code: 200, message: '删除成功', undoId: trash.undoId, undoExpiresAt: trash.expiresAt });
});

app.delete('/admin/keys', adminAuth, (req, res) => {
  const { keyList } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  let keys = loadKeys();
  const before = keys.length;
  const removed = keys.filter(k => keyList.includes(k.key));
  keys = keys.filter(k => !keyList.includes(k.key));
  saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  const trash = removed.length ? pushTrash(removed, ip) : null;
  auditLog.record('key_bulk_delete', { count: before - keys.length, undoId: trash?.undoId }, 'admin', ip);
  res.json({ code: 200, message: `已删除 ${before - keys.length} 个卡密`, undoId: trash?.undoId, undoExpiresAt: trash?.expiresAt });
});

// 列出可撤销的删除批次
app.get('/admin/trash', adminAuth, (req, res) => {
  pruneTrash();
  res.json({
    code: 200,
    data: _trashBin.map(t => ({
      undoId: t.undoId,
      deletedAt: t.deletedAt,
      expiresAt: t.expiresAt,
      count: t.items.length,
      deletedBy: t.deletedBy,
      remainingMs: Math.max(0, t.expiresAt - Date.now()),
      sampleKeys: t.items.slice(0, 3).map(k => k.key)
    })),
    total: _trashBin.length
  });
});

// 撤销删除：恢复指定批次
app.post('/admin/trash/:undoId/restore', adminAuth, (req, res) => {
  pruneTrash();
  const i = _trashBin.findIndex(t => t.undoId === req.params.undoId);
  if (i === -1) return res.status(404).json({ code: 404, message: '撤销记录不存在或已过期' });
  const batch = _trashBin[i];
  const keys = loadKeys();
  const existing = new Set(keys.map(k => k.key));
  let restored = 0, skipped = 0;
  for (const item of batch.items) {
    if (existing.has(item.key)) { skipped++; continue; }
    keys.push(item);
    existing.add(item.key);
    restored++;
  }
  if (restored) saveKeys(keys);
  _trashBin.splice(i, 1);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_restore', { restored, skipped, undoId: batch.undoId }, 'admin', ip);
  broadcastEvent('trashUpdated', { count: _trashBin.length }, true);
  res.json({ code: 200, message: `已恢复 ${restored} 个，跳过 ${skipped} 个（已存在）`, data: { restored, skipped } });
});

// 永久清空回收站
app.delete('/admin/trash', adminAuth, (req, res) => {
  const n = _trashBin.length;
  _trashBin.length = 0;
  broadcastEvent('trashUpdated', { count: 0 }, true);
  res.json({ code: 200, message: `已清空 ${n} 批回收记录` });
});

// ─── Admin: Key Blacklist ─────────────────────────────────────────────────────
app.get('/admin/keys/blacklist', adminAuth, (req, res) => {
  const cfg = loadConfig();
  res.json({ code: 200, data: cfg.blacklist || [] });
});

app.post('/admin/keys/blacklist', adminAuth, (req, res) => {
  const { key } = req.body || {};
  if (!key) return res.status(400).json({ code: 400, message: '请提供卡密' });
  const cfg = loadConfig();
  if (!cfg.blacklist.includes(key)) cfg.blacklist.push(key);
  saveConfig(cfg);
  res.json({ code: 200, message: '已加入黑名单' });
});

app.delete('/admin/keys/blacklist/:key', adminAuth, (req, res) => {
  const cfg = loadConfig();
  cfg.blacklist = cfg.blacklist.filter(k => k !== req.params.key);
  saveConfig(cfg);
  res.json({ code: 200, message: '已从黑名单移除' });
});

// 卡密黑名单批量导入
app.post('/admin/keys/blacklist/bulk', adminAuth, (req, res) => {
  const { keys: list } = req.body || {};
  if (!Array.isArray(list) || !list.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  if (list.length > 5000) return res.status(400).json({ code: 400, message: '一次最多 5000 条' });
  const cfg = loadConfig();
  if (!cfg.blacklist) cfg.blacklist = [];
  const set = new Set(cfg.blacklist);
  let added = 0;
  for (const k of list) {
    const s = String(k || '').trim();
    if (s && !set.has(s) && s.length <= 64 && /^[A-Za-z0-9._-]{3,64}$/.test(s)) { set.add(s); added++; }
  }
  cfg.blacklist = Array.from(set);
  saveConfig(cfg);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('blacklist_bulk_add', { added, total: cfg.blacklist.length }, 'admin', ip);
  res.json({ code: 200, message: `已加入 ${added} 个，跳过 ${list.length - added} 个`, data: { added, total: cfg.blacklist.length } });
});

// ─── Admin: IP Blacklist ──────────────────────────────────────────────────────
app.get('/admin/ip-blacklist', adminAuth, (req, res) => {
  const cfg = loadConfig();
  res.json({ code: 200, data: cfg.ipBlacklist || [] });
});

app.post('/admin/ip-blacklist', adminAuth, (req, res) => {
  const { ip, reason } = req.body || {};
  if (!ip || typeof ip !== 'string') return res.status(400).json({ code: 400, message: '请提供 IP 地址' });
  // Basic IP validation (IPv4/IPv6/CIDR)
  if (ip.length > 50 || !/^[\d.:a-fA-F/]+$/.test(ip)) return res.status(400).json({ code: 400, message: 'IP 格式无效' });
  const cfg = loadConfig();
  if (!cfg.ipBlacklist) cfg.ipBlacklist = [];
  if (!cfg.ipBlacklist.includes(ip)) cfg.ipBlacklist.push(ip);
  saveConfig(cfg);
  res.json({ code: 200, message: 'IP 已加入黑名单' });
});

// IP 黑名单批量导入
app.post('/admin/ip-blacklist/bulk', adminAuth, (req, res) => {
  const { ips } = req.body || {};
  if (!Array.isArray(ips) || !ips.length) return res.status(400).json({ code: 400, message: '请提供 IP 列表' });
  if (ips.length > 5000) return res.status(400).json({ code: 400, message: '一次最多 5000 条' });
  const cfg = loadConfig();
  if (!cfg.ipBlacklist) cfg.ipBlacklist = [];
  const set = new Set(cfg.ipBlacklist);
  let added = 0, skipped = 0;
  for (const raw of ips) {
    const s = String(raw || '').trim();
    if (!s || s.length > 50 || !/^[\d.:a-fA-F/]+$/.test(s)) { skipped++; continue; }
    if (!set.has(s)) { set.add(s); added++; } else { skipped++; }
  }
  cfg.ipBlacklist = Array.from(set);
  saveConfig(cfg);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('ip_blacklist_bulk_add', { added, skipped, total: cfg.ipBlacklist.length }, 'admin', ip);
  res.json({ code: 200, message: `已加入 ${added} 个，跳过 ${skipped} 个`, data: { added, skipped, total: cfg.ipBlacklist.length } });
});

app.delete('/admin/ip-blacklist/:ip', adminAuth, (req, res) => {
  const ip = decodeURIComponent(req.params.ip);
  if (!ip || ip.length > 50 || !/^[\d.:a-fA-F/]+$/.test(ip)) return res.status(400).json({ code: 400, message: 'IP 格式无效' });
  const cfg = loadConfig();
  cfg.ipBlacklist = (cfg.ipBlacklist || []).filter(x => x !== ip);
  saveConfig(cfg);
  res.json({ code: 200, message: '已移除' });
});

// ─── Admin: Apps ──────────────────────────────────────────────────────────────
function computeAppStats() {
  const cfg = loadConfig();
  const now = Date.now();
  return cfg.apps.map(a => {
    const appLogs = reqLogs.filter(l => l.appid === a.appid);
    const total = appLogs.length;
    const today = appLogs.filter(l => l.t > now - 86400000).length;
    const success = appLogs.filter(l => l.status === 200).length;
    const rate = total > 0 ? Math.round(success / total * 100) : 0;
    return { ...a, stats: { total, today, success, rate } };
  });
}

app.get('/admin/apps', adminAuth, (req, res) => {
  let apps = appStatsCache.get();
  if (!apps) {
    apps = computeAppStats();
    appStatsCache.set(apps);
  }
  res.json({ code: 200, data: apps });
});

app.post('/admin/apps', adminAuth, (req, res) => {
  const { name, appid, requireSign = false } = req.body || {};
  const appName = sanitizeTextField(name, 80);
  if (!appName) return res.status(400).json({ code: 400, message: 'name invalid' });
  if (!name || !appid) return res.status(400).json({ code: 400, message: 'name 和 appid 不能为空' });
  if (!/^[a-zA-Z0-9_-]{2,32}$/.test(appid)) return res.status(400).json({ code: 400, message: 'appid 只能包含字母/数字/下划线/连字符，2~32位' });
  const cfg = loadConfig();
  if (cfg.apps.find(a => a.appid === appid)) return res.status(400).json({ code: 400, message: 'AppID 已存在' });
  const app_obj = { appid, name: appName, secret: crypto.randomBytes(24).toString('hex'), enabled: true, requireSign, createdAt: Date.now() };
  cfg.apps.push(app_obj);
  saveConfig(cfg);
  broadcastEvent('appsUpdated', { count: cfg.apps.length, action: 'created', appid }, true);
  res.json({ code: 200, message: '应用创建成功', data: app_obj });
});

app.patch('/admin/apps/:appid', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const idx = cfg.apps.findIndex(a => a.appid === req.params.appid);
  if (idx === -1) return res.status(404).json({ code: 404, message: '应用不存在' });
  const { enabled, requireSign, name, rateLimitPerMin } = req.body || {};
  if (enabled !== undefined) cfg.apps[idx].enabled = !!enabled;
  if (requireSign !== undefined) cfg.apps[idx].requireSign = !!requireSign;
  if (rateLimitPerMin !== undefined) {
    const r = parseInt(rateLimitPerMin);
    if (isNaN(r) || r < 0 || r > 100000) return res.status(400).json({ code: 400, message: 'rateLimitPerMin 必须为 0-100000（0 表示不限制）' });
    cfg.apps[idx].rateLimitPerMin = r;
  }
  if (name !== undefined) {
    const appName = sanitizeTextField(name, 80);
    if (!appName) return res.status(400).json({ code: 400, message: 'name invalid' });
    cfg.apps[idx].name = appName;
  }
  saveConfig(cfg);
  broadcastEvent('appsUpdated', { count: cfg.apps.length, action: 'updated', appid: req.params.appid }, true);
  res.json({ code: 200, message: '更新成功', data: cfg.apps[idx] });
});

app.delete('/admin/apps/:appid', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const before = cfg.apps.length;
  cfg.apps = cfg.apps.filter(a => a.appid !== req.params.appid);
  const appCountAfterDelete = cfg.apps.length;
  if (cfg.apps.length === before) return res.status(404).json({ code: 404, message: '应用不存在' });
  saveConfig(cfg);
  broadcastEvent('appsUpdated', { count: appCountAfterDelete, action: 'deleted', appid: req.params.appid }, true);
  res.json({ code: 200, message: '删除成功' });
});

app.post('/admin/apps/:appid/reset-secret', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const idx = cfg.apps.findIndex(a => a.appid === req.params.appid);
  if (idx === -1) return res.status(404).json({ code: 404, message: '应用不存在' });
  cfg.apps[idx].secret = crypto.randomBytes(24).toString('hex');
  saveConfig(cfg);
  broadcastEvent('appsUpdated', { count: cfg.apps.length, action: 'secretReset', appid: req.params.appid }, true);
  res.json({ code: 200, message: '密钥已重置', secret: cfg.apps[idx].secret });
});

// 单个应用详细统计
app.get('/admin/apps/:appid/stats', adminAuth, (req, res) => {
  const { appid } = req.params;
  const days = Math.min(parseInt(req.query.days) || 7, 30);
  const now = Date.now();
  const appLogs = reqLogs.filter(l => l.appid === appid);
  const total = appLogs.length;
  const today = appLogs.filter(l => l.t > now - 86400000).length;
  const success = appLogs.filter(l => l.status === 200).length;
  const errors = appLogs.filter(l => l.status >= 400).length;
  const daily = [];
  for (let i = days - 1; i >= 0; i--) {
    const start = now - (i + 1) * 86400000, end = now - i * 86400000;
    const slice = appLogs.filter(l => l.t >= start && l.t < end);
    const d = new Date(end);
    daily.push({ date: `${d.getMonth()+1}/${d.getDate()}`, total: slice.length, success: slice.filter(l=>l.status===200).length });
  }
  // 24小时分布（以近30天日志为基础，统计每小时的平均请求量）
  const hourly = Array(24).fill(0);
  const recentLogs = appLogs.filter(l => l.t > now - 30 * 86400000);
  recentLogs.forEach(l => { hourly[new Date(l.t).getHours()]++; });
  // 归一化为每天平均
  const daysWithData = Math.max(1, Math.min(30, Math.ceil((now - (appLogs[appLogs.length - 1]?.t || now)) / 86400000)));
  const hourlyAvg = hourly.map(c => Math.round(c / daysWithData * 10) / 10);

  const keys = loadKeys().filter(k => k.appId === appid);
  res.json({ code: 200, data: { total, today, success, errors, successRate: total ? Math.round(success*100/total) : 0, daily, hourly: hourlyAvg, boundKeys: keys.length } });
});

// ─── Admin: Logs ──────────────────────────────────────────────────────────────
app.get('/admin/logs', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  const offset = Math.max(parseInt(req.query.offset) || 0, 0);
  const { status, ip, appid, rid, key, q } = req.query;
  let logs = reqLogs;
  if (status) logs = logs.filter(l => String(l.status).startsWith(status));
  if (ip) logs = logs.filter(l => (l.ip || '').includes(ip));
  if (appid) logs = logs.filter(l => l.appid === appid);
  if (rid) logs = logs.filter(l => l.rid === rid);
  if (key) logs = logs.filter(l => (l.key || '').includes(key));
  if (q) {
    const lq = String(q).toLowerCase();
    logs = logs.filter(l => (l.msg || '').toLowerCase().includes(lq) || (l.p || '').toLowerCase().includes(lq));
  }
  res.json({ code: 200, data: logs.slice(offset, offset + limit), total: reqLogs.length, filtered: logs.length });
});

app.delete('/admin/logs', adminAuth, (req, res) => {
  reqLogs = [];
  fs.writeFileSync(LOGS_FILE, '[]');
  statsCache.invalidate();
  appStatsCache.invalidate();
  broadcastEvent('logsCleared', {}, true);
  broadcastEvent('statsUpdated', computeKeyStats(), true);
  res.json({ code: 200, message: '日志已清空' });
});

// ─── Admin: Config ────────────────────────────────────────────────────────────
app.get('/admin/config', adminAuth, (req, res) => {
  const cfg = loadConfig();
  res.json({ code: 200, data: {
    globalRequireSign: cfg.globalRequireSign,
    rateLimitPerMin: cfg.rateLimitPerMin,
    maintenanceMode: !!cfg.maintenanceMode,
    maintenanceMessage: cfg.maintenanceMessage || '',
    blacklistCount: (cfg.blacklist || []).length,
    ipBlacklistCount: (cfg.ipBlacklist || []).length
  } });
});

app.patch('/admin/config', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const { globalRequireSign, rateLimitPerMin, maintenanceMode, maintenanceMessage } = req.body || {};
  if (globalRequireSign !== undefined) cfg.globalRequireSign = !!globalRequireSign;
  if (rateLimitPerMin !== undefined) cfg.rateLimitPerMin = Math.max(10, Math.min(1000, parseInt(rateLimitPerMin) || 60));
  if (maintenanceMode !== undefined) cfg.maintenanceMode = !!maintenanceMode;
  if (maintenanceMessage !== undefined) cfg.maintenanceMessage = sanitizeTextField(maintenanceMessage, 160);
  saveConfig(cfg);
  res.json({ code: 200, message: '配置已保存' });
});

// ─── 自动补货配置 ───────────────────────────────────────────────────────────
app.get('/admin/auto-stock', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const keys = loadKeys();
  const unused = keys.filter(k => keyStatus(k) === 'unused').length;
  res.json({ code: 200, data: { config: cfg.autoStock || DEFAULT_CONFIG.autoStock, currentUnused: unused } });
});

app.patch('/admin/auto-stock', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const cur = cfg.autoStock || { ...DEFAULT_CONFIG.autoStock };
  const { enabled, threshold, refillTo, type, value, prefix, group } = req.body || {};
  if (enabled !== undefined) cur.enabled = !!enabled;
  if (threshold !== undefined) {
    const t = parseInt(threshold);
    if (!t || t < 1 || t > 100000) return res.status(400).json({ code: 400, message: '阈值必须为 1~100000' });
    cur.threshold = t;
  }
  if (refillTo !== undefined) {
    const r = parseInt(refillTo);
    if (!r || r < 1 || r > 100000) return res.status(400).json({ code: 400, message: '补货至必须为 1~100000' });
    cur.refillTo = r;
  }
  if (cur.refillTo <= cur.threshold) return res.status(400).json({ code: 400, message: '补货至必须大于触发阈值' });
  if (type !== undefined) {
    if (!['days', 'times'].includes(type)) return res.status(400).json({ code: 400, message: '类型必须是 days 或 times' });
    cur.type = type;
  }
  if (value !== undefined) {
    const v = parseInt(value);
    if (!v || v < 1 || v > 100000) return res.status(400).json({ code: 400, message: '值必须为 1~100000' });
    cur.value = v;
  }
  if (prefix !== undefined) cur.prefix = String(prefix).replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8) || 'KM';
  if (group !== undefined) cur.group = String(group).slice(0, 50);
  cfg.autoStock = cur;
  saveConfig(cfg);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('auto_stock_config', cur, 'admin', ip);
  res.json({ code: 200, message: '已保存', data: cur });
});

// 手动触发一次补货检查（便于测试/立即补货）
app.post('/admin/auto-stock/trigger', adminAuth, (req, res) => {
  try {
    taskScheduler.tasks && taskScheduler.tasks.forEach; // 容错
  } catch {}
  // 直接内联执行同逻辑
  const cfg = loadConfig();
  const cur = cfg.autoStock || {};
  if (!cur.enabled) return res.status(400).json({ code: 400, message: '自动补货未启用' });
  const keys = loadKeys();
  const unused = keys.filter(k => keyStatus(k) === 'unused').length;
  if (unused >= cur.threshold) return res.json({ code: 200, message: `当前未使用 ${unused}，未触发`, generated: 0 });
  const needed = Math.min(1000, cur.refillTo - unused);
  const prefix = (String(cur.prefix || 'KM')).replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8) || 'KM';
  const type = cur.type === 'times' ? 'times' : 'days';
  const value = Math.max(1, Math.min(100000, parseInt(cur.value) || 30));
  const group = (cur.group || 'auto').toString().slice(0, 50);
  const generated = [];
  for (let i = 0; i < needed; i++) {
    let k, t = 0;
    do { k = genKey(prefix); t++; } while (keys.find(x => x.key === k) && t < 200);
    keys.push({ key: k, type, value, status: 'unused', note: '手动补货', group, createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 });
    generated.push(k);
  }
  if (generated.length) saveKeys(keys);
  auditLog.record('auto_stock_manual', { generated: generated.length }, 'admin', 'local');
  res.json({ code: 200, message: `已生成 ${generated.length} 张`, generated: generated.length });
});

// ─── 磁盘空间监控 ───────────────────────────────────────────────────────────
app.get('/admin/system/disk', adminAuth, (req, res) => {
  try {
    const items = [];
    const dataFiles = ['config.json', 'keys.json', 'logs.json'];
    let totalSize = 0;
    for (const name of dataFiles) {
      const p = path.join(DATA_DIR, name);
      if (fs.existsSync(p)) {
        const st = fs.statSync(p);
        items.push({ name, size: st.size, mtime: st.mtimeMs });
        totalSize += st.size;
      }
    }
    // 归档日志
    const archives = fs.readdirSync(DATA_DIR).filter(f => /^logs-\d{4}-\d{2}-\d{2}\.json$/.test(f));
    let archiveSize = 0;
    archives.forEach(f => { try { archiveSize += fs.statSync(path.join(DATA_DIR, f)).size; } catch {} });
    // 备份
    const backupDir = path.join(DATA_DIR, 'backups');
    let backupCount = 0, backupSize = 0;
    if (fs.existsSync(backupDir)) {
      const files = fs.readdirSync(backupDir);
      backupCount = files.length;
      files.forEach(f => { try { backupSize += fs.statSync(path.join(backupDir, f)).size; } catch {} });
    }
    res.json({
      code: 200,
      data: {
        dataFiles: items,
        totalSize,
        archives: { count: archives.length, size: archiveSize },
        backups: { count: backupCount, size: backupSize },
        grandTotal: totalSize + archiveSize + backupSize
      }
    });
  } catch (err) {
    res.status(500).json({ code: 500, message: '读取磁盘信息失败', error: err.message });
  }
});

// ─── Admin: Backup / Restore ──────────────────────────────────────────────────
app.get('/admin/backup', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const keys = loadKeys();
  const backup = {
    version: '2.1.0',
    exportedAt: Date.now(),
    config: { ...cfg, adminToken: null },
    keys,
    logs: reqLogs.slice(0, 200)
  };
  res.setHeader('Content-Disposition', `attachment; filename="cardkey-backup-${Date.now()}.json"`);
  res.json(backup);
});

app.post('/admin/restore', adminAuth, (req, res) => {
  const { config, keys, overwrite = false } = req.body || {};
  const results = [];

  if (keys && Array.isArray(keys)) {
    if (overwrite) {
      saveKeys(keys);
      results.push(`卡密已全量恢复 ${keys.length} 条`);
    } else {
      const existing = loadKeys();
      const existingSet = new Set(existing.map(k => k.key));
      const toAdd = keys.filter(k => !existingSet.has(k.key));
      saveKeys([...existing, ...toAdd]);
      results.push(`新增卡密 ${toAdd.length} 条，跳过重复 ${keys.length - toAdd.length} 条`);
    }
  }

  if (config) {
    const cfg = loadConfig();
    if (config.apps) { cfg.apps = config.apps; results.push(`应用 ${config.apps.length} 个`); }
    if (config.blacklist) { cfg.blacklist = config.blacklist; results.push(`卡密黑名单 ${config.blacklist.length} 条`); }
    if (config.ipBlacklist) { cfg.ipBlacklist = config.ipBlacklist; results.push(`IP黑名单 ${config.ipBlacklist.length} 条`); }
    if (config.rateLimitPerMin) cfg.rateLimitPerMin = config.rateLimitPerMin;
    if (config.globalRequireSign !== undefined) cfg.globalRequireSign = config.globalRequireSign;
    saveConfig(cfg);
  }

  res.json({ code: 200, message: '数据恢复成功：' + results.join('，') });
});

// ─── Client API ───────────────────────────────────────────────────────────────
app.get('/api/verify', rateLimiter, clientAuth, (req, res) => {
  const key = req.query.key;
  const device_id = req.query.device_id || '';
  if (!key) { logAfter(req, 400, '缺少key参数'); return res.json({ code: 400, message: '缺少 key 参数', valid: false }); }

  const keys = loadKeys();
  const obj = keys.find(k => k.key === key);
  if (!obj) { logAfter(req, 404, '卡密不存在'); return res.json({ code: 404, message: '卡密不存在', valid: false }); }

  const st = keyStatus(obj);
  if (st === 'unused') {
    logAfter(req, 200, '未激活');
    return res.json({ code: 200, message: '卡密有效（未激活）', valid: true, status: 'unused', keyInfo: { type: obj.type, value: obj.value } });
  }
  if (st === 'expired') {
    logAfter(req, 403, '已过期');
    return res.json({ code: 403, message: obj.type === 'times' ? '使用次数已耗尽' : '卡密已过期', valid: false, status: 'expired' });
  }
  if (obj.deviceId && device_id && obj.deviceId !== device_id) {
    logAfter(req, 403, '设备不匹配');
    return res.json({ code: 403, message: '设备绑定验证失败', valid: false, status: 'device_mismatch' });
  }

  const remaining = obj.type === 'times'
    ? obj.value - obj.usedCount
    : obj.expireTime ? Math.max(0, Math.ceil((obj.expireTime - Date.now()) / 86400000)) : null;

  logAfter(req, 200, '验证成功');
  res.json({ code: 200, message: '卡密有效', valid: true, status: 'active', data: { type: obj.type, value: obj.value, usedCount: obj.usedCount, expireTime: obj.expireTime, activatedAt: obj.activatedAt, remaining }, keyInfo: { type: obj.type, value: obj.value, usedCount: obj.usedCount, expireTime: obj.expireTime, activatedAt: obj.activatedAt, remaining } });
});

app.post('/api/activate', rateLimiter, clientAuth, (req, res) => {
  const { key, device_id } = req.body || {};
  const appid = req._clientAppid;
  if (!key) { logAfter(req, 400, '缺少key参数'); return res.json({ code: 400, message: '缺少 key 参数', success: false }); }

  const keys = loadKeys();
  const idx = keys.findIndex(k => k.key === key);
  if (idx === -1) { logAfter(req, 404, '卡密不存在'); return res.json({ code: 404, message: '卡密不存在', success: false }); }
  if (keys[idx].status !== 'unused') { logAfter(req, 400, '已被使用'); return res.json({ code: 400, message: '卡密已被使用或已过期', success: false }); }

  const now = Date.now();
  keys[idx] = { ...keys[idx], status: 'used', activatedAt: now, deviceId: device_id || null, appId: appid || null, usedCount: 1, expireTime: keys[idx].type === 'days' ? now + keys[idx].value * 86400000 : null };
  saveKeys(keys);

  logAfter(req, 200, '激活成功');
  broadcastEvent('keyActivated', { key, appid, deviceId: device_id }, true);
  webhookManager.trigger('keyActivated', { key, appid, deviceId: device_id, expireTime: keys[idx].expireTime, type: keys[idx].type });
  res.json({ code: 200, message: '激活成功', success: true, data: { type: keys[idx].type, value: keys[idx].value, activatedAt: now, expireTime: keys[idx].expireTime } });
});

app.post('/api/use', rateLimiter, clientAuth, (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key) { logAfter(req, 400, '缺少key参数'); return res.json({ code: 400, message: '缺少 key 参数', success: false }); }

  const keys = loadKeys();
  const idx = keys.findIndex(k => k.key === key);
  if (idx === -1) { logAfter(req, 404, '卡密不存在'); return res.json({ code: 404, message: '卡密不存在', success: false }); }

  const st = keyStatus(keys[idx]);
  if (st !== 'active') { logAfter(req, 403, st === 'unused' ? '未激活' : '已过期'); return res.json({ code: 403, message: st === 'unused' ? '卡密未激活' : '卡密已过期或次数耗尽', success: false }); }
  if (keys[idx].deviceId && device_id && keys[idx].deviceId !== device_id) {
    logAfter(req, 403, '设备不匹配');
    return res.json({ code: 403, message: '设备绑定验证失败', success: false });
  }

  if (keys[idx].type === 'times') keys[idx].usedCount++;
  saveKeys(keys);

  const remaining = keys[idx].type === 'times' ? keys[idx].value - keys[idx].usedCount : null;
  logAfter(req, 200, '使用成功');
  broadcastEvent('keyUsed', { key, remaining }, true);
  webhookManager.trigger('keyUsed', { key, appid: keys[idx].appId, remaining, usedCount: keys[idx].usedCount });
  res.json({ code: 200, message: '验证成功', success: true, remaining });
});

// 心跳接口：定期验证 session 存活，返回最新卡密状态
// ─── 在线客户端追踪 ────────────────────────────────────────────────────────
// key -> { key, deviceId, appid, ip, firstSeen, lastSeen, heartbeats }
const _onlineClients = new Map();
const ONLINE_THRESHOLD_MS = 120000; // 2 分钟内有心跳视为在线

function trackClient(key, deviceId, appid, ip) {
  if (!key) return;
  const id = `${key}::${deviceId || '-'}`;
  const now = Date.now();
  let c = _onlineClients.get(id);
  if (!c) {
    c = { key, deviceId: deviceId || null, appid: appid || null, ip, firstSeen: now, lastSeen: now, heartbeats: 0 };
    _onlineClients.set(id, c);
    statsCache.invalidate();
    broadcastEvent('clientOnline', { key, deviceId: c.deviceId, appid: c.appid, ip, onlineCount: countOnlineClients() }, true);
    broadcastEvent('statsUpdated', computeKeyStats(), true);
  } else {
    c.lastSeen = now;
    c.ip = ip;
    c.appid = appid || c.appid;
  }
  c.heartbeats++;
  if (_onlineClients.size > 5000) cleanupOnlineClients();
}

function cleanupOnlineClients() {
  const cutoff = Date.now() - ONLINE_THRESHOLD_MS * 5;
  let removed = 0;
  for (const [id, c] of _onlineClients.entries()) {
    if (c.lastSeen < cutoff) { _onlineClients.delete(id); removed++; }
  }
  if (removed > 0) {
    statsCache.invalidate();
    broadcastEvent('clientOfflineSweep', { removed, onlineCount: countOnlineClients() }, true);
    broadcastEvent('statsUpdated', computeKeyStats(), true);
  }
}

function countOnlineClients() {
  const cutoff = Date.now() - ONLINE_THRESHOLD_MS;
  let n = 0;
  for (const c of _onlineClients.values()) if (c.lastSeen >= cutoff) n++;
  return n;
}

app.post('/api/heartbeat', rateLimiter, clientAuth, (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key) return res.json({ code: 400, message: '缺少 key 参数', alive: false });

  const keys = loadKeys();
  const obj = keys.find(k => k.key === key);
  if (!obj) return res.json({ code: 404, message: '卡密不存在', alive: false });

  const st = keyStatus(obj);
  if (st === 'expired') return res.json({ code: 403, message: '卡密已过期', alive: false, status: 'expired' });
  if (obj.deviceId && device_id && obj.deviceId !== device_id)
    return res.json({ code: 403, message: '设备验证失败', alive: false, status: 'device_mismatch' });

  // 记录在线客户端
  trackClient(key, device_id || obj.deviceId, req._clientAppid || obj.appId, req._clientIp);

  const remaining = obj.type === 'times'
    ? obj.value - obj.usedCount
    : obj.expireTime ? Math.max(0, Math.ceil((obj.expireTime - Date.now()) / 86400000)) : null;
  const remainingMs = obj.type === 'days' && obj.expireTime ? Math.max(0, obj.expireTime - Date.now()) : null;

  res.json({ code: 200, alive: true, status: st, data: {
    type: obj.type, value: obj.value, usedCount: obj.usedCount,
    expireTime: obj.expireTime, activatedAt: obj.activatedAt,
    remaining, remainingMs, deviceId: obj.deviceId, appId: obj.appId, note: obj.note, group: obj.group
  }});
});

// 管理员查看在线客户端
app.get('/admin/online-clients', adminAuth, (req, res) => {
  const now = Date.now();
  const list = [];
  const cutoff = now - ONLINE_THRESHOLD_MS;
  for (const c of _onlineClients.values()) {
    list.push({
      key: c.key,
      deviceId: c.deviceId,
      appid: c.appid,
      ip: c.ip,
      firstSeen: c.firstSeen,
      lastSeen: c.lastSeen,
      heartbeats: c.heartbeats,
      online: c.lastSeen >= cutoff,
      idleSeconds: Math.floor((now - c.lastSeen) / 1000)
    });
  }
  list.sort((a, b) => b.lastSeen - a.lastSeen);
  res.json({ code: 200, data: list, total: list.length, online: list.filter(x => x.online).length });
});

// 清空在线客户端记录
app.delete('/admin/online-clients', adminAuth, (req, res) => {
  const before = _onlineClients.size;
  _onlineClients.clear();
  statsCache.invalidate();
  broadcastEvent('onlineCleared', { removed: before, onlineCount: 0 }, true);
  broadcastEvent('statsUpdated', computeKeyStats(), true);
  res.json({ code: 200, message: `已清空 ${before} 条在线记录` });
});

// 公告接口：返回系统公告信息
app.get('/api/announcement', rateLimiter, (req, res) => {
  const cfg = loadConfig();
  res.json({ code: 200, announcement: cfg.announcement || null, version: SERVER_VERSION, serverTime: Date.now() });
});

// 管理员设置公告（服务端做 XSS 过滤与长度限制）
function sanitizeAnnouncement(raw) {
  if (!raw) return '';
  let s = String(raw).slice(0, 500);
  // 剥离 <script> / <iframe> / on* 属性 / javascript: 协议
  s = s.replace(/<\s*\/?\s*(script|iframe|object|embed|link|meta|style)\b[^>]*>/gi, '');
  s = s.replace(/\son\w+\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+)/gi, '');
  s = s.replace(/javascript\s*:/gi, '');
  return s;
}
app.post('/admin/announcement', adminAuth, (req, res) => {
  const { text } = req.body || {};
  const clean = sanitizeAnnouncement(text);
  const cfg = loadConfig();
  cfg.announcement = clean || null;
  saveConfig(cfg);
  broadcastEvent('announcement', { text: cfg.announcement }, false);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('set_announcement', { length: clean.length }, 'admin', ip);
  res.json({ code: 200, message: '公告已更新', data: { text: cfg.announcement } });
});

// 密码强度评估（本地计算，不需要登录）
function scorePassword(pwd) {
  if (!pwd || typeof pwd !== 'string') return { score: 0, level: 'none', tips: ['请输入密码'] };
  const tips = [];
  let score = 0;
  if (pwd.length >= 8) score += 20; else tips.push('长度至少 8 位');
  if (pwd.length >= 12) score += 10;
  if (/[a-z]/.test(pwd)) score += 15; else tips.push('建议包含小写字母');
  if (/[A-Z]/.test(pwd)) score += 15; else tips.push('建议包含大写字母');
  if (/[0-9]/.test(pwd)) score += 15; else tips.push('建议包含数字');
  if (/[^A-Za-z0-9]/.test(pwd)) score += 20; else tips.push('建议包含特殊字符');
  if (/(.)\1\1/.test(pwd)) { score -= 10; tips.push('避免重复字符'); }
  if (['admin123', 'password', '12345678', 'qwerty123', 'admin', 'root'].includes(pwd.toLowerCase())) {
    score = Math.min(score, 10); tips.push('不要使用常见弱密码');
  }
  score = Math.max(0, Math.min(100, score));
  let level = 'weak';
  if (score >= 80) level = 'strong';
  else if (score >= 55) level = 'medium';
  return { score, level, tips: tips.slice(0, 4) };
}

app.post('/admin/password/strength', adminAuth, (req, res) => {
  const { password } = req.body || {};
  res.json({ code: 200, data: scorePassword(password) });
});

// 安全审计：默认密码/无签名应用/缺失功能警示
app.get('/admin/security/audit', adminAuth, (req, res) => {
  const cfg = loadConfig();
  const checks = [];
  // 默认密码检测（支持 scrypt/bcrypt 哈希或明文）
  try {
    const stored = cfg.adminPassword || '';
    const isHashed = stored.startsWith('$2') || stored.startsWith('scrypt:') || stored.startsWith('$argon2');
    const isDefault = !isHashed && stored === 'admin123';
    const level = isDefault ? 'critical' : (isHashed ? 'ok' : 'warn');
    const msg = isDefault ? '仍在使用默认密码 admin123，请立即更改' : (isHashed ? '密码已哈希加密存储' : '密码已自定义（未哈希）');
    checks.push({ name: '管理员密码', level, message: msg });
  } catch {
    checks.push({ name: '管理员密码', level: 'ok', message: '已自定义' });
  }
  // 应用未启用签名
  const unsigned = (cfg.apps || []).filter(a => !a.requireSign && !cfg.globalRequireSign);
  checks.push({ name: 'HMAC 签名', level: unsigned.length > 0 ? 'warn' : 'ok', message: unsigned.length > 0 ? `${unsigned.length} 个应用未启用签名校验` : '所有应用都启用签名' });
  // 速率限制过高
  checks.push({ name: '速率限制', level: (cfg.rateLimitPerMin || 60) > 300 ? 'warn' : 'ok', message: `每分钟 ${cfg.rateLimitPerMin || 60} 次` });
  checks.push({ name: '管理端 Origin 防护', level: 'ok', message: '管理接口和实时通道会拒绝非同源/非本机 Origin' });
  // API 令牌
  const rawTokens = Array.isArray(cfg.apiTokens) ? cfg.apiTokens : [];
  const tokens = rawTokens.map(normalizeApiTokenRecord);
  const plainTokens = rawTokens.filter(t => t && t.token && !t.tokenHash).length;
  const activeWriteTokens = tokens.filter(t => t.enabled !== false && t.scope === 'write' && (!t.expiresAt || t.expiresAt > Date.now())).length;
  const expiredTokens = tokens.filter(t => t.expiresAt && t.expiresAt <= Date.now()).length;
  checks.push({
    name: 'API 令牌存储',
    level: plainTokens > 0 ? 'critical' : 'ok',
    message: plainTokens > 0 ? `${plainTokens} 个令牌仍含明文字段，请重新生成` : `${tokens.length} 个令牌均以哈希摘要存储`
  });
  checks.push({
    name: 'API 写权限令牌',
    level: activeWriteTokens > 5 ? 'warn' : 'ok',
    message: activeWriteTokens > 0 ? `${activeWriteTokens} 个启用中的写权限令牌，${expiredTokens} 个已过期` : `无启用中的写权限令牌，${expiredTokens} 个已过期`
  });
  // Webhook 出站地址
  try {
    const hooks = webhookManager.getWebhooks();
    const invalidHooks = hooks.filter(w => {
      try { webhookManager.validateUrl(w.url); return false; } catch { return true; }
    }).length;
    checks.push({
      name: 'Webhook 出站安全',
      level: invalidHooks > 0 ? 'critical' : 'ok',
      message: invalidHooks > 0 ? `${invalidHooks} 个 Webhook 地址无效或指向私网` : `${hooks.filter(w => w.active !== false).length}/${hooks.length} 个启用，已阻止私网目标`
    });
  } catch {}
  checks.push({ name: '维护模式', level: cfg.maintenanceMode ? 'warn' : 'ok', message: cfg.maintenanceMode ? '维护模式已开启，客户端校验会被暂停' : '维护模式未开启' });
  checks.push({ name: '实时通道', level: 'ok', message: `${adminClients.size} 个管理端连接，事件序号 ${realtimeSeq}` });
  const tasks = typeof taskScheduler.listTasks === 'function' ? taskScheduler.listTasks() : [];
  const failedTasks = tasks.filter(t => t.status === 'error').length;
  checks.push({
    name: '定时任务健康',
    level: failedTasks > 0 ? 'warn' : tasks.length > 0 ? 'ok' : 'warn',
    message: tasks.length > 0 ? `${tasks.filter(t => t.active).length}/${tasks.length} 个任务运行中，${failedTasks} 个最近失败` : '尚未启动定时任务'
  });
  // 会话数
  checks.push({ name: '当前会话数', level: _sessions.size > 10 ? 'warn' : 'ok', message: `${_sessions.size} 个活跃会话` });
  // 备份
  try {
    const backups = backupManager.listBackups();
    const latest = backups[0];
    const ageDays = latest ? Math.floor((Date.now() - latest.timestamp) / 86400000) : 999;
    checks.push({ name: '最近备份', level: ageDays > 30 ? 'critical' : ageDays > 7 ? 'warn' : 'ok', message: latest ? `${ageDays} 天前（${backups.length} 个备份）` : '暂无备份' });
  } catch {}
  const overall = checks.some(c => c.level === 'critical') ? 'critical' : checks.some(c => c.level === 'warn') ? 'warn' : 'ok';
  res.json({ code: 200, data: { overall, checks } });
});

// 批量续期：为多个 days 型卡密延长 N 天
app.post('/admin/keys/bulk-extend', adminAuth, (req, res) => {
  const { keyList, days } = req.body || {};
  const d = parseInt(days);
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  if (!d || d <= 0 || d > 3650) return res.status(400).json({ code: 400, message: '天数必须为 1~3650 之间的正整数' });
  const keys = loadKeys();
  const set = new Set(keyList);
  let extended = 0, skipped = 0;
  const now = Date.now();
  keys.forEach(k => {
    if (!set.has(k.key)) return;
    if (k.type !== 'days' || k.status === 'unused') { skipped++; return; }
    const base = Math.max(k.expireTime || now, now);
    k.expireTime = base + d * 86400000;
    extended++;
  });
  if (extended) saveKeys(keys);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_bulk_extend', { extended, skipped, days: d }, 'admin', ip);
  res.json({ code: 200, message: `已为 ${extended} 个卡密续期 ${d} 天，跳过 ${skipped} 个`, data: { extended, skipped } });
});

// 批量改前缀（仅未激活卡密）
app.post('/admin/keys/bulk-rename-prefix', adminAuth, (req, res) => {
  const { keyList, newPrefix } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  const safe = String(newPrefix || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8);
  if (!safe) return res.status(400).json({ code: 400, message: '前缀无效' });
  const keys = loadKeys();
  const set = new Set(keyList);
  const existing = new Set(keys.map(k => k.key));
  let renamed = 0, skipped = 0;
  keys.forEach(k => {
    if (!set.has(k.key)) return;
    if (k.status !== 'unused') { skipped++; return; }
    const parts = k.key.split('-');
    if (parts.length < 2) { skipped++; return; }
    parts[0] = safe;
    const nk = parts.join('-');
    if (existing.has(nk)) { skipped++; return; }
    existing.delete(k.key);
    existing.add(nk);
    k.key = nk;
    renamed++;
  });
  if (renamed) saveKeys(keys);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_bulk_rename_prefix', { renamed, skipped, newPrefix: safe }, 'admin', ip);
  res.json({ code: 200, message: `已重命名 ${renamed} 个，跳过 ${skipped} 个`, data: { renamed, skipped } });
});

// 批量设置备注
app.post('/admin/keys/bulk-set-note', adminAuth, (req, res) => {
  const { keyList, note } = req.body || {};
  if (!Array.isArray(keyList) || !keyList.length) return res.status(400).json({ code: 400, message: '请提供卡密列表' });
  if (typeof note !== 'string' || note.length > 200) return res.status(400).json({ code: 400, message: '备注必须是 0-200 字符的字符串' });
  const cleanNote = sanitizeTextField(note, 200);
  const keys = loadKeys();
  const set = new Set(keyList);
  let updated = 0;
  keys.forEach(k => { if (set.has(k.key)) { k.note = cleanNote; updated++; } });
  if (updated) saveKeys(keys);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_bulk_set_note', { updated, note: cleanNote }, 'admin', ip);
  res.json({ code: 200, message: `已更新 ${updated} 个备注`, data: { updated } });
});

// 自动清理已过期超过 N 天的卡密
app.post('/admin/keys/auto-cleanup', adminAuth, (req, res) => {
  const days = Math.max(1, Math.min(365, parseInt(req.body?.days) || 30));
  const cutoff = Date.now() - days * 86400000;
  const keys = loadKeys();
  const before = keys.length;
  const kept = keys.filter(k => {
    if (keyStatus(k) !== 'expired') return true;
    if (k.type === 'days' && k.expireTime && k.expireTime < cutoff) return false;
    if (k.type === 'times' && k.activatedAt && k.activatedAt < cutoff) return false;
    return true;
  });
  const removed = before - kept.length;
  if (removed > 0) saveKeys(kept);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_auto_cleanup', { removed, days }, 'admin', ip);
  res.json({ code: 200, message: `已清理 ${removed} 个过期超 ${days} 天的卡密`, data: { removed, remaining: kept.length } });
});

// 卡密续期（管理员操作）
app.post('/admin/keys/:key/extend', adminAuth, (req, res) => {
  const { days } = req.body || {};
  const d = parseInt(days);
  if (!d || d <= 0) return res.status(400).json({ code: 400, message: '请提供有效的续期天数' });

  const keys = loadKeys();
  const idx = keys.findIndex(k => k.key === req.params.key);
  if (idx === -1) return res.status(404).json({ code: 404, message: '卡密不存在' });
  if (keys[idx].type !== 'days') return res.status(400).json({ code: 400, message: '只有天数卡才能续期' });
  if (keys[idx].status === 'unused') return res.status(400).json({ code: 400, message: '未激活的卡密无法续期' });

  const base = Math.max(keys[idx].expireTime || Date.now(), Date.now());
  keys[idx].expireTime = base + d * 86400000;
  saveKeys(keys);
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
  auditLog.record('key_extend', { key: req.params.key, days: d, newExpireTime: keys[idx].expireTime }, 'admin', ip);
  res.json({ code: 200, message: `续期成功，延长 ${d} 天`, data: { key: req.params.key, newExpireTime: keys[idx].expireTime } });
});

// 克隆卡密（创建一份相同类型/值/备注/分组的新未激活卡密）
app.post('/admin/keys/:key/clone', adminAuth, (req, res) => {
  const keys = loadKeys();
  const src = keys.find(k => k.key === req.params.key);
  if (!src) return res.status(404).json({ code: 404, message: '卡密不存在' });
  const prefix = src.key.split('-')[0] || 'KM';
  let newKey, attempts = 0;
  do { newKey = genKey(prefix); attempts++; } while (keys.find(k => k.key === newKey) && attempts < 200);
  const clone = {
    key: newKey, type: src.type, value: src.value, status: 'unused',
    note: src.note ? `[克隆] ${src.note}` : '', group: src.group || '',
    createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0
  };
  keys.push(clone);
  saveKeys(keys);
  const ip = normalizeIp(req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown');
  auditLog.record('key_clone', { source: req.params.key, clone: newKey }, 'admin', ip);
  res.json({ code: 200, message: '克隆成功', data: clone });
});

// 查看单个卡密的请求日志
app.get('/admin/keys/:key/logs', adminAuth, (req, res) => {
  const key = req.params.key;
  const limit = Math.min(parseInt(req.query.limit) || 50, 200);
  const logs = reqLogs.filter(l => l.key === key).slice(0, limit);
  res.json({ code: 200, data: logs, total: logs.length });
});

// 单个卡密详情（供抽屉刷新用）
app.get('/admin/keys/:key', adminAuth, (req, res) => {
  const keys = loadKeys();
  const obj = keys.find(k => k.key === req.params.key);
  if (!obj) return res.status(404).json({ code: 404, message: '卡密不存在' });
  res.json({ code: 200, data: { ...obj, status: keyStatus(obj) } });
});

// 卡密活动时间线：从 reqLogs 里反查该卡密的请求记录
app.get('/admin/keys/:key/timeline', adminAuth, (req, res) => {
  const targetKey = req.params.key;
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 500);
  const items = [];
  for (const l of reqLogs) {
    if (l.key === targetKey) {
      items.push({ t: l.t, ip: l.ip, path: l.p, method: l.m, appid: l.appid, status: l.status, msg: l.msg });
      if (items.length >= limit) break;
    }
  }
  res.json({ code: 200, data: items, total: items.length });
});

// 卡密使用 IP 列表（去重 + 最近访问时间）
app.get('/admin/keys/:key/ips', adminAuth, (req, res) => {
  const targetKey = req.params.key;
  const hours = Math.min(Math.max(parseInt(req.query.hours) || 24 * 30, 1), 24 * 365);
  const cutoff = Date.now() - hours * 3600000;
  const ipStats = new Map();
  for (const l of reqLogs) {
    if (l.key !== targetKey || l.t < cutoff || !l.ip) continue;
    const e = ipStats.get(l.ip) || { ip: l.ip, count: 0, firstSeen: l.t, lastSeen: l.t, statuses: {} };
    e.count++;
    if (l.t < e.firstSeen) e.firstSeen = l.t;
    if (l.t > e.lastSeen) e.lastSeen = l.t;
    e.statuses[l.status] = (e.statuses[l.status] || 0) + 1;
    ipStats.set(l.ip, e);
  }
  const list = Array.from(ipStats.values()).sort((a, b) => b.lastSeen - a.lastSeen);
  res.json({ code: 200, data: list, total: list.length, hours });
});

// 失败原因排行（按 msg 聚合错误状态）
app.get('/admin/analytics/error-reasons', adminAuth, (req, res) => {
  const hours = Math.min(Math.max(parseInt(req.query.hours) || 24, 1), 24 * 30);
  const cutoff = Date.now() - hours * 3600000;
  const reasons = new Map();
  for (const l of reqLogs) {
    if (l.t < cutoff) continue;
    if (!l.status || l.status < 400) continue;
    const key = `${l.status}|${l.msg || '未知'}`;
    const e = reasons.get(key) || { status: l.status, msg: l.msg || '未知', count: 0, sampleIps: new Set() };
    e.count++;
    if (e.sampleIps.size < 5 && l.ip) e.sampleIps.add(l.ip);
    reasons.set(key, e);
  }
  const list = Array.from(reasons.values())
    .sort((a, b) => b.count - a.count)
    .slice(0, 20)
    .map(e => ({ status: e.status, msg: e.msg, count: e.count, sampleIps: Array.from(e.sampleIps) }));
  res.json({ code: 200, data: list, hours });
});

// 请求 IP 排行统计
app.get('/admin/analytics/top-ips', adminAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 10, 50);
  const hours = Math.min(parseInt(req.query.hours) || 24, 24 * 7);
  const cutoff = Date.now() - hours * 3600000;
  const ipStats = {};
  for (const l of reqLogs) {
    if (l.t < cutoff) continue;
    const ip = l.ip || 'unknown';
    if (!ipStats[ip]) ipStats[ip] = { ip, total: 0, success: 0, errors: 0, blocked: 0 };
    ipStats[ip].total++;
    if (l.status === 200) ipStats[ip].success++;
    else if (l.status === 429) ipStats[ip].blocked++;
    else if (l.status >= 400) ipStats[ip].errors++;
  }
  const sorted = Object.values(ipStats).sort((a, b) => b.total - a.total).slice(0, limit);
  res.json({ code: 200, data: sorted, hours });
});

// ─── Start ────────────────────────────────────────────────────────────────────
function buildRealtimeSnapshot() {
  const cfg = loadConfig();
  const keys = loadKeys();
  const alerts = alertEngine.getAlerts();
  const backups = backupManager.listBackups();
  const unsignedApps = (cfg.apps || []).filter(a => !a.requireSign && !cfg.globalRequireSign).length;
  const disabledApps = (cfg.apps || []).filter(a => a.enabled === false).length;
  const criticalAlerts = alerts.filter(a => a.severity === 'critical' && !a.acknowledged).length;
  const securityOverall = criticalAlerts > 0 ? 'critical' : unsignedApps > 0 ? 'warn' : 'ok';

  return {
    version: SERVER_VERSION,
    serverTime: Date.now(),
    stats: computeKeyStats(keys),
    liveMetrics: computeLiveMetrics(),
    recentLogs: reqLogs.slice(0, 10),
    alerts: {
      total: alerts.length,
      critical: criticalAlerts,
      items: alerts.slice(0, 10)
    },
    sessions: { total: _sessions.size },
    apps: {
      total: (cfg.apps || []).length,
      enabled: (cfg.apps || []).filter(a => a.enabled !== false).length,
      disabled: disabledApps,
      unsigned: unsignedApps
    },
    backups: {
      total: backups.length,
      latest: backups[0] || null
    },
    online: {
      total: _onlineClients.size,
      online: countOnlineClients()
    },
    realtime: {
      seq: realtimeSeq,
      connectedAdmins: adminClients.size,
      recentEvents: realtimeHistory.slice(0, 30)
    },
    security: {
      overall: securityOverall,
      unsignedApps,
      disabledApps,
      criticalAlerts
    },
    config: {
      maintenanceMode: !!cfg.maintenanceMode,
      maintenanceMessage: cfg.maintenanceMessage || ''
    }
  };
}

app.get('/admin/realtime/snapshot', adminAuth, (req, res) => {
  res.json({ code: 200, data: buildRealtimeSnapshot() });
});

app.get('/admin/realtime/events', adminAuth, (req, res) => {
  const sinceSeq = parseInt(req.query.sinceSeq) || 0;
  const limit = Math.min(Math.max(parseInt(req.query.limit) || 50, 1), REALTIME_HISTORY_LIMIT);
  const events = realtimeHistory
    .filter(e => !sinceSeq || e.seq > sinceSeq)
    .slice(0, limit);
  res.json({ code: 200, data: events, latestSeq: realtimeSeq });
});

app.get('/admin/tasks/status', adminAuth, (req, res) => {
  const tasks = typeof taskScheduler.listTasks === 'function' ? taskScheduler.listTasks() : [];
  res.json({
    code: 200,
    data: tasks,
    summary: {
      total: tasks.length,
      active: tasks.filter(t => t.active).length,
      running: tasks.filter(t => t.status === 'running').length,
      failed: tasks.filter(t => t.status === 'error').length
    },
    serverTime: Date.now()
  });
});

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

function isAllowedRealtimeOrigin(req) {
  return isAllowedAdminOrigin(req, req.headers.origin);
}

wss.on('connection', (ws, req) => {
  if (!isAllowedRealtimeOrigin(req)) {
    ws.close(1008, 'origin rejected');
    return;
  }
  const ip = req.socket.remoteAddress;
  ws.isAlive = true;

  // Server-side keep-alive ping; clears itself on close/error
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.ping();
    } else {
      clearInterval(pingInterval);
    }
  }, 30000);

  ws.on('pong', () => { ws.isAlive = true; });

  let wsMsgCount = 0;
  let wsMsgWindowStart = Date.now();
  ws.on('message', (message) => {
    try {
      if (message.length > 4096) {
        ws.close(1009, 'message too large');
        return;
      }
      const now = Date.now();
      if (now - wsMsgWindowStart > 60000) {
        wsMsgWindowStart = now;
        wsMsgCount = 0;
      }
      wsMsgCount++;
      if (wsMsgCount > 120) {
        ws.close(1008, 'rate limited');
        return;
      }
      const msg = JSON.parse(message);
      if (msg.type === 'ping') {
        // Respond to client-side ping
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'pong' }));
        return;
      }
      if (msg.type === 'snapshot' && adminClients.has(ws)) {
        sendRealtimeEvent(ws, 'realtimeSnapshot', buildRealtimeSnapshot());
        return;
      }
      if (msg.type === 'events' && adminClients.has(ws)) {
        const sinceSeq = parseInt(msg.sinceSeq) || 0;
        sendRealtimeEvent(ws, 'realtimeEvents', realtimeHistory.filter(e => !sinceSeq || e.seq > sinceSeq).slice(0, 50));
        return;
      }
      if (msg.type === 'auth') {
        const token = msg.token;
        const sess = getSession(token);
        const cfg = loadConfig();
        if (sess || (token && cfg.adminToken && safeEqualString(token, cfg.adminToken))) {
          if (sess) { sess.lastActive = Date.now(); ws._sessionToken = token; }
          adminClients.add(ws);
          allClients.add(ws);
          ws.send(JSON.stringify({ type: 'authOk', message: '认证成功', wsCount: adminClients.size }));
          sendRealtimeEvent(ws, 'realtimeSnapshot', buildRealtimeSnapshot());
          broadcastEvent('wsCountUpdated', { count: adminClients.size }, true);
        } else {
          ws.send(JSON.stringify({ type: 'authFail', message: '认证失败' }));
          ws.close();
        }
      }
    } catch (e) {
      // ignore malformed messages
    }
  });

  ws.on('close', () => {
    clearInterval(pingInterval);
    adminClients.delete(ws);
    allClients.delete(ws);
    broadcastEvent('wsCountUpdated', { count: adminClients.size }, true);
  });

  ws.on('error', () => {
    clearInterval(pingInterval);
    adminClients.delete(ws);
    allClients.delete(ws);
  });
});

// ─── 初始化定时任务（在服务器启动后；Serverless 环境跳过，函数冻结后无意义） ─
if (!IS_SERVERLESS) setTimeout(() => {
  // 每小时自动备份一次
  taskScheduler.schedule('auto-backup', 3600000, async () => {
    try {
      const cfg = loadConfig();
      const keys = loadKeys();
      const backup = await backupManager.createBackup(cfg, keys, reqLogs);
      backupManager.deleteOldBackups(7);
      broadcastEvent('backupCreated', { ...backup, source: 'scheduler' }, true);
      broadcastEvent('systemTaskRan', { task: 'auto-backup', status: 'success', message: `备份创建成功：${backup.filename}`, timestamp: Date.now() }, true);
      console.log(`[Auto Backup] 备份创建成功: ${backup.filename}`);
    } catch (err) {
      broadcastEvent('systemTaskRan', { task: 'auto-backup', status: 'error', message: err.message, timestamp: Date.now() }, true);
      console.error('[Auto Backup] 备份失败:', err.message);
    }
  }, false); // 不立即执行，等待 1 小时后第一次运行

  // 每 30 秒检查一次告警
  taskScheduler.schedule('check-alerts', 30000, () => {
    try {
      const keys = loadKeys();
      const context = {
        keyStats: { unused: keys.filter(k => keyStatus(k) === 'unused').length },
        logs: reqLogs,
        rateLimitTriggered: rlMap.size
      };
      const newAlerts = alertEngine.check(context);
      if (newAlerts.length > 0) {
        broadcastEvent('alerts', newAlerts, true);
      }
    } catch (err) {
      console.error('[Alert Check] 告警检查失败:', err.message);
    }
  }, false);

  // 每 60 秒更新性能指标
  taskScheduler.schedule('update-performance', 60000, () => {
    try {
      performanceMonitor.recordWSConnection(adminClients.size);
    } catch (err) {
      // 忽略
    }
  }, false);

  // 每 5 分钟清理过期的日志文件
  taskScheduler.schedule('cleanup-logs', 300000, () => {
    try {
      const cutoff = Date.now() - 7 * 86400000;
      const files = fs.readdirSync(DATA_DIR);
      let removed = 0;
      files.forEach(f => {
        if (f.match(/^logs-\d{4}-\d{2}-\d{2}\.json$/)) {
          const filePath = path.join(DATA_DIR, f);
          const stats = fs.statSync(filePath);
          if (stats.mtime.getTime() < cutoff) {
            fs.unlinkSync(filePath);
            removed++;
            console.log(`[Cleanup] 删除过期日志文件: ${f}`);
          }
        }
      });
      if (removed > 0) broadcastEvent('systemTaskRan', { task: 'cleanup-logs', status: 'success', message: `清理 ${removed} 个过期日志文件`, timestamp: Date.now() }, true);
    } catch (err) {
      broadcastEvent('systemTaskRan', { task: 'cleanup-logs', status: 'error', message: err.message, timestamp: Date.now() }, true);
      console.error('[Cleanup] 清理失败:', err.message);
    }
  }, false);

  // 每 10 分钟检查即将到期的卡密，实时推送通知
  taskScheduler.schedule('expiry-check', 600000, () => {
    try {
      const keys = loadKeys();
      const now = Date.now();
      const soon1d = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime > now && k.expireTime <= now + 86400000);
      const soon3d = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime > now + 86400000 && k.expireTime <= now + 3 * 86400000);
      const soon7d = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime > now + 3 * 86400000 && k.expireTime <= now + 7 * 86400000);
      if (soon1d.length > 0 || soon3d.length > 0) {
        broadcastEvent('keyExpirySoon', {
          within1d: soon1d.length,
          within3d: soon3d.length,
          within7d: soon7d.length,
          keys1d: soon1d.slice(0, 5).map(k => k.key)
        }, true);
      }
      // 检测本次扫描中刚刚过期的卡密（状态从 active → expired），触发 Webhook
      const justExpired = keys.filter(k => k.type === 'days' && k.expireTime && k.expireTime <= now && k.expireTime > now - 600000 && k.status !== 'unused');
      if (justExpired.length > 0) {
        webhookManager.trigger('keyExpired', {
          count: justExpired.length,
          keys: justExpired.slice(0, 10).map(k => ({ key: k.key, group: k.group, expireTime: k.expireTime }))
        });
        broadcastEvent('keyExpired', { count: justExpired.length, keys: justExpired.slice(0, 5).map(k => k.key) }, true);
      }
    } catch (err) {
      console.error('[Expiry Check] 检查失败:', err.message);
    }
  }, false);

  // 每 3 秒推送实时系统指标（CPU/内存/请求速率/响应时间）
  taskScheduler.schedule('live-metrics-push', 3000, () => {
    try {
      if (adminClients.size === 0) return; // 无订阅者时跳过
      const m = computeLiveMetrics();
      broadcastEvent('liveMetrics', m, true);
    } catch {}
  }, false);

  // 每 10 秒检测高内存/高 CPU 并记录
  taskScheduler.schedule('resource-watchdog', 10000, () => {
    try {
      const m = computeLiveMetrics();
      if (m.heapUsedMB > 0 && m.heapTotalMB > 0) {
        const pct = Math.round(m.heapUsedMB * 100 / m.heapTotalMB);
        if (pct > 90) systemLogger.log('WARN', `堆内存使用率过高 ${pct}%`, { heapUsedMB: m.heapUsedMB, heapTotalMB: m.heapTotalMB });
      }
      if (m.loadAvg[0] > m.cpuCount * 2) {
        systemLogger.log('WARN', `CPU 负载过高 ${m.loadAvg[0]}`, { cpuCount: m.cpuCount });
      }
    } catch {}
  }, false);

  // 每 60 秒清理过期会话
  taskScheduler.schedule('session-cleanup', 60000, () => {
    try { cleanupSessions(); } catch {}
  }, false);

  // 每 60 秒清理离线客户端
  taskScheduler.schedule('online-clients-cleanup', 60000, () => {
    try { cleanupOnlineClients(); } catch {}
  }, false);

  // 每 2 分钟检查自动补货
  taskScheduler.schedule('auto-stock', 120000, () => {
    try {
      const cfg = loadConfig();
      const cur = cfg.autoStock || {};
      if (!cur.enabled) return;
      const keys = loadKeys();
      const unused = keys.filter(k => keyStatus(k) === 'unused').length;
      const threshold = Math.max(1, cur.threshold || 50);
      const refillTo = Math.max(threshold + 1, cur.refillTo || 200);
      if (unused >= threshold) return;
      const needed = Math.min(1000, refillTo - unused);
      const prefix = (String(cur.prefix || 'KM')).replace(/[^A-Za-z0-9]/g, '').toUpperCase().slice(0, 8) || 'KM';
      const type = cur.type === 'times' ? 'times' : 'days';
      const value = Math.max(1, Math.min(100000, parseInt(cur.value) || 30));
      const group = (cur.group || 'auto').toString().slice(0, 50);
      const generated = [];
      for (let i = 0; i < needed; i++) {
        let k, t = 0;
        do { k = genKey(prefix); t++; } while (keys.find(x => x.key === k) && t < 200);
        const obj = { key: k, type, value, status: 'unused', note: '自动补货', group, createdAt: Date.now(), activatedAt: null, expireTime: null, deviceId: null, appId: null, usedCount: 0 };
        keys.push(obj);
        generated.push(obj);
      }
      if (generated.length) {
        saveKeys(keys);
        systemLogger.log('INFO', `自动补货：生成 ${generated.length} 张卡密（库存 ${unused} → ${unused + generated.length}）`);
        auditLog.record('auto_stock', { generated: generated.length, threshold, refillTo, type, value }, 'system', 'local');
        broadcastEvent('autoStockTriggered', { generated: generated.length, threshold, refillTo, unusedBefore: unused }, true);
      }
    } catch (err) {
      systemLogger.log('ERROR', '自动补货失败', { error: err.message });
    }
  }, false);

  console.log('[System] 定时任务已启动');

  // 每 10 秒广播实时流量数据
  taskScheduler.schedule('live-traffic', 10000, () => {
    try {
      const now = Date.now();
      broadcastEvent('liveTraffic', {
        rpm: reqLogs.filter(l => l.t > now - 60000).length,
        r10s: reqLogs.filter(l => l.t > now - 10000).length,
        r5m: reqLogs.filter(l => l.t > now - 300000).length,
        timestamp: now
      }, true);
    } catch {}
  }, true); // 立即执行一次
}, 2000);

// 直接 node server.js 启动监听；被 require（如 Vercel handler）则只导出 app
if (require.main === module && !IS_SERVERLESS) {
  server.listen(PORT, () => {
    const cfg = loadConfig();
    const stored = cfg.adminPassword || '';
    const pwDisplay = (stored.startsWith('scrypt:') || stored.startsWith('$2')) ? '[已哈希加密]' : (stored === 'admin123' ? 'admin123 (请尽快修改!)' : '[自定义]');
    console.log('');
    console.log(`  Card Key Management System  v${SERVER_VERSION} Enhanced`);
    console.log('  ────────────────────────────────────────');
    console.log(`  URL   : http://localhost:${PORT}`);
    console.log(`  Admin : ${pwDisplay}`);
    if (cfg.apps && cfg.apps.length) console.log(`  App   : ${cfg.apps[0].appid}`);
    console.log(`  Features: WebSocket ✓ | Alerts ✓ | Backups ✓ | Analytics ✓ | Live Metrics ✓ | Multi-Session ✓`);
    if (IS_SERVERLESS) console.log('  Mode  : Serverless (定时任务/WebSocket 已禁用)');
    console.log('');
  });
}

module.exports = app;
