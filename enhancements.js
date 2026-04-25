// 卡密管理系统 - 增强功能模块
// 包含：告警系统、备份管理、操作审计、监控

const fs = require('fs');
const path = require('path');

function isPrivateWebhookHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!h) return true;
  if (h === 'localhost' || h === '::1' || h === '0:0:0:0:0:0:0:1') return true;
  if (/^127\./.test(h) || /^10\./.test(h) || /^169\.254\./.test(h)) return true;
  if (/^192\.168\./.test(h)) return true;
  const m = h.match(/^172\.(\d{1,3})\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (h === '0.0.0.0' || h === '::') return true;
  return false;
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. 告警系统
// ═══════════════════════════════════════════════════════════════════════════════

class AlertEngine {
  constructor() {
    this.alerts = [];
    this.alertRules = [
      {
        id: 'low_stock',
        name: '卡密库存不足',
        condition: (context) => context.keyStats.unused < 100,
        severity: 'warning',
        description: '未使用卡密少于 100 张'
      },
      {
        id: 'high_error_rate',
        name: '高错误率',
        condition: (context) => {
          const fiveMinLogs = context.logs.filter(l => l.t > Date.now() - 300000);
          if (fiveMinLogs.length < 10) return false;
          const errorRate = fiveMinLogs.filter(l => l.status >= 400).length / fiveMinLogs.length;
          return errorRate > 0.2; // 超过 20%
        },
        severity: 'critical',
        description: '过去 5 分钟错误率超过 20%'
      },
      {
        id: 'rate_limit_triggered',
        name: '频率限制触发',
        condition: (context) => context.rateLimitTriggered > 5,
        severity: 'info',
        description: '有 IP 触发频率限制'
      }
    ];
  }

  check(context) {
    const newAlerts = [];
    this.alertRules.forEach(rule => {
      if (rule.condition(context)) {
        const existingAlert = this.alerts.find(a => a.id === rule.id);
        if (!existingAlert) {
          const alert = {
            id: rule.id,
            name: rule.name,
            severity: rule.severity,
            description: rule.description,
            timestamp: Date.now(),
            acknowledged: false
          };
          this.alerts.unshift(alert);
          if (this.alerts.length > 100) this.alerts.pop();
          newAlerts.push(alert);
        }
      } else {
        this.alerts = this.alerts.filter(a => a.id !== rule.id);
      }
    });
    return newAlerts;
  }

  getAlerts(severity = null) {
    if (severity) return this.alerts.filter(a => a.severity === severity);
    return this.alerts;
  }

  acknowledgeAlert(alertId) {
    const alert = this.alerts.find(a => a.id === alertId);
    if (alert) alert.acknowledged = true;
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. 备份管理系统
// ═══════════════════════════════════════════════════════════════════════════════

class BackupManager {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.backupDir = path.join(dataDir, 'backups');
    this.ensureBackupDir();
  }

  ensureBackupDir() {
    if (!fs.existsSync(this.backupDir)) {
      fs.mkdirSync(this.backupDir, { recursive: true });
    }
  }

  createBackup(config, keys, logs) {
    const timestamp = Date.now();
    const logsSlice = logs.slice(0, 500);
    const backup = {
      version: '2.2.0',
      exportedAt: timestamp,
      exportedAtISO: new Date(timestamp).toISOString(),
      keysCount: keys.length,
      logsCount: logsSlice.length,
      config: { ...config, adminToken: null },
      keys,
      logs: logsSlice
    };

    const filename = `backup-${timestamp}.json`;
    const backupPath = path.join(this.backupDir, filename);

    return new Promise((resolve, reject) => {
      fs.writeFile(backupPath, JSON.stringify(backup, null, 2), (err) => {
        if (err) reject(err);
        else resolve({
          id: timestamp,
          filename,
          path: backupPath,
          size: JSON.stringify(backup).length,
          timestamp,
          keysCount: keys.length,
          logsCount: logsSlice.length
        });
      });
    });
  }

  listBackups() {
    try {
      const files = fs.readdirSync(this.backupDir)
        .filter(f => f.startsWith('backup-') && f.endsWith('.json'))
        .sort()
        .reverse();

      return files.map(f => {
        const filePath = path.join(this.backupDir, f);
        const stats = fs.statSync(filePath);
        const timestamp = parseInt(f.match(/\d+/)[0]);
        let keysCount = 0, logsCount = 0;
        try {
          // Read only the first 512 bytes to extract metadata without loading the full file
          const buf = Buffer.alloc(512);
          const fd = fs.openSync(filePath, 'r');
          const bytesRead = fs.readSync(fd, buf, 0, 512, 0);
          fs.closeSync(fd);
          const header = buf.slice(0, bytesRead).toString('utf8');
          const km = header.match(/"keysCount"\s*:\s*(\d+)/);
          const lm = header.match(/"logsCount"\s*:\s*(\d+)/);
          if (km) keysCount = parseInt(km[1]);
          if (lm) logsCount = parseInt(lm[1]);
        } catch {}
        return {
          filename: f,
          timestamp,
          date: new Date(timestamp).toISOString(),
          size: stats.size,
          keysCount,
          logsCount
        };
      });
    } catch {
      return [];
    }
  }

  getBackup(filename) {
    const backupPath = path.join(this.backupDir, filename);
    if (!fs.existsSync(backupPath)) return null;
    try {
      return JSON.parse(fs.readFileSync(backupPath, 'utf8'));
    } catch {
      return null;
    }
  }

  deleteOldBackups(keepDays = 7) {
    const cutoff = Date.now() - keepDays * 86400000;
    const files = fs.readdirSync(this.backupDir);

    files.forEach(f => {
      const timestamp = parseInt(f.match(/\d+/)?.[0] || 0);
      if (timestamp < cutoff) {
        fs.unlinkSync(path.join(this.backupDir, f));
      }
    });
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. 操作审计日志
// ═══════════════════════════════════════════════════════════════════════════════

class AuditLog {
  constructor() {
    this.logs = [];
  }

  record(action, details, userId = 'admin', ip = 'local') {
    const entry = {
      timestamp: Date.now(),
      action,
      details,
      userId,
      ip,
      status: 'success'
    };
    this.logs.unshift(entry);
    if (this.logs.length > 1000) this.logs.pop();
    return entry;
  }

  getLogs(filter = {}) {
    let result = this.logs;

    if (filter.action) result = result.filter(l => l.action === filter.action);
    if (filter.userId) result = result.filter(l => l.userId === filter.userId);
    if (filter.startTime) result = result.filter(l => l.timestamp >= filter.startTime);
    if (filter.endTime) result = result.filter(l => l.timestamp <= filter.endTime);

    return result.slice(0, filter.limit || 100);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. 性能监控
// ═══════════════════════════════════════════════════════════════════════════════

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      requests: [],
      wsConnections: 0,
      avgResponseTime: 0
    };
  }

  recordRequest(endpoint, duration, status) {
    this.metrics.requests.push({
      timestamp: Date.now(),
      endpoint,
      duration,
      status
    });

    if (this.metrics.requests.length > 1000) {
      this.metrics.requests.shift();
    }

    this.updateAverages();
  }

  updateAverages() {
    if (this.metrics.requests.length === 0) {
      this.metrics.avgResponseTime = 0;
      return;
    }

    const recentRequests = this.metrics.requests.slice(-100);
    const totalDuration = recentRequests.reduce((sum, r) => sum + r.duration, 0);
    this.metrics.avgResponseTime = Math.round(totalDuration / recentRequests.length);
  }

  recordWSConnection(count) {
    this.metrics.wsConnections = count;
  }

  getMetrics() {
    return {
      avgResponseTime: this.metrics.avgResponseTime,
      wsConnections: this.metrics.wsConnections,
      totalRequests: this.metrics.requests.length,
      uptime: process.uptime(),
      memory: process.memoryUsage()
    };
  }

  getSlowRequests(threshold = 100) {
    return this.metrics.requests
      .filter(r => r.duration > threshold)
      .sort((a, b) => b.duration - a.duration)
      .slice(0, 10);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 5. 定时任务管理
// ═══════════════════════════════════════════════════════════════════════════════

class TaskScheduler {
  constructor() {
    this.tasks = new Map();
    this.metadata = new Map();
  }

  schedule(taskId, interval, callback, immediate = false) {
    if (this.tasks.has(taskId)) {
      this.cancel(taskId);
    }

    const meta = {
      taskId,
      interval,
      createdAt: Date.now(),
      nextRun: Date.now() + interval,
      lastRun: null,
      lastDurationMs: null,
      runCount: 0,
      errorCount: 0,
      status: 'scheduled',
      lastError: null
    };
    this.metadata.set(taskId, meta);

    const run = async () => {
      const started = Date.now();
      meta.status = 'running';
      meta.lastRun = started;
      try {
        await callback();
        meta.status = 'ok';
        meta.lastError = null;
      } catch (err) {
        meta.status = 'error';
        meta.errorCount += 1;
        meta.lastError = err?.message || String(err);
      } finally {
        meta.runCount += 1;
        meta.lastDurationMs = Date.now() - started;
        meta.nextRun = Date.now() + interval;
      }
    };

    if (immediate) Promise.resolve().then(run).catch(() => {});

    const timer = setInterval(() => { run().catch(() => {}); }, interval);
    this.tasks.set(taskId, { timer, run });

    return taskId;
  }

  cancel(taskId) {
    if (this.tasks.has(taskId)) {
      const task = this.tasks.get(taskId);
      clearInterval(task.timer || task);
      this.tasks.delete(taskId);
      const meta = this.metadata.get(taskId);
      if (meta) {
        meta.status = 'cancelled';
        meta.nextRun = null;
      }
      return true;
    }
    return false;
  }

  cancelAll() {
    this.tasks.forEach(task => clearInterval(task.timer || task));
    this.tasks.clear();
    this.metadata.forEach(meta => {
      meta.status = 'cancelled';
      meta.nextRun = null;
    });
  }

  listTasks() {
    return Array.from(this.metadata.values())
      .map(meta => ({ ...meta, active: this.tasks.has(meta.taskId) }))
      .sort((a, b) => a.taskId.localeCompare(b.taskId));
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 6. 数据统计和导出
// ═══════════════════════════════════════════════════════════════════════════════

class DataExporter {
  static toCSV(data, headers) {
    const rows = [headers.join(',')];

    data.forEach(item => {
      const values = headers.map(h => {
        const value = item[h];
        const escaped = String(value)
          .replace(/"/g, '""')
          .replace(/\n/g, ' ');
        return `"${escaped}"`;
      });
      rows.push(values.join(','));
    });

    return rows.join('\n');
  }

  static exportKeys(keys) {
    const headers = ['卡密', '类型', '有效期/次数', '状态', '激活时间', '过期时间', '设备绑定', '备注'];
    const data = keys.map(k => ({
      '卡密': k.key,
      '类型': k.type === 'days' ? '天数卡' : '次数卡',
      '有效期/次数': k.value,
      '状态': k.status,
      '激活时间': k.activatedAt ? new Date(k.activatedAt).toLocaleString('zh-CN') : '—',
      '过期时间': k.expireTime ? new Date(k.expireTime).toLocaleString('zh-CN') : '—',
      '设备绑定': k.deviceId || '—',
      '备注': k.note || '—'
    }));

    return this.toCSV(data, headers);
  }

  static exportLogs(logs) {
    const headers = ['时间', 'IP', '方法', '接口', '卡密', '应用', '状态码', '消息'];
    const data = logs.map(l => ({
      '时间': new Date(l.t).toLocaleString('zh-CN'),
      'IP': l.ip || '—',
      '方法': l.m || '—',
      '接口': l.p || '—',
      '卡密': l.key ? l.key.slice(0, 12) + '…' : '—',
      '应用': l.appid || '—',
      '状态码': l.status || '—',
      '消息': l.msg || '—'
    }));

    return this.toCSV(data, headers);
  }

  static exportStats(stats) {
    const headers = ['指标', '数值'];
    const data = Object.entries(stats).map(([key, value]) => ({
      '指标': key,
      '数值': value
    }));

    return this.toCSV(data, headers);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 7. 高级搜索和筛选
// ═══════════════════════════════════════════════════════════════════════════════

class AdvancedSearch {
  constructor() {
    this.filters = [];
    this.history = [];
  }

  addFilter(name, condition) {
    this.filters.push({ name, condition });
  }

  search(data, conditions) {
    let results = data;

    conditions.forEach(cond => {
      if (cond.type === 'text') {
        results = results.filter(item => {
          const text = JSON.stringify(item).toLowerCase();
          return text.includes(cond.value.toLowerCase());
        });
      } else if (cond.type === 'range') {
        results = results.filter(item => {
          const val = item[cond.field];
          return val >= cond.min && val <= cond.max;
        });
      } else if (cond.type === 'enum') {
        results = results.filter(item => cond.values.includes(item[cond.field]));
      } else if (cond.type === 'date') {
        results = results.filter(item => {
          const date = new Date(item[cond.field]);
          return date >= cond.startDate && date <= cond.endDate;
        });
      }
    });

    this.history.unshift({ conditions, timestamp: Date.now(), resultCount: results.length });
    if (this.history.length > 50) this.history.pop();

    return results;
  }

  getHistory() {
    return this.history.slice(0, 20);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 8. Webhook 通知系统
// ═══════════════════════════════════════════════════════════════════════════════

class WebhookManager {
  constructor() {
    this.webhooks = [];
    this.deliveries = [];
    this.onChange = null;
  }

  validateUrl(url) {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Webhook URL must use http or https');
    if (process.env.ALLOW_PRIVATE_WEBHOOKS !== '1' && isPrivateWebhookHost(parsed.hostname)) {
      throw new Error('Webhook URL cannot target localhost or private network addresses');
    }
    return parsed;
  }

  addWebhook(url, events, active = true) {
    // Validate URL — must be http/https only
    try {
      this.validateUrl(url);
    } catch {
      throw new Error('Webhook URL 无效，必须以 http:// 或 https:// 开头');
    }
    const webhook = {
      id: Date.now().toString(),
      url,
      events,
      active,
      createdAt: Date.now(),
      lastTriggered: null,
      failureCount: 0,
      successCount: 0
    };
    this.webhooks.push(webhook);
    this._changed();
    return webhook;
  }

  _changed() {
    if (typeof this.onChange === 'function') {
      try { this.onChange(this.getState()); } catch {}
    }
  }

  loadState(state = {}) {
    this.webhooks = Array.isArray(state.webhooks) ? state.webhooks.slice(0, 200) : [];
    this.deliveries = Array.isArray(state.deliveries) ? state.deliveries.slice(0, 500) : [];
  }

  getState() {
    return {
      webhooks: this.webhooks.slice(0, 200),
      deliveries: this.deliveries.slice(0, 500)
    };
  }

  async trigger(event, data) {
    const promises = this.webhooks
      .filter(w => w.active && w.events.includes(event))
      .map(w => this._sendWebhook(w, event, data));

    return Promise.all(promises);
  }

  async _sendWebhook(webhook, event, data) {
    const startTime = Date.now();
    try {
      this.validateUrl(webhook.url);
      // 10-second timeout to prevent hanging
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);

      const response = await fetch(webhook.url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event,
          data,
          timestamp: Date.now(),
          webhookId: webhook.id
        }),
        signal: controller.signal
      });
      clearTimeout(timeout);
      const responseTime = Date.now() - startTime;

      webhook.lastTriggered = Date.now();
      webhook.failureCount = 0;
      webhook.successCount = (webhook.successCount || 0) + 1;

      this.deliveries.unshift({
        webhookId: webhook.id,
        event,
        success: response.ok,
        status: response.ok ? 'success' : 'http_error',
        httpStatus: response.status,
        timestamp: Date.now(),
        responseTime
      });
      this._changed();
    } catch (err) {
      webhook.failureCount++;
      const isTimeout = err.name === 'AbortError';

      this.deliveries.unshift({
        webhookId: webhook.id,
        event,
        success: false,
        status: 'failed',
        error: isTimeout ? '请求超时 (10s)' : err.message,
        timestamp: Date.now(),
        responseTime: Date.now() - startTime
      });
      this._changed();
    }

    if (this.deliveries.length > 500) this.deliveries.pop();
  }

  getWebhooks() {
    return this.webhooks;
  }

  deleteWebhook(id) {
    this.webhooks = this.webhooks.filter(w => w.id !== id);
    this._changed();
  }

  getDeliveries(webhookId = null, limit = 50) {
    let results = this.deliveries;
    if (webhookId) results = results.filter(d => d.webhookId === webhookId);
    return results.slice(0, limit);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 9. 设备管理系统
// ═══════════════════════════════════════════════════════════════════════════════

class DeviceManager {
  constructor() {
    this.devices = [];
  }

  registerDevice(deviceId, deviceName, appId) {
    const device = {
      id: deviceId,
      name: deviceName,
      appId,
      registeredAt: Date.now(),
      lastSeen: Date.now(),
      status: 'active',
      boundKeys: [],
      ipAddresses: []
    };
    this.devices.push(device);
    return device;
  }

  getDevicesByApp(appId) {
    return this.devices.filter(d => d.appId === appId);
  }

  getDevicesByKey(keyId) {
    return this.devices.filter(d => d.boundKeys.includes(keyId));
  }

  updateLastSeen(deviceId, ip) {
    const device = this.devices.find(d => d.id === deviceId);
    if (device) {
      device.lastSeen = Date.now();
      if (!device.ipAddresses.includes(ip)) {
        device.ipAddresses.push(ip);
      }
    }
  }

  disableDevice(deviceId) {
    const device = this.devices.find(d => d.id === deviceId);
    if (device) device.status = 'disabled';
  }

  getDeviceStats() {
    return {
      total: this.devices.length,
      active: this.devices.filter(d => d.status === 'active').length,
      disabled: this.devices.filter(d => d.status === 'disabled').length,
      totalBoundKeys: this.devices.reduce((sum, d) => sum + d.boundKeys.length, 0)
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 10. 系统日志管理
// ═══════════════════════════════════════════════════════════════════════════════

class SystemLogger {
  constructor() {
    this.logs = [];
    this.categories = {
      'INFO': 'info',
      'WARN': 'warning',
      'ERROR': 'error',
      'DEBUG': 'debug',
      'SYSTEM': 'system'
    };
  }

  log(category, message, details = {}) {
    const entry = {
      timestamp: Date.now(),
      category,
      message,
      details,
      id: Date.now().toString()
    };
    this.logs.unshift(entry);
    if (this.logs.length > 2000) this.logs.pop();
    return entry;
  }

  getLogs(filter = {}) {
    let results = this.logs;

    if (filter.category) {
      results = results.filter(l => l.category === filter.category);
    }
    if (filter.search) {
      const q = filter.search.toLowerCase();
      results = results.filter(l =>
        l.message.toLowerCase().includes(q) ||
        JSON.stringify(l.details).toLowerCase().includes(q)
      );
    }
    if (filter.startTime) {
      results = results.filter(l => l.timestamp >= filter.startTime);
    }
    if (filter.endTime) {
      results = results.filter(l => l.timestamp <= filter.endTime);
    }

    return results.slice(0, filter.limit || 100);
  }

  getStats() {
    return {
      total: this.logs.length,
      byCategory: Object.keys(this.categories).reduce((acc, cat) => {
        acc[cat] = this.logs.filter(l => l.category === cat).length;
        return acc;
      }, {})
    };
  }

  clearOldLogs(daysOld = 7) {
    const cutoff = Date.now() - daysOld * 86400000;
    this.logs = this.logs.filter(l => l.timestamp > cutoff);
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 11. 批量操作管理
// ═══════════════════════════════════════════════════════════════════════════════

class BulkOperationManager {
  constructor() {
    this.operations = [];
  }

  createOperation(operationId, type, itemCount) {
    const operation = {
      id: operationId,
      type, // 'generate', 'import', 'delete', 'activate'
      itemCount,
      processedCount: 0,
      status: 'processing', // 'processing', 'completed', 'failed'
      startTime: Date.now(),
      endTime: null,
      errors: []
    };
    this.operations.push(operation);
    return operation;
  }

  updateProgress(operationId, processedCount, error = null) {
    const op = this.operations.find(o => o.id === operationId);
    if (op) {
      op.processedCount = processedCount;
      if (error) op.errors.push(error);

      if (processedCount >= op.itemCount) {
        op.status = op.errors.length > 0 ? 'completed_with_errors' : 'completed';
        op.endTime = Date.now();
      }
    }
  }

  getOperation(operationId) {
    return this.operations.find(o => o.id === operationId);
  }

  getProgress(operationId) {
    const op = this.getOperation(operationId);
    if (!op) return null;
    return {
      id: op.id,
      progress: Math.round((op.processedCount / op.itemCount) * 100),
      processed: op.processedCount,
      total: op.itemCount,
      status: op.status,
      errors: op.errors.length
    };
  }
}

// ═══════════════════════════════════════════════════════════════════════════════
// 12. 数据统计增强
// ═══════════════════════════════════════════════════════════════════════════════

class AdvancedStatistics {
  static getKeyUsageStats(keys, logs) {
    const now = Date.now();
    const isExpired = (k) => (k.type === 'days' && k.expireTime && k.expireTime < now) || (k.type === 'times' && k.usedCount >= k.value);
    const computed = (k) => k.status === 'unused' ? 'unused' : (isExpired(k) ? 'expired' : 'active');
    const activeKeys = keys.filter(k => computed(k) === 'active').length;
    const unusedKeys = keys.filter(k => computed(k) === 'unused').length;
    const expiredKeys = keys.filter(k => computed(k) === 'expired').length;
    const totalUsage = logs.filter(l => l.msg === '使用成功').length;
    return {
      totalKeys: keys.length,
      activeKeys,
      unusedKeys,
      expiredKeys,
      totalActivations: logs.filter(l => l.msg === '激活成功').length,
      totalUsage,
      averageUsagePerKey: totalUsage / Math.max(1, keys.length - unusedKeys)
    };
  }

  static getAppUsageStats(logs) {
    const appStats = {};
    logs.forEach(l => {
      if (!appStats[l.appid]) {
        appStats[l.appid] = {
          total: 0,
          success: 0,
          errors: 0,
          lastUsed: 0
        };
      }
      appStats[l.appid].total++;
      if (l.status === 200) appStats[l.appid].success++;
      else if (l.status >= 400) appStats[l.appid].errors++;
      appStats[l.appid].lastUsed = Math.max(appStats[l.appid].lastUsed, l.t);
    });

    return Object.entries(appStats).map(([appid, stats]) => ({
      appid,
      ...stats,
      successRate: (stats.success / stats.total * 100).toFixed(2) + '%'
    }));
  }

  static getDailyTrends(logs, days = 30) {
    const trends = {};
    const now = Date.now();

    for (let i = 0; i < days; i++) {
      const day = new Date(now - i * 86400000).toISOString().split('T')[0];
      trends[day] = {
        requests: 0,
        success: 0,
        errors: 0,
        activations: 0
      };
    }

    logs.forEach(l => {
      const day = new Date(l.t).toISOString().split('T')[0];
      if (trends[day]) {
        trends[day].requests++;
        if (l.status === 200) trends[day].success++;
        else if (l.status >= 400) trends[day].errors++;
        if (l.msg === '激活成功') trends[day].activations++;
      }
    });

    return Object.entries(trends)
      .reverse()
      .map(([date, stats]) => ({ date, ...stats }));
  }
}

module.exports = {
  AlertEngine,
  BackupManager,
  AuditLog,
  PerformanceMonitor,
  TaskScheduler,
  DataExporter,
  AdvancedSearch,
  WebhookManager,
  DeviceManager,
  SystemLogger,
  BulkOperationManager,
  AdvancedStatistics
};
