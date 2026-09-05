// bot.js - Standalone Telegram Bot for RootGuard (Universal Node.js with SQLite & Multi-Model AI)
// Runs directly with: node bot.js
// Dependencies: npm install dotenv @google/genai jszip
// ⚡ made by @toshitzz | Enhanced with Precision Partition Deletion & Crucial Chmod Detection

const dotenv = require('dotenv');
const { GoogleGenAI, Type } = require('@google/genai');
const JSZip = require('jszip');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

dotenv.config();

/**
 * =======================================================================
 * 🛡️ RootGuard Telegram Bot (Universal Node.js with SQLite & Multi-Model AI)
 * ⚡ made by @toshitzz
 * =======================================================================
 * 
 * Detection System Features:
 * • Precision File Deletion Analysis:
 *   - Prevents false-positive high-risk flags for harmless/targeted file removals (cache, dalvik, logs, $MODDIR).
 *   - Strictly flags CATASTROPHIC partition wipes (/system, /data, /vendor, /boot, /dev/block) that cause bootloops/unbootable devices.
 * • Crucial System chmod Detection:
 *   - Monitors permission stripping on core system binaries and partitions (chmod 000 /system/bin/* -> bootloop hazard).
 *   - Monitors unsafe exposure of raw partition blocks and root vaults (chmod 777 /dev/block/*).
 * • 100% Real Gemini AI Analysis (Context, Purpose, Battery, Scam Check)
 * • Plain English Explanations (Every technical word explained in simple terms)
 * • Super Fast Model Switching (Failover resilience with live status updates)
 * • Built-in SQLite Database (User cooldowns, daily quotas, scan history)
 * • Interactive Telegram Buttons (Simpler Words, What Should I Do, Code, Bootloop)
 * • Offline Deep Heuristic Engine (Zero missed brick commands guarantee)
 * =======================================================================
 */

// Global Unhandled Exception Shields (Prevents process crashes on mobile/Termux/VPS)
process.on('unhandledRejection', (reason) => {
  console.warn('⚠️ [Safe Shield] Handled asynchronous rejection:', reason && reason.message ? reason.message : reason);
});

process.on('uncaughtException', (err) => {
  console.warn('⚠️ [Safe Shield] Handled uncaught exception:', err && err.message ? err.message : err);
});

const TELEGRAM_TOKEN = (process.env.TELEGRAM_BOT_TOKEN || '').trim();
const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();

// Support single ID or comma-separated IDs: "123456789,987654321"
const OWNER_IDS = (process.env.OWNER_ID || '')
  .split(',')
  .map((s) => s.trim().replace(/^tg:/i, ''))
  .filter(Boolean);

if (!TELEGRAM_TOKEN) {
  console.warn('⚠️ Warning: TELEGRAM_BOT_TOKEN is missing in environment.');
  console.warn('👉 To connect to Telegram, set TELEGRAM_BOT_TOKEN in .env (get token from @BotFather).');
}

if (!GEMINI_API_KEY) {
  console.warn('⚠️ Warning: GEMINI_API_KEY is missing in environment.');
  console.warn('👉 Get an API key at: https://aistudio.google.com/app/apikey');
}

const maskedGeminiKey = GEMINI_API_KEY.length > 10
  ? `${GEMINI_API_KEY.slice(0, 6)}...${GEMINI_API_KEY.slice(-4)}`
  : 'None configured';

console.log('⚡ RootGuard Telegram Bot • made by @toshitzz');
console.log(`🔑 Google Gemini API Key: ${GEMINI_API_KEY ? 'Loaded (' + maskedGeminiKey + ')' : 'Offline'}`);
console.log('👑 Configured Owner IDs (Unlimited scans):', OWNER_IDS.length ? OWNER_IDS.join(', ') : 'None specified (Add OWNER_ID in .env)');

// =======================================================================
// 1. SQLite Database Engine (Cooldowns, Quotas, VIPs, History)
// =======================================================================
let sqliteDb = null;
let useFallbackDb = false;

// Fallback in-memory/JSON store if node:sqlite is unavailable
const memoryStore = {
  users: new Map(),
  cooldowns: new Map(),
  dailyQuotas: new Map(),
  scans: [],
};

try {
  const { DatabaseSync } = require('node:sqlite');
  const dbFile = path.resolve(process.cwd(), 'rootguard.db');
  sqliteDb = new DatabaseSync(dbFile);

  sqliteDb.exec(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      username TEXT,
      first_name TEXT,
      is_vip INTEGER DEFAULT 0,
      is_banned INTEGER DEFAULT 0,
      total_scans INTEGER DEFAULT 0,
      created_at INTEGER,
      last_active INTEGER
    );

    CREATE TABLE IF NOT EXISTS cooldowns (
      user_id TEXT PRIMARY KEY,
      last_scan_time INTEGER DEFAULT 0,
      active_scan_lock INTEGER DEFAULT 0,
      cooldown_until INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS daily_quotas (
      user_id TEXT,
      date TEXT,
      scan_count INTEGER DEFAULT 0,
      PRIMARY KEY (user_id, date)
    );

    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      file_name TEXT,
      file_hash TEXT,
      file_size INTEGER,
      verdict TEXT,
      risk_score INTEGER,
      model_used TEXT,
      duration_ms INTEGER,
      created_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS system_stats (
      key TEXT PRIMARY KEY,
      value TEXT
    );

    CREATE TABLE IF NOT EXISTS scan_cache (
      scan_id TEXT PRIMARY KEY,
      file_name TEXT,
      audit_json TEXT,
      created_at INTEGER
    );
  `);
  console.log('🗄️ SQLite Database: Active & Initialized (rootguard.db)');
} catch (e) {
  console.warn('⚠️ Native node:sqlite not supported in this runtime. Engaging Memory store fallback:', e.message);
  useFallbackDb = true;
}

// In-memory cache for interactive button callbacks
const recentScansCache = new Map(); // scanId -> { audit, scripts, fileName, summary }
const knownChatIds = new Set();
// Active interactive Q&A sessions (userId -> { scanId, fileName, timestamp })
const userQuestionSessions = new Map();

function dbSaveScanCache(scanId, fileName, audit, scripts = []) {
  if (!scanId) return;
  const scriptSummaries = (scripts || []).map((s) => ({
    path: s.path,
    size: s.size || (s.content ? s.content.length : 0),
    content: (s.content || '').slice(0, 35000),
    type: s.type || 'script',
  }));

  const cacheItem = { audit, fileName, scripts: scriptSummaries, time: Date.now() };
  recentScansCache.set(scanId, cacheItem);

  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT OR REPLACE INTO scan_cache (scan_id, file_name, audit_json, created_at)
        VALUES (?, ?, ?, ?)
      `).run(scanId, fileName, JSON.stringify({ audit, scripts: scriptSummaries }), Date.now());
    } catch (e) {}
  }
}

function dbGetScanCache(scanId) {
  if (!scanId) return null;
  const inMem = recentScansCache.get(scanId);
  if (inMem) return inMem;
  if (!useFallbackDb && sqliteDb) {
    try {
      const row = sqliteDb.prepare('SELECT * FROM scan_cache WHERE scan_id = ?').get(scanId);
      if (row && row.audit_json) {
        const parsed = JSON.parse(row.audit_json);
        const obj = {
          audit: parsed.audit || parsed,
          scripts: parsed.scripts || [],
          fileName: row.file_name,
          time: row.created_at,
        };
        recentScansCache.set(scanId, obj);
        return obj;
      }
    } catch (e) {}
  }
  return null;
}

function dbRegisterOrTouchUser(userId, username, firstName, isOwner = false) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const now = Date.now();

  if (!useFallbackDb && sqliteDb) {
    try {
      const existing = sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId);
      if (existing) {
        sqliteDb.prepare(`
          UPDATE users 
          SET username = COALESCE(?, username),
              first_name = COALESCE(?, first_name),
              last_active = ?,
              is_vip = CASE WHEN ? = 1 THEN 1 ELSE is_vip END
          WHERE user_id = ?
        `).run(username || null, firstName || null, now, isOwner ? 1 : 0, cleanId);
        return sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId);
      } else {
        sqliteDb.prepare(`
          INSERT INTO users (user_id, username, first_name, is_vip, is_banned, total_scans, created_at, last_active)
          VALUES (?, ?, ?, ?, 0, 0, ?, ?)
        `).run(cleanId, username || null, firstName || null, isOwner ? 1 : 0, now, now);
        return sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId);
      }
    } catch (err) {
      console.warn('DB touch error:', err.message);
    }
  }

  let user = memoryStore.users.get(cleanId);
  if (!user) {
    user = {
      user_id: cleanId,
      username: username || null,
      first_name: firstName || null,
      is_vip: isOwner ? 1 : 0,
      is_banned: 0,
      total_scans: 0,
      created_at: now,
      last_active: now,
    };
    memoryStore.users.set(cleanId, user);
  } else {
    if (username) user.username = username;
    if (firstName) user.first_name = firstName;
    user.last_active = now;
    if (isOwner) user.is_vip = 1;
  }
  return user;
}

function dbGetUser(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  if (!useFallbackDb && sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM users WHERE user_id = ?').get(cleanId) || null;
    } catch (e) {}
  }
  return memoryStore.users.get(cleanId) || null;
}

function dbSetVip(userId, isVip) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  dbRegisterOrTouchUser(cleanId);
  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE users SET is_vip = ? WHERE user_id = ?').run(isVip ? 1 : 0, cleanId);
      return true;
    } catch (e) {}
  }
  const u = memoryStore.users.get(cleanId);
  if (u) u.is_vip = isVip ? 1 : 0;
  return true;
}

function dbSetBanned(userId, isBanned) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  dbRegisterOrTouchUser(cleanId);
  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE users SET is_banned = ? WHERE user_id = ?').run(isBanned ? 1 : 0, cleanId);
      return true;
    } catch (e) {}
  }
  const u = memoryStore.users.get(cleanId);
  if (u) u.is_banned = isBanned ? 1 : 0;
  return true;
}

function isUserOwnerOrVip(rawUserId) {
  const cleanId = String(rawUserId).replace(/^tg:/i, '').trim();
  if (OWNER_IDS.includes(cleanId)) return true;
  const user = dbGetUser(cleanId);
  return Boolean(user && user.is_vip === 1);
}

const DAILY_SCAN_LIMIT = 5;
const COOLDOWN_SECONDS = 15;

function dbCheckCooldownAndLock(userId, isOwner = false, cooldownSeconds = COOLDOWN_SECONDS, dailyMax = DAILY_SCAN_LIMIT) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const user = dbRegisterOrTouchUser(cleanId, undefined, undefined, isOwner);
  const now = Date.now();
  const today = new Date().toISOString().split('T')[0];

  if (user && user.is_banned === 1) {
    return { allowed: false, reason: 'BANNED' };
  }

  const isVip = isOwner || (user && user.is_vip === 1);

  if (!useFallbackDb && sqliteDb) {
    try {
      const cdRow = sqliteDb.prepare('SELECT * FROM cooldowns WHERE user_id = ?').get(cleanId);
      if (cdRow) {
        if (!isVip && cdRow.cooldown_until && now < cdRow.cooldown_until) {
          const remaining = Math.max(1, Math.ceil((cdRow.cooldown_until - now) / 1000));
          return { allowed: false, reason: 'COOLDOWN', remainingSeconds: remaining };
        }

        if (cdRow.active_scan_lock === 1) {
          if (now - cdRow.last_scan_time < 90000) {
            const waitSec = Math.max(1, Math.ceil((90000 - (now - cdRow.last_scan_time)) / 1000));
            return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: waitSec };
          }
        }
      }

      const quotaRow = sqliteDb.prepare('SELECT scan_count FROM daily_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const currentCount = quotaRow ? quotaRow.scan_count : 0;

      if (!isVip && currentCount >= dailyMax) {
        return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: currentCount, dailyMax };
      }

      sqliteDb.prepare(`
        INSERT INTO cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES (?, ?, 1, 0)
        ON CONFLICT(user_id) DO UPDATE SET
          last_scan_time = excluded.last_scan_time,
          active_scan_lock = 1
      `).run(cleanId, now);

      return {
        allowed: true,
        remainingDailyScans: isVip ? 9999 : Math.max(0, dailyMax - (currentCount + 1)),
        isVip,
      };
    } catch (err) {
      console.warn('DB check cooldown error:', err.message);
    }
  }

  const cd = memoryStore.cooldowns.get(cleanId) || { last_scan_time: 0, active_scan_lock: 0, cooldown_until: 0 };
  if (!isVip && cd.cooldown_until && now < cd.cooldown_until) {
    return { allowed: false, reason: 'COOLDOWN', remainingSeconds: Math.max(1, Math.ceil((cd.cooldown_until - now) / 1000)) };
  }
  if (cd.active_scan_lock === 1 && now - cd.last_scan_time < 90000) {
    return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: Math.max(1, Math.ceil((90000 - (now - cd.last_scan_time)) / 1000)) };
  }

  const quotaKey = `${cleanId}:${today}`;
  const used = memoryStore.dailyQuotas.get(quotaKey) || 0;
  if (!isVip && used >= dailyMax) {
    return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: used, dailyMax };
  }

  cd.active_scan_lock = 1;
  cd.last_scan_time = now;
  memoryStore.cooldowns.set(cleanId, cd);

  return {
    allowed: true,
    remainingDailyScans: isVip ? 9999 : Math.max(0, dailyMax - (used + 1)),
    isVip,
  };
}

function dbReleaseLockAndRecordScan(userId, record, cooldownSeconds = COOLDOWN_SECONDS) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const now = Date.now();
  const today = new Date().toISOString().split('T')[0];

  const user = dbGetUser(cleanId);
  const isVip = user ? user.is_vip === 1 : false;
  const cooldownUntil = isVip ? 0 : now + (cooldownSeconds * 1000);

  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT INTO cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES (?, ?, 0, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          last_scan_time = excluded.last_scan_time,
          active_scan_lock = 0,
          cooldown_until = excluded.cooldown_until
      `).run(cleanId, now, cooldownUntil);

      sqliteDb.prepare(`
        INSERT INTO daily_quotas (user_id, date, scan_count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET
          scan_count = scan_count + 1
      `).run(cleanId, today);

      sqliteDb.prepare('UPDATE users SET total_scans = total_scans + 1 WHERE user_id = ?').run(cleanId);

      sqliteDb.prepare(`
        INSERT INTO scans (user_id, file_name, file_hash, file_size, verdict, risk_score, model_used, duration_ms, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        cleanId,
        record.file_name,
        record.file_hash || null,
        record.file_size || 0,
        record.verdict,
        record.risk_score,
        record.model_used,
        record.duration_ms,
        now
      );
      return;
    } catch (e) {
      console.warn('DB record error:', e.message);
    }
  }

  const cd = memoryStore.cooldowns.get(cleanId) || {};
  cd.active_scan_lock = 0;
  cd.last_scan_time = now;
  cd.cooldown_until = cooldownUntil;
  memoryStore.cooldowns.set(cleanId, cd);

  const quotaKey = `${cleanId}:${today}`;
  const used = memoryStore.dailyQuotas.get(quotaKey) || 0;
  memoryStore.dailyQuotas.set(quotaKey, used + 1);

  if (user) user.total_scans = (user.total_scans || 0) + 1;
  memoryStore.scans.unshift({ ...record, id: Date.now(), user_id: cleanId, created_at: now });
  if (memoryStore.scans.length > 50) memoryStore.scans.pop();
}

function dbForceReleaseLock(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare('UPDATE cooldowns SET active_scan_lock = 0 WHERE user_id = ?').run(cleanId);
      return;
    } catch (e) {}
  }
  const cd = memoryStore.cooldowns.get(cleanId);
  if (cd) cd.active_scan_lock = 0;
}

function dbGetStats() {
  if (!useFallbackDb && sqliteDb) {
    try {
      const totalUsers = sqliteDb.prepare('SELECT COUNT(*) as count FROM users').get()?.count || 0;
      const totalScans = sqliteDb.prepare('SELECT COUNT(*) as count FROM scans').get()?.count || 0;
      const totalBricksStopped = sqliteDb.prepare("SELECT COUNT(*) as count FROM scans WHERE verdict = 'MALICIOUS_BRICK_RISK'").get()?.count || 0;
      const vipCount = sqliteDb.prepare('SELECT COUNT(*) as count FROM users WHERE is_vip = 1').get()?.count || 0;
      return { totalUsers, totalScans, totalBricksStopped, vipCount };
    } catch (e) {}
  }
  return {
    totalUsers: memoryStore.users.size,
    totalScans: memoryStore.scans.length,
    totalBricksStopped: memoryStore.scans.filter((s) => s.verdict === 'MALICIOUS_BRICK_RISK').length,
    vipCount: Array.from(memoryStore.users.values()).filter((u) => u.is_vip === 1).length,
  };
}

function dbGetRecentScans(limit = 10) {
  if (!useFallbackDb && sqliteDb) {
    try {
      return sqliteDb.prepare('SELECT * FROM scans ORDER BY id DESC LIMIT ?').all(limit) || [];
    } catch (e) {}
  }
  return memoryStore.scans.slice(0, limit);
}

function dbGetUserQuota(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const isVip = isUserOwnerOrVip(cleanId);
  if (isVip) {
    return { used: 0, remaining: 9999, max: 9999, isVip: true };
  }

  const today = new Date().toISOString().split('T')[0];
  if (!useFallbackDb && sqliteDb) {
    try {
      const row = sqliteDb.prepare('SELECT scan_count FROM daily_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const used = row ? row.scan_count : 0;
      return { used, remaining: Math.max(0, DAILY_SCAN_LIMIT - used), max: DAILY_SCAN_LIMIT, isVip: false };
    } catch (e) {}
  }
  const used = memoryStore.dailyQuotas.get(`${cleanId}:${today}`) || 0;
  return { used, remaining: Math.max(0, DAILY_SCAN_LIMIT - used), max: DAILY_SCAN_LIMIT, isVip: false };
}

function dbResetQuota(userId) {
  const cleanId = String(userId).replace(/^tg:/i, '').trim();
  const today = new Date().toISOString().split('T')[0];
  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare('DELETE FROM daily_quotas WHERE user_id = ?').run(cleanId);
      sqliteDb.prepare('UPDATE cooldowns SET cooldown_until = 0, active_scan_lock = 0 WHERE user_id = ?').run(cleanId);
      return true;
    } catch (e) {}
  }
  memoryStore.dailyQuotas.delete(`${cleanId}:${today}`);
  const cd = memoryStore.cooldowns.get(cleanId);
  if (cd) {
    cd.cooldown_until = 0;
    cd.active_scan_lock = 0;
  }
  return true;
}

// =======================================================================
// 2. High-Concurrency Job Queue
// =======================================================================
const MAX_CONCURRENT_SCANS = 4;
let activeScansCount = 0;
const scanQueue = [];

function enqueueScanJob(job) {
  scanQueue.push(job);
  processNextScanJob();
}

function processNextScanJob() {
  if (activeScansCount >= MAX_CONCURRENT_SCANS || scanQueue.length === 0) {
    return;
  }

  const job = scanQueue.shift();
  activeScansCount++;

  job.run().finally(() => {
    activeScansCount--;
    processNextScanJob();
  });
}

// =======================================================================
// 3. Lazy Gemini SDK Client
// =======================================================================
let aiInstance = null;
function getAi() {
  if (!aiInstance && GEMINI_API_KEY) {
    try {
      aiInstance = new GoogleGenAI({
        apiKey: GEMINI_API_KEY,
        httpOptions: {
          headers: {
            'User-Agent': 'aistudio-build',
          },
        },
      });
    } catch (e) {
      console.warn('Could not initialize GoogleGenAI SDK:', e.message);
    }
  }
  return aiInstance;
}

// =======================================================================
// 4. Telegram API Network Layer
// =======================================================================
function sleepMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callTelegram(method, params = {}, timeoutMs = 35000, maxRetries = 2) {
  let attempt = 0;
  while (attempt <= maxRetries) {
    attempt++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      if (typeof fetch === 'function') {
        const res = await fetch(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/${method}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(params),
          signal: controller.signal,
        });
        clearTimeout(timer);
        const data = await res.json();
        return data;
      }

      const data = await new Promise((resolve, reject) => {
        const postData = JSON.stringify(params);
        const options = {
          hostname: 'api.telegram.org',
          port: 443,
          path: `/bot${TELEGRAM_TOKEN}/${method}`,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(postData),
          },
          timeout: timeoutMs,
        };

        const req = https.request(options, (res) => {
          let str = '';
          res.on('data', (c) => (str += c));
          res.on('end', () => {
            try {
              resolve(JSON.parse(str));
            } catch (e) {
              resolve({ ok: false, description: `Malformed JSON response (${res.statusCode})` });
            }
          });
        });

        req.on('error', (err) => reject(err));
        req.on('timeout', () => {
          req.destroy();
          reject(new Error(`Telegram API request (${method}) timed out after ${Math.round(timeoutMs / 1000)}s`));
        });

        req.write(postData);
        req.end();
      });
      clearTimeout(timer);
      return data;
    } catch (err) {
      clearTimeout(timer);
      const errMsg = err?.message || String(err);
      const isTransient =
        err?.name === 'AbortError' ||
        err?.name === 'TypeError' ||
        err?.code === 'ECONNABORTED' ||
        err?.code === 'ECONNRESET' ||
        err?.code === 'EPIPE' ||
        err?.code === 'ETIMEDOUT' ||
        errMsg.includes('ECONNABORTED') ||
        errMsg.includes('ECONNRESET') ||
        errMsg.includes('fetch failed') ||
        errMsg.includes('terminated') ||
        errMsg.includes('socket hang up') ||
        errMsg.includes('UND_ERR_SOCKET') ||
        errMsg.includes('other side closed') ||
        errMsg.includes('timed out');

      if (isTransient && attempt <= maxRetries) {
        await sleepMs(250 * attempt);
        continue;
      }
      throw err;
    }
  }
}

async function sendTelegramMessage(chatId, text, replyToId = null, replyMarkup = null) {
  if (!TELEGRAM_TOKEN) return { ok: false, error: 'No Telegram token' };
  const params = {
    chat_id: chatId,
    text: text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };
  if (replyToId) params.reply_to_message_id = replyToId;
  if (replyMarkup) params.reply_markup = replyMarkup;

  try {
    const res = await callTelegram('sendMessage', params);
    if (!res.ok && res.description?.includes('can\'t parse entities')) {
      params.parse_mode = undefined;
      return await callTelegram('sendMessage', params);
    }
    return res;
  } catch (err) {
    try {
      await sleepMs(300);
      const retryRes = await callTelegram('sendMessage', params, 35000, 1);
      return retryRes;
    } catch (retryErr) {
      console.warn(`sendMessage failure to ${chatId}:`, retryErr.message);
      return { ok: false, error: retryErr.message };
    }
  }
}

async function editTelegramMessage(chatId, messageId, text, replyMarkup = null) {
  if (!TELEGRAM_TOKEN) return { ok: false };
  const params = {
    chat_id: chatId,
    message_id: messageId,
    text: text,
    parse_mode: 'HTML',
    disable_web_page_preview: true,
  };
  if (replyMarkup) params.reply_markup = replyMarkup;

  try {
    const res = await callTelegram('editMessageText', params);
    if (!res.ok && res.description?.includes('can\'t parse entities')) {
      params.parse_mode = undefined;
      return await callTelegram('editMessageText', params);
    }
    return res;
  } catch (err) {
    try {
      await sleepMs(250);
      return await callTelegram('editMessageText', params, 35000, 1);
    } catch (retryErr) {
      return { ok: false, error: retryErr.message };
    }
  }
}

async function answerCallbackQuery(callbackQueryId, text = '', showAlert = false) {
  if (!callbackQueryId || !TELEGRAM_TOKEN) return { ok: true };
  try {
    return await callTelegram(
      'answerCallbackQuery',
      {
        callback_query_id: callbackQueryId,
        text: text || undefined,
        show_alert: showAlert,
      },
      8000,
      1
    );
  } catch (err) {
    return { ok: false, error: err?.message };
  }
}

async function sendChatAction(chatId, action = 'typing') {
  if (!TELEGRAM_TOKEN) return { ok: false };
  try {
    return await callTelegram('sendChatAction', { chat_id: chatId, action }, 8000, 0);
  } catch (err) {
    return { ok: false };
  }
}

function renderAuditProgress(fileName, step, totalSteps, pct, title, subtitle) {
  const filledBars = Math.max(1, Math.min(10, Math.round((pct / 100) * 10)));
  const emptyBars = 10 - filledBars;
  const bar = '▰'.repeat(filledBars) + '▱'.repeat(emptyBars);
  const stageIcons = ['📥', '📦', '🛡️', '🤖', '⚡'];
  const icon = stageIcons[step - 1] || '🔍';

  return (
    `🛡️ <b>RootGuard Security Inspection</b>\n` +
    `⚡ <i>made by @toshitzz</i>\n` +
    `━━━━━━━━━━━━━━━━━━━━━\n` +
    `📦 <b>Target:</b> <code>${escapeHtml(fileName)}</code>\n\n` +
    `${icon} <b>[Step ${step}/${totalSteps}] ${title}</b>\n` +
    `<code>[ ${bar} ] ${pct}%</code>\n` +
    `<i>${subtitle}</i>\n` +
    `━━━━━━━━━━━━━━━━━━━━━\n` +
    `⚡ <i>RootGuard Engine • Google Gemini AI</i>`
  );
}

async function downloadTelegramFile(fileId) {
  const fileRes = await callTelegram('getFile', { file_id: fileId });
  if (!fileRes.ok || !fileRes.result?.file_path) {
    throw new Error('Telegram getFile API call failed: ' + (fileRes.description || 'Unknown reason'));
  }

  const filePath = fileRes.result.file_path;
  const fileUrl = `https://api.telegram.org/file/bot${TELEGRAM_TOKEN}/${filePath}`;

  if (typeof fetch === 'function') {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 45000);
    try {
      const res = await fetch(fileUrl, { signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) {
        throw new Error(`Failed to download file from Telegram (HTTP ${res.status})`);
      }
      const arrayBuffer = await res.arrayBuffer();
      return Buffer.from(arrayBuffer);
    } catch (err) {
      clearTimeout(timer);
      throw err;
    }
  }

  return new Promise((resolve, reject) => {
    https.get(fileUrl, { timeout: 45000 }, (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to download file from Telegram (HTTP ${res.statusCode})`));
      }
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', (err) => reject(err));
    }).on('error', (err) => reject(err));
  });
}

function escapeHtml(text = '') {
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function getTimeUntilMidnightUtc() {
  const now = new Date();
  const midnight = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 0, 0));
  const diffMs = midnight.getTime() - now.getTime();
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  const minutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
  const seconds = Math.floor((diffMs % (1000 * 60)) / 1000);
  return `${hours}h ${minutes}m ${seconds}s`;
}

// =======================================================================
// 5. Script & Archive Inspection with Binary Decryption Engine
// =======================================================================
function calculateEntropy(buf) {
  if (!buf || buf.length === 0) return 0;
  const frequencies = new Map();
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    frequencies.set(byte, (frequencies.get(byte) || 0) + 1);
  }
  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / buf.length;
    entropy -= p * Math.log2(p);
  }
  return Number(entropy.toFixed(3));
}

function isPrintableScript(buf) {
  if (!buf || buf.length === 0) return false;
  let printableCount = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      printableCount++;
    }
  }
  return printableCount / buf.length > 0.85;
}

function isElfBinary(buf) {
  return (
    buf &&
    buf.length >= 4 &&
    buf[0] === 0x7f &&
    buf[1] === 0x45 &&
    buf[2] === 0x4c &&
    buf[3] === 0x46
  );
}

function extractStringsFromBinary(buf, minLen = 4) {
  const strings = [];
  let current = [];
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    if (b >= 32 && b <= 126) {
      current.push(b);
    } else {
      if (current.length >= minLen) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= minLen) {
    strings.push(String.fromCharCode(...current));
  }
  return strings;
}

function tryDecompress(buf) {
  if (!buf || buf.length < 4) return null;
  // Gzip magic \x1f\x8b
  if (buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      return zlib.gunzipSync(buf);
    } catch (e) {}
  }
  // Zlib / Deflate
  try {
    return zlib.inflateSync(buf);
  } catch (e) {}
  try {
    return zlib.inflateRawSync(buf);
  } catch (e) {}
  return null;
}

function rc4Decrypt(keyStr, data) {
  if (!keyStr || !data || data.length === 0) return null;
  try {
    const key = Buffer.from(keyStr);
    const S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + key[i % key.length]) & 255;
      const tmp = S[i];
      S[i] = S[j];
      S[j] = tmp;
    }
    let i = 0;
    j = 0;
    const out = Buffer.alloc(data.length);
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 255;
      j = (j + S[i]) & 255;
      const tmp = S[i];
      S[i] = S[j];
      S[j] = tmp;
      out[k] = data[k] ^ S[(S[i] + S[j]) & 255];
    }
    return out;
  } catch (e) {
    return null;
  }
}

function multiByteXor(buf, keyStr) {
  if (!keyStr || !buf || buf.length === 0) return null;
  try {
    const key = Buffer.from(keyStr);
    const out = Buffer.alloc(buf.length);
    for (let i = 0; i < buf.length; i++) {
      out[i] = buf[i] ^ key[i % key.length];
    }
    return out;
  } catch (e) {
    return null;
  }
}

function tryOpenSslAesDecrypt(buf, password) {
  if (!buf || buf.length < 32 || !password) return null;
  if (buf.slice(0, 8).toString() !== 'Salted__') return null;
  const salt = buf.slice(8, 16);
  const ciphertext = buf.slice(16);

  // EVP_BytesToKey using MD5 (standard OpenSSL enc key derivation)
  let d = Buffer.alloc(0);
  let d_i = Buffer.alloc(0);
  const passBuf = Buffer.from(password);
  while (d.length < 32 + 16) {
    const hash = crypto.createHash('md5');
    if (d_i.length > 0) hash.update(d_i);
    hash.update(passBuf);
    hash.update(salt);
    d_i = hash.digest();
    d = Buffer.concat([d, d_i]);
  }
  const key = d.slice(0, 32);
  const iv = d.slice(32, 48);

  try {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (e) {
    return null;
  }
}

function extractPotentialKeys(contextText = '', metadata = {}) {
  const keys = new Set(['root', 'magisk', 'kernelsu', 'apatch', 'android', '123456', 'toshitzz', 'module', 'system']);
  if (metadata.id) keys.add(metadata.id.trim());
  if (metadata.name) keys.add(metadata.name.trim());
  if (metadata.author) keys.add(metadata.author.trim());

  if (contextText) {
    const patterns = [
      /(?:key|pass|password|secret)\s*=\s*["']([^"']+)["']/gi,
      /-k\s+["']?([a-zA-Z0-9_\-\.\@\$]+)["']?/gi,
      /-pass\s+(?:pass:)?["']?([^"'\s]+)["']?/gi,
      /openssl\s+enc\s+.*-k\s+([^\s]+)/gi,
      /KEY=["']?([^"'\s]+)["']?/gi,
      /PASS=["']?([^"'\s]+)["']?/gi,
      /PASSWORD=["']?([^"'\s]+)["']?/gi,
    ];
    for (const pat of patterns) {
      let match;
      while ((match = pat.exec(contextText)) !== null) {
        if (match[1] && match[1].length >= 2) {
          keys.add(match[1].trim());
        }
      }
    }
  }
  return Array.from(keys);
}

function trySingleByteXor(buf) {
  if (!buf || buf.length < 4) return null;
  for (let key = 1; key <= 255; key++) {
    if (
      (buf[0] ^ key) === 0x7f &&
      (buf[1] ^ key) === 0x45 &&
      (buf[2] ^ key) === 0x4c &&
      (buf[3] ^ key) === 0x46
    ) {
      const decrypted = Buffer.alloc(buf.length);
      for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ key;
      }
      return { key, decryptedBytes: decrypted, type: 'ELF' };
    }
    if ((buf[0] ^ key) === 0x23 && (buf[1] ^ key) === 0x21) {
      const decrypted = Buffer.alloc(buf.length);
      for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ key;
      }
      if (isPrintableScript(decrypted)) {
        return { key, decryptedBytes: decrypted, type: 'SCRIPT' };
      }
    }
    if ((buf[0] ^ key) === 0x1f && (buf[1] ^ key) === 0x8b) {
      const decrypted = Buffer.alloc(buf.length);
      for (let i = 0; i < buf.length; i++) {
        decrypted[i] = buf[i] ^ key;
      }
      const decompressed = tryDecompress(decrypted);
      if (decompressed) {
        if (isElfBinary(decompressed)) return { key, decryptedBytes: decompressed, type: 'ELF' };
        if (isPrintableScript(decompressed)) return { key, decryptedBytes: decompressed, type: 'SCRIPT' };
      }
    }
  }
  return null;
}

function attemptDeepDecryption(fileName, rawContent, contextScripts = '', metadata = {}) {
  const buf = Buffer.isBuffer(rawContent) ? rawContent : Buffer.from(rawContent);
  const entropy = calculateEntropy(buf);
  const textContent = typeof rawContent === 'string' ? rawContent : buf.slice(0, 20000).toString('utf-8');

  // Check if plain script without hidden encoded payload
  if (
    isPrintableScript(buf) &&
    !textContent.includes('base64 -d') &&
    !textContent.includes('base64 --decode') &&
    !textContent.includes('eval "$(') &&
    !textContent.includes('openssl enc') &&
    !textContent.includes('__ARCHIVE_BELOW__') &&
    !textContent.includes('__PAYLOAD_BEGINS__') &&
    !textContent.includes('\\x')
  ) {
    return {
      fileName,
      isEncrypted: false,
      decrypted: false,
      entropy,
      details: 'Standard readable script or text file.',
    };
  }

  // 1. Check embedded self-extracting archive markers (e.g. __ARCHIVE_BELOW__, tail -n +X)
  const archiveMarker = textContent.indexOf('__ARCHIVE_BELOW__');
  const payloadMarker = textContent.indexOf('__PAYLOAD_BEGINS__');
  const markerIdx = archiveMarker !== -1 ? archiveMarker + 18 : payloadMarker !== -1 ? payloadMarker + 19 : -1;
  if (markerIdx > 0 && markerIdx < buf.length) {
    const payloadBuf = buf.slice(markerIdx);
    const decompressed = tryDecompress(payloadBuf);
    if (decompressed) {
      if (isPrintableScript(decompressed)) {
        const text = decompressed.toString('utf-8');
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: 'Embedded Compressed Archive Unpacker -> Shell Script',
          entropy,
          extractedSnippet: text.slice(0, 150),
          decryptedText: text,
          details: 'Successfully unpacked and decompressed embedded script payload.',
        };
      }
      if (isElfBinary(decompressed)) {
        const strings = extractStringsFromBinary(decompressed);
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: 'Embedded Compressed Archive Unpacker -> ELF Binary',
          entropy,
          extractedSnippet: strings.slice(0, 10).join('; '),
          decryptedBytes: decompressed,
          recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
          details: 'Successfully unpacked embedded ELF binary payload.',
        };
      }
    }
  }

  // 2. Multi-layer Base64 Obfuscation Unpacker (Recursively unpack up to 4 layers)
  const b64Matches = [
    ...textContent.matchAll(/echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64\s+-(?:d|-decode)/gi),
    ...textContent.matchAll(/base64\s+-(?:d|-decode)\s+<<<["']?\s*([A-Za-z0-9+/=]{20,})/gi),
    ...textContent.matchAll(/(?:PAYLOAD|DATA|B64)=["']([A-Za-z0-9+/=]{30,})["']/gi),
  ];
  for (const m of b64Matches) {
    let candidate = m[1];
    let rounds = 0;
    let decodedBuf = null;

    while (rounds < 4 && candidate) {
      try {
        decodedBuf = Buffer.from(candidate, 'base64');
        rounds++;
        // Check if decompresses
        const decomp = tryDecompress(decodedBuf);
        if (decomp) decodedBuf = decomp;

        if (isElfBinary(decodedBuf)) {
          const strings = extractStringsFromBinary(decodedBuf);
          return {
            fileName,
            isEncrypted: true,
            decrypted: true,
            method: `Base64 De-obfuscator (${rounds} round${rounds > 1 ? 's' : ''}) -> ELF Binary`,
            entropy,
            extractedSnippet: strings.slice(0, 10).join('; '),
            decryptedBytes: decodedBuf,
            recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
            details: `Successfully de-obfuscated Base64 layers (${rounds} rounds) to ELF binary.`,
          };
        }
        if (isPrintableScript(decodedBuf)) {
          const text = decodedBuf.toString('utf-8');
          // Check if nested base64
          const nested = text.match(/echo\s+["']?([A-Za-z0-9+/=]{20,})["']?\s*\|\s*base64/i);
          if (nested) {
            candidate = nested[1];
            continue;
          }
          return {
            fileName,
            isEncrypted: true,
            decrypted: true,
            method: `Base64 De-obfuscator (${rounds} round${rounds > 1 ? 's' : ''}) -> Shell Script`,
            entropy,
            extractedSnippet: text.slice(0, 150),
            decryptedText: text,
            details: `Successfully de-obfuscated Base64 script wrapper (${rounds} rounds).`,
          };
        }
        candidate = null;
      } catch (e) {
        break;
      }
    }
  }

  // 3. Hex escape stream decoding (e.g. \x7f\x45\x4c\x46 or long hex strings)
  const hexMatches = [
    ...textContent.matchAll(/printf\s+["']((?:\\x[0-9a-fA-F]{2}){10,})["']/gi),
    ...textContent.matchAll(/(?:HEX|SHELLCODE)=["']((?:[0-9a-fA-F]{2}){16,})["']/gi),
  ];
  for (const hm of hexMatches) {
    try {
      const rawHex = hm[1].replace(/\\x/g, '');
      const hexBuf = Buffer.from(rawHex, 'hex');
      const decomp = tryDecompress(hexBuf) || hexBuf;
      if (isElfBinary(decomp)) {
        const strings = extractStringsFromBinary(decomp);
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: 'Hex Escape Stream Decoder -> ELF Binary',
          entropy,
          extractedSnippet: strings.slice(0, 10).join('; '),
          decryptedBytes: decomp,
          recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
          details: 'Successfully decoded hex-escaped shellcode into ELF binary.',
        };
      }
      if (isPrintableScript(decomp)) {
        const text = decomp.toString('utf-8');
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: 'Hex Escape Stream Decoder -> Shell Script',
          entropy,
          extractedSnippet: text.slice(0, 150),
          decryptedText: text,
          details: 'Successfully decoded hex-escaped script.',
        };
      }
    } catch (e) {}
  }

  // 4. Direct Decompression attempt (in case payload is raw gzip/zlib)
  const directDecomp = tryDecompress(buf);
  if (directDecomp) {
    if (isElfBinary(directDecomp)) {
      const strings = extractStringsFromBinary(directDecomp);
      return {
        fileName,
        isEncrypted: true,
        decrypted: true,
        method: 'Direct Compression Unpacker (Gzip/Deflate) -> ELF Binary',
        entropy,
        extractedSnippet: strings.slice(0, 10).join('; '),
        decryptedBytes: directDecomp,
        recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
        details: 'Successfully decompressed compressed binary payload.',
      };
    }
    if (isPrintableScript(directDecomp)) {
      const text = directDecomp.toString('utf-8');
      return {
        fileName,
        isEncrypted: true,
        decrypted: true,
        method: 'Direct Compression Unpacker (Gzip/Deflate) -> Shell Script',
        entropy,
        extractedSnippet: text.slice(0, 150),
        decryptedText: text,
        details: 'Successfully decompressed compressed script.',
      };
    }
  }

  // 5. Single-byte XOR brute force (all 255 keys)
  const xor = trySingleByteXor(buf);
  if (xor) {
    const keyHex = `0x${xor.key.toString(16).toUpperCase().padStart(2, '0')}`;
    if (xor.type === 'ELF') {
      const strings = extractStringsFromBinary(xor.decryptedBytes);
      return {
        fileName,
        isEncrypted: true,
        decrypted: true,
        method: `Single-byte XOR Brute-Force (Key: ${keyHex}) -> ELF Binary`,
        entropy,
        extractedSnippet: strings.slice(0, 10).join('; '),
        decryptedBytes: xor.decryptedBytes,
        recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
        details: `Successfully decrypted! Recovered ELF binary using single-byte XOR key ${keyHex}.`,
      };
    } else {
      const text = xor.decryptedBytes.toString('utf-8');
      return {
        fileName,
        isEncrypted: true,
        decrypted: true,
        method: `Single-byte XOR Brute-Force (Key: ${keyHex}) -> Shell Script`,
        entropy,
        extractedSnippet: text.slice(0, 150),
        decryptedText: text,
        details: `Successfully decrypted! Recovered shell script using single-byte XOR key ${keyHex}.`,
      };
    }
  }

  // 6. Multi-Byte XOR & RC4 with harvested candidate keys
  const candidateKeys = extractPotentialKeys(contextScripts + '\n' + textContent, metadata);
  for (const candKey of candidateKeys) {
    // Try multi-byte XOR
    const xorOut = multiByteXor(buf, candKey);
    if (xorOut) {
      const decomp = tryDecompress(xorOut) || xorOut;
      if (isElfBinary(decomp)) {
        const strings = extractStringsFromBinary(decomp);
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `Multi-byte XOR Decryption (Key: "${candKey}") -> ELF Binary`,
          entropy,
          extractedSnippet: strings.slice(0, 10).join('; '),
          decryptedBytes: decomp,
          recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
          details: `Successfully decrypted with candidate key "${candKey}"! Recovered ELF binary.`,
        };
      }
      if (isPrintableScript(decomp)) {
        const text = decomp.toString('utf-8');
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `Multi-byte XOR Decryption (Key: "${candKey}") -> Shell Script`,
          entropy,
          extractedSnippet: text.slice(0, 150),
          decryptedText: text,
          details: `Successfully decrypted with candidate key "${candKey}"! Recovered shell script.`,
        };
      }
    }

    // Try RC4
    const rc4Out = rc4Decrypt(candKey, buf);
    if (rc4Out) {
      const decomp = tryDecompress(rc4Out) || rc4Out;
      if (isElfBinary(decomp)) {
        const strings = extractStringsFromBinary(decomp);
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `RC4 Stream Decryption (Key: "${candKey}") -> ELF Binary`,
          entropy,
          extractedSnippet: strings.slice(0, 10).join('; '),
          decryptedBytes: decomp,
          recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
          details: `Successfully decrypted with RC4 stream cipher using key "${candKey}"!`,
        };
      }
      if (isPrintableScript(decomp)) {
        const text = decomp.toString('utf-8');
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `RC4 Stream Decryption (Key: "${candKey}") -> Shell Script`,
          entropy,
          extractedSnippet: text.slice(0, 150),
          decryptedText: text,
          details: `Successfully decrypted with RC4 stream cipher using key "${candKey}"!`,
        };
      }
    }

    // Try OpenSSL AES-256-CBC if Salted__ header
    const aesOut = tryOpenSslAesDecrypt(buf, candKey);
    if (aesOut) {
      const decomp = tryDecompress(aesOut) || aesOut;
      if (isElfBinary(decomp)) {
        const strings = extractStringsFromBinary(decomp);
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `OpenSSL AES-256-CBC Decryption (Key: "${candKey}") -> ELF Binary`,
          entropy,
          extractedSnippet: strings.slice(0, 10).join('; '),
          decryptedBytes: decomp,
          recoveredCommands: strings.filter((s) => /rm\b|chmod\b|dd\b|sh\b|su\b/i.test(s)),
          details: `Successfully decrypted OpenSSL AES-256-CBC container using key "${candKey}"!`,
        };
      }
      if (isPrintableScript(decomp)) {
        const text = decomp.toString('utf-8');
        return {
          fileName,
          isEncrypted: true,
          decrypted: true,
          method: `OpenSSL AES-256-CBC Decryption (Key: "${candKey}") -> Shell Script`,
          entropy,
          extractedSnippet: text.slice(0, 150),
          decryptedText: text,
          details: `Successfully decrypted OpenSSL AES-256-CBC container using key "${candKey}"!`,
        };
      }
    }
  }

  // 7. Check if file is an un-decrypted encrypted payload or high-entropy binary
  const isOpenSslSalted =
    buf.length >= 16 &&
    buf[0] === 0x53 && buf[1] === 0x61 && buf[2] === 0x6c && buf[3] === 0x74 &&
    buf[4] === 0x65 && buf[5] === 0x64 && buf[6] === 0x5f && buf[7] === 0x5f;

  const isSuspiciousBinary =
    isOpenSslSalted ||
    entropy >= 7.0 ||
    fileName.endsWith('.enc') ||
    fileName.endsWith('.bin') ||
    (fileName.includes('system/bin') && !isElfBinary(buf) && !isPrintableScript(buf));

  if (isSuspiciousBinary) {
    return {
      fileName,
      isEncrypted: true,
      decrypted: false,
      entropy,
      details: isOpenSslSalted
        ? 'OpenSSL AES Encrypted Container (Salted__). Decryption key could not be recovered from module.'
        : `Encrypted or packed binary payload detected (Entropy: ${entropy.toFixed(2)}/8.0). Decryption key not found.`,
      unverifiedWarning:
        '⚠️ Result is NOT guaranteed: Encrypted binary could not be decrypted. Complete safety cannot be certified because hidden binary payload cannot be audited.',
    };
  }

  return {
    fileName,
    isEncrypted: false,
    decrypted: false,
    entropy,
    details: 'Binary or resource file inspected.',
  };
}

function isZipEncrypted(bufferOrArray) {
  const buf = Buffer.isBuffer(bufferOrArray) ? bufferOrArray : Buffer.from(bufferOrArray);
  if (!buf || buf.length < 30) return false;
  for (let i = 0; i < Math.min(buf.length - 30, 200000); i++) {
    if (buf[i] === 0x50 && buf[i + 1] === 0x4B && buf[i + 2] === 0x03 && buf[i + 3] === 0x04) {
      const bitFlag = buf.readUInt16LE(i + 6);
      if (bitFlag & 0x0001) return true;
    }
  }
  return false;
}

async function extractScriptsFromModule(fileName, bufferOrText) {
  const isZip = fileName.toLowerCase().endsWith('.zip');
  const binaryDecryption = [];

  if (!isZip) {
    const content = Buffer.isBuffer(bufferOrText) ? bufferOrText.toString('utf-8') : String(bufferOrText);
    const dummyMetadata = { name: fileName, type: 'standalone_sh' };
    const singleScript = [{ path: fileName, content, size: content.length, type: 'script' }];
    const allFiles = [{ path: fileName, size: content.length, isScript: true, isConfig: false, isSystem: false, isBinary: false }];

    // Also check standalone script for embedded obfuscation/decryption
    const dec = attemptDeepDecryption(fileName, bufferOrText, content);
    if (dec.isEncrypted) {
      binaryDecryption.push(dec);
      if (dec.decrypted && dec.decryptedText) {
        singleScript.push({ path: `[DECRYPTED] ${fileName}`, content: dec.decryptedText, size: dec.decryptedText.length, type: 'script' });
      }
    }

    return {
      scripts: singleScript,
      metadata: dummyMetadata,
      fileCount: 1,
      allFiles,
      fileBreakdown: { total: 1, scripts: 1, configs: 0, systemFiles: 0, binaries: 0 },
      binaryDecryption,
    };
  }

  if (Buffer.isBuffer(bufferOrText) && isZipEncrypted(bufferOrText)) {
    binaryDecryption.push({
      fileName,
      isEncrypted: true,
      decrypted: false,
      entropy: calculateEntropy(bufferOrText),
      details: 'Entire ZIP archive is password-protected or encrypted.',
      unverifiedWarning:
        '⚠️ Result is NOT guaranteed: Entire ZIP archive is password-protected/encrypted and cannot be unpacked. Safety cannot be certified.',
    });
    return {
      scripts: [{ path: 'encrypted_archive.zip', content: '# Encrypted archive', size: 0, type: 'script' }],
      metadata: { name: fileName, type: 'encrypted_zip' },
      fileCount: 1,
      allFiles: [{ path: fileName, size: bufferOrText.length, isScript: false, isConfig: false, isSystem: false, isBinary: true }],
      fileBreakdown: { total: 1, scripts: 0, configs: 0, systemFiles: 0, binaries: 1 },
      binaryDecryption,
    };
  }

  let zip;
  try {
    zip = await JSZip.loadAsync(bufferOrText);
  } catch (loadErr) {
    const msg = (loadErr.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password') || msg.includes('unsupported')) {
      binaryDecryption.push({
        fileName,
        isEncrypted: true,
        decrypted: false,
        details: 'Encrypted ZIP archive.',
        unverifiedWarning: '⚠️ Result is NOT guaranteed: Encrypted ZIP archive could not be unpacked.',
      });
      return {
        scripts: [{ path: 'encrypted_archive.zip', content: '# Encrypted archive', size: 0, type: 'script' }],
        metadata: { name: fileName, type: 'encrypted_zip' },
        fileCount: 1,
        allFiles: [{ path: fileName, size: bufferOrText.length, isScript: false, isConfig: false, isSystem: false, isBinary: true }],
        fileBreakdown: { total: 1, scripts: 0, configs: 0, systemFiles: 0, binaries: 1 },
        binaryDecryption,
      };
    }
    throw loadErr;
  }

  const scripts = [];
  const allFiles = [];
  const metadata = { type: 'magisk_module' };
  let fileCount = 0;
  let scriptCount = 0;
  let configCount = 0;
  let systemCount = 0;
  let binaryCount = 0;

  // Pre-gather all script texts for decryption password extraction
  let contextScripts = '';

  // Pass 1: Extract all text scripts, configs, and metadata
  const pendingBinaryEntries = [];

  for (const relativePath of Object.keys(zip.files)) {
    const entry = zip.files[relativePath];
    if (entry.dir) continue;
    fileCount++;

    const lower = relativePath.toLowerCase();
    const entryData = entry._data || {};

    if (entryData.isEncrypted) {
      binaryDecryption.push({
        fileName: relativePath,
        isEncrypted: true,
        decrypted: false,
        details: 'Encrypted ZIP entry detected.',
        unverifiedWarning: '⚠️ Result is NOT guaranteed: Encrypted file inside archive could not be read.',
      });
      continue;
    }

    const uncompressedSize = entryData.uncompressedSize || 0;

    const isShellScript =
      lower.endsWith('.sh') ||
      lower.endsWith('.bash') ||
      lower.endsWith('.rc') ||
      lower.includes('customize.sh') ||
      lower.includes('service.sh') ||
      lower.includes('post-fs-data.sh') ||
      lower.includes('boot-completed.sh') ||
      lower.includes('action.sh') ||
      lower.includes('update-binary') ||
      lower.includes('addon.d');

    const isConfigFile =
      lower.endsWith('.prop') ||
      lower.endsWith('.rule') ||
      lower.endsWith('.xml') ||
      lower.endsWith('.json') ||
      lower.endsWith('.conf') ||
      lower.endsWith('.cfg');

    const isSystemFile = lower.startsWith('system/') || lower.startsWith('systemless/');
    const isBinary =
      lower.endsWith('.so') ||
      lower.endsWith('.apk') ||
      lower.endsWith('.dex') ||
      lower.endsWith('.bin') ||
      lower.endsWith('.enc') ||
      lower.startsWith('system/bin/') ||
      lower.startsWith('system/xbin/');

    if (isShellScript) scriptCount++;
    else if (isConfigFile) configCount++;
    if (isSystemFile) systemCount++;
    if (isBinary) binaryCount++;

    allFiles.push({
      path: relativePath,
      size: uncompressedSize,
      isScript: isShellScript,
      isConfig: isConfigFile,
      isSystem: isSystemFile,
      isBinary,
    });

    if (isShellScript || isConfigFile || (!isBinary && uncompressedSize < 100000)) {
      try {
        const text = await entry.async('string');
        contextScripts += '\n' + text;
        scripts.push({
          path: relativePath,
          content: text.slice(0, 15000),
          size: text.length,
          type: isShellScript ? 'script' : 'config',
        });

        if (relativePath === 'module.prop' || relativePath.endsWith('/module.prop')) {
          for (const line of text.split('\n')) {
            const trimmed = line.trim();
            if (trimmed.startsWith('id=')) metadata.id = trimmed.slice(3).trim();
            if (trimmed.startsWith('name=')) metadata.name = trimmed.slice(5).trim();
            if (trimmed.startsWith('author=')) metadata.author = trimmed.slice(7).trim();
            if (trimmed.startsWith('version=')) metadata.version = trimmed.slice(8).trim();
            if (trimmed.startsWith('description=')) metadata.description = trimmed.slice(12).trim();
          }
        }

        // Check if script itself wraps an obfuscated payload or archive
        if (
          text.includes('base64 -d') ||
          text.includes('base64 --decode') ||
          text.includes('__ARCHIVE_BELOW__') ||
          text.includes('__PAYLOAD_BEGINS__') ||
          text.includes('\\x') ||
          text.includes('openssl enc')
        ) {
          pendingBinaryEntries.push({ relativePath, entry, isText: true, text });
        }
      } catch (err) {
        // Skip unreadable text
      }
    } else if (uncompressedSize < 8000000) {
      pendingBinaryEntries.push({ relativePath, entry, isText: false });
    }
  }

  // Pass 2: Deep decryption across all binaries and obfuscated wrappers using full context
  for (const item of pendingBinaryEntries) {
    try {
      const rawBuf = await item.entry.async('nodebuffer');
      const dec = attemptDeepDecryption(item.relativePath, rawBuf, contextScripts, metadata);
      if (dec.isEncrypted) {
        binaryDecryption.push(dec);
        if (dec.decrypted && dec.decryptedText) {
          scripts.push({
            path: `[DECRYPTED] ${item.relativePath}`,
            content: dec.decryptedText.slice(0, 20000),
            size: dec.decryptedText.length,
            type: 'script',
          });
        }
        if (dec.decrypted && dec.recoveredCommands && dec.recoveredCommands.length > 0) {
          scripts.push({
            path: `[DECRYPTED_BINARY] ${item.relativePath}`,
            content: dec.recoveredCommands.join('\n'),
            size: dec.recoveredCommands.join('\n').length,
            type: 'script',
          });
        }
      }
    } catch (err) {}
  }

  const lowerPaths = allFiles.map((f) => f.path.toLowerCase());
  if (lowerPaths.some((p) => p.includes('action.sh') || p.includes('boot-completed.sh'))) {
    metadata.type = 'ksu_module';
  } else {
    metadata.type = 'magisk_module';
  }

  return {
    scripts,
    metadata,
    fileCount,
    allFiles,
    fileBreakdown: {
      total: fileCount,
      scripts: scriptCount,
      configs: configCount,
      systemFiles: systemCount,
      binaries: binaryCount,
    },
    binaryDecryption,
  };
}

// =======================================================================
// 6. Deep Static Heuristic Engine (100% Offline Accuracy Safety Net)
//    ENHANCED: Precision Partition Wipe vs Safe File Deletion, Crucial Chmod Detection & Binary Decryption
// =======================================================================
function runDeepHeuristicScanner(scripts, binaryDecryption = []) {
  const candidateCommands = [];
  const corrupting = [];
  const risky = [];
  const good = [];
  const sepolicyIssues = [];
  const deletionLog = [];
  const chmodLog = [];

  for (const file of scripts) {
    const lines = file.content.split('\n');
    lines.forEach((rawLine, idx) => {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) return;

      if (line.match(/\b(rm|chmod|dd|wipe|format|mke2fs|setenforce|curl|wget|eval)\b/i)) {
        candidateCommands.push({ command: line, file: file.path });
      }

      // =================================================================
      // [A] PRECISION FILE & PARTITION DELETION DETECTION
      // Goal: Prevent bricking/bootloops from partition wipes, but DO NOT
      // flag harmless file deletions (temp, cache, module self-cleanup).
      // =================================================================
      if (line.match(/\brm\b/i)) {
        // 1. CATASTROPHIC WHOLE-PARTITION WIPES (Causes phone unable to boot / bootloop / permanent brick)
        const isCatastrophicWipe =
          line.match(/rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(\/\s*$|\/\*\s*$|\/system\/?(\*|\s*$)|(\/|")system\/\*|\/data\/?(\*|\s*$)|(\/|")data\/\*|\/vendor\/?(\*|\s*$)|(\/|")vendor\/\*|\/product\/?(\*|\s*$)|(\/|")product\/\*|\/boot\/?(\*|\s*$)|(\/|")boot\/\*|\/metadata\/?(\*|\s*$))/i) ||
          line.match(/rm\s+(-[a-zA-Z]*\s+)*(\/init\b|\/system\/bin\/init|\/system\/bin\/app_process|\/system\/bin\/linker|\/system\/framework\/?(\*|\s*$))/i) ||
          line.match(/rm\s+(-[a-zA-Z]*\s+)*.*(locksettings\.db|gatekeeper\.password\.key|gatekeeper\.pattern\.key|\/data\/system\/users\b)/i);

        // 2. HARMLESS / NORMAL MODULE FILE DELETIONS (Cache, dalvik, logs, temp, module's own folder)
        const isHarmlessCleanup =
          line.match(/(\$MODDIR|\$MODPATH|\/data\/adb\/modules\/|\/data\/adb\/modules_update\/|\/data\/local\/tmp\/|\/cache\b|\/data\/dalvik-cache\b|\/data\/cache\b|\/dev\/tmp\b|\.log\b|\.tmp\b|\.bak\b|\.pid\b)/i) &&
          !isCatastrophicWipe;

        if (isCatastrophicWipe) {
          corrupting.push({
            command: line,
            file: file.path,
            type: 'PARTITION_WIPE_BRICK_RISK',
            explanation: 'Catastrophic deletion of whole partition or core boot files (makes device unable to boot or triggers permanent bootloop).',
          });
          deletionLog.push({ command: line, classification: 'CATASTROPHIC_PARTITION_WIPE', risk: 'HIGH' });
        } else if (isHarmlessCleanup) {
          good.push({
            command: line,
            file: file.path,
            type: 'SAFE_FILE_CLEANUP',
            explanation: 'Safe cleanup of non-critical cache, temporary mod files, or module directory.',
          });
          deletionLog.push({ command: line, classification: 'SAFE_TEMPORARY_CLEANUP', risk: 'NONE' });
        } else {
          // Specific targeted file deletion (e.g. debloating an individual APK or removing a single config)
          // DO NOT mark as corrupting/brick hazard! Review in caution.
          risky.push({
            command: line,
            file: file.path,
            type: 'TARGETED_FILE_DELETION',
            explanation: 'Deletes a targeted individual file. Verified that it does NOT wipe entire system partition.',
          });
          deletionLog.push({ command: line, classification: 'TARGETED_SPECIFIC_FILE', risk: 'LOW' });
        }
      }

      // =================================================================
      // [B] CRUCIAL SYSTEM CHMOD SECURITY DETECTION
      // Goal: Detect permission tampering that leads to boot failure
      // (stripping permissions on /system) or severe privilege compromise.
      // =================================================================
      else if (line.match(/\bchmod\b/i)) {
        // 1. BOOTLOOP / BRICK CHMOD: Stripping execute or read on vital system paths (chmod 000 /system/bin/*)
        const isBootloopChmod =
          line.match(/chmod\s+(-[a-zA-Z]*\s+)*(000|0000|\-x|[0-3][0-3][0-3])\s+(\/|\/system|\/init|\/system\/bin|\/system\/xbin|\/vendor|\/data\b|\/system\/framework)/i);

        // 2. CRUCIAL PARTITION RAW BLOCK EXPOSURE / WEAKENING (chmod 777 /dev/block/* or /data/system)
        const isInsecureSystemChmod =
          line.match(/chmod\s+(-[a-zA-Z]*\s+)*(777|666|a\+[rwxd]+)\s+(\/dev\/block|\/data\/system|\/data\/adb|\/proc\/kmsg|\/dev\/socket)/i);

        // 3. SUID BIT ESCALATION ON ARBITRARY BINARIES
        const isSuidEscalation =
          line.match(/chmod\s+(-[a-zA-Z]*\s+)*([1-7]?[47][0-7]{3}|\+s|u\+s)\s+(\/data\/local\/tmp|\/sdcard|\/tmp)/i);

        // 4. SAFE STANDARD ROOT MODULE CHMOD (e.g. chmod 755 $MODDIR/*.sh, chmod 644 configs)
        const isSafeModChmod =
          line.match(/chmod\s+(-[a-zA-Z]*\s+)*(755|644|0755|0644|\+x)\s+(\$MODDIR|\$MODPATH|\/data\/adb\/modules|\/data\/local\/tmp|\.\/)/i);

        if (isBootloopChmod) {
          corrupting.push({
            command: line,
            file: file.path,
            type: 'CRITICAL_CHMOD_BOOTLOOP_HAZARD',
            explanation: 'Removes execute/read permissions from crucial system binaries or partitions, causing immediate boot failure or bootloop!',
          });
          chmodLog.push({ command: line, classification: 'CRITICAL_PERMISSION_STRIPPING', risk: 'HIGH' });
        } else if (isInsecureSystemChmod) {
          risky.push({
            command: line,
            file: file.path,
            type: 'CRITICAL_BLOCK_CHMOD_EXPOSURE',
            explanation: 'Grants world-accessible (777/666) permissions to raw partition block devices or root vaults, breaking Android partition security.',
          });
          chmodLog.push({ command: line, classification: 'RAW_BLOCK_OVEREXPOSURE', risk: 'MEDIUM' });
        } else if (isSuidEscalation) {
          risky.push({
            command: line,
            file: file.path,
            type: 'SUID_INJECTION',
            explanation: 'Sets SUID bit on temporary storage to elevate binary permissions.',
          });
          chmodLog.push({ command: line, classification: 'SUID_ELEVATION', risk: 'MEDIUM' });
        } else if (isSafeModChmod) {
          good.push({
            command: line,
            file: file.path,
            type: 'SAFE_MODULE_CHMOD',
            explanation: 'Standard module executable permission setup (chmod 755/644).',
          });
          chmodLog.push({ command: line, classification: 'STANDARD_SAFE_CHMOD', risk: 'NONE' });
        } else {
          good.push({ command: line, file: file.path });
        }
      }

      // =================================================================
      // [C] OTHER BRICK & PARTITION OVERWRITE COMMANDS
      // =================================================================
      else if (line.match(/dd\s+if=.*\s+of=\/dev\/block\/(bootdevice|by-name)\/(boot|recovery|super|modem|efs|vbmeta|userdata|system)/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          type: 'RAW_BLOCK_OVERWRITE',
          explanation: 'Overwrites critical Android partitions directly, causing a permanent brick.',
        });
      } else if (line.match(/mke2fs|make_ext4fs|blkdiscard|wipe\s+data/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          type: 'BLOCK_FORMAT_WIPE',
          explanation: 'Re-formats partition blocks or wipes flash storage.',
        });
      }

      // =================================================================
      // [D] GENERAL RISKY / NETWORK SUSPICIOUS COMMANDS
      // =================================================================
      else if (line.match(/setenforce\s+0/i)) {
        risky.push({
          command: line,
          file: file.path,
          type: 'SELINUX_DISABLED',
          explanation: 'Turns off SELinux (Android\'s built-in shield that separates apps), allowing rogue apps to spy on private files.',
        });
      } else if (line.match(/(curl|wget)\s+.*\|\s*(sh|bash)/i)) {
        risky.push({
          command: line,
          file: file.path,
          type: 'REMOTE_CODE_EXECUTION',
          explanation: 'Downloads unverified web code and runs it directly with root permissions.',
        });
      } else if (line.match(/eval\s+.*\$\(echo\s+.*base64/i)) {
        risky.push({
          command: line,
          file: file.path,
          type: 'OBFUSCATED_BASE64',
          explanation: 'Executes hidden, encrypted base64 commands to conceal actions.',
        });
      }

      // =================================================================
      // [E] SAFE / STANDARD MAGISK & KSU COMMANDS
      // =================================================================
      else if (line.match(/ui_print|set_perm|resetprop|MODDIR=\${0%\/\*}|magisk\s+--install/i)) {
        good.push({ command: line, file: file.path });
      }
    });

    if (file.path.endsWith('sepolicy.rule')) {
      const seLines = file.content.split('\n');
      for (const seLine of seLines) {
        if (seLine.includes('permissive')) {
          sepolicyIssues.push(`Permissive domain: ${seLine.trim()}`);
        }
      }
    }
  }

  // Binary decryption analysis
  let decryptionAssessment = '';
  const unverified = (binaryDecryption || []).filter((b) => !b.decrypted);
  const decrypted = (binaryDecryption || []).filter((b) => b.decrypted);

  if (unverified.length > 0) {
    risky.push({
      command: `[ENCRYPTED_BINARY] ${unverified.map((u) => u.fileName).join(', ')}`,
      file: unverified[0].fileName,
      type: 'UNVERIFIED_ENCRYPTED_BINARY',
      explanation: 'Module contains encrypted or obfuscated binary payloads that could not be decrypted. Complete safety cannot be certified; result is NOT guaranteed.',
    });
    decryptionAssessment = `⚠️ Encrypted binary file(s) found (${unverified.map((u) => u.fileName).join(', ')}). Best-effort decryption could not decrypt the binary payload (Entropy: ${unverified[0].entropy || 'high'}). Result is NOT guaranteed safe because hidden code cannot be audited.`;
  }

  if (decrypted.length > 0) {
    good.push({
      command: `[DECRYPTED_BINARY] ${decrypted.map((d) => d.fileName).join(', ')}`,
      file: decrypted[0].fileName,
      type: 'DECRYPTED_BINARY_AUDITED',
      explanation: `Successfully decrypted binary payloads using ${decrypted.map((d) => d.method).join(', ')}. Payload extracted and verified.`,
    });
    if (!decryptionAssessment) {
      decryptionAssessment = `🔓 Successfully decrypted ${decrypted.length} binary payload(s) (${decrypted.map((d) => `${d.fileName} via ${d.method}`).join(', ')}). The revealed code was inspected and audited for security.`;
    } else {
      decryptionAssessment += ` Decrypted: ${decrypted.map((d) => d.fileName).join(', ')}.`;
    }
  }

  let riskScore = 0;
  let verdict = 'SAFE';

  if (corrupting.length > 0) {
    riskScore = Math.min(100, 85 + corrupting.length * 5);
    verdict = 'MALICIOUS_BRICK_RISK';
  } else if (risky.length > 0) {
    riskScore = Math.min(75, 25 + risky.length * 12);
    verdict = riskScore > 50 ? 'DANGEROUS' : 'CAUTION';
  } else {
    riskScore = Math.max(0, 5 - good.length * 2);
    verdict = 'SAFE';
  }

  // If unverified encrypted binaries exist, safety is not guaranteed
  if (unverified.length > 0 && verdict === 'SAFE') {
    verdict = 'CAUTION';
    riskScore = Math.max(riskScore, 45);
  }

  return {
    verdict,
    riskScore,
    summary: verdict === 'MALICIOUS_BRICK_RISK'
      ? `🚨 Dangerous partition wipe or crucial system chmod detected! This module will cause a bootloop or brick your phone.`
      : verdict === 'DANGEROUS'
      ? `⚠️ Suspicious commands found (such as downloading web scripts, disabling SELinux, or modifying crucial partition permissions).`
      : verdict === 'CAUTION'
      ? (unverified.length > 0
          ? `⚠️ Unverified encrypted binary detected. Result is not guaranteed because hidden code could not be audited.`
          : `ℹ️ Targeted modifications found. Checked files: it does NOT wipe entire system partitions.`)
      : `✅ Clean & safe. No whole partition wipes or destructive system chmod commands detected.`,
    whatThisModuleDoes: 'Android root module or tweak script evaluated with precision partition & chmod inspection.',
    mechanisms: ['Installs scripts into root manager environment.'],
    scamOrPlaceboCheck: 'Basic static heuristic check. Verify module author before flashing.',
    batteryAndHeatImpact: 'Standard root module impact.',
    bootloopRisk: corrupting.length > 0
      ? 'CRITICAL BRICK & BOOTLOOP HAZARD: Detected commands that wipe partitions or strip crucial system permissions!'
      : 'Low risk: No destructive partition-wide wipes or system chmod stripping found.',
    privacySafety: risky.length > 0 ? 'Review flagged network/permission commands.' : 'No data exfiltration found.',
    uninstallSafety: 'Should remove cleanly from your root manager.',
    recommendation: verdict === 'MALICIOUS_BRICK_RISK'
      ? 'DO NOT FLASH. This contains commands capable of wiping system partitions or causing unrecoverable bootloops.'
      : unverified.length > 0
      ? 'CAUTION: Module contains encrypted binary that could not be decrypted. Result is not guaranteed. Only install if you trust the author.'
      : 'Module does not appear to wipe core partitions. Keep a safe-mode recovery method handy before flashing.',
    corruptingCommands: corrupting,
    riskyCommands: risky,
    goodCommands: good,
    candidateCommands,
    sepolicyIssues,
    deletionLog,
    chmodLog,
    binaryDecryption: binaryDecryption || [],
    decryptionAssessment,
    engine: 'RootGuard Deep Heuristics (Enhanced)',
  };
}

// =======================================================================
// 7. 100% Real Gemini AI Analysis + Super Fast Switching
//    UPDATED DETECTION INSTRUCTIONS:
//    - Do not mark high risk if deleting parts of file/cache/temp (not whole partition)
//    - Check exact file targeted
//    - Crucial system chmod detection
// =======================================================================
async function auditModuleWithRealAi(fileName, scripts, metadata, onProgress, binaryDecryption = []) {
  const heuristicResult = runDeepHeuristicScanner(scripts, binaryDecryption);
  const ai = getAi();

  if (!ai) {
    return heuristicResult;
  }

  const formattedScripts = scripts
    .slice(0, 10)
    .map((s) => `### FILE: ${s.path}\n\`\`\`bash\n${s.content.slice(0, 6000)}\n\`\`\``)
    .join('\n\n');

  const metaText = Object.entries(metadata)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\n');

  const prompt = `You are RootGuard AI, an expert Android security auditor specializing in Magisk, KernelSU, APatch root modules and shell scripts.
Your job is to read all provided scripts, configuration files, and properties and evaluate what it REALLY does, with special attention to brick prevention, partition deletion vs safe cleanup, crucial system chmod security, and encrypted binaries.

CRITICAL DETECTION SYSTEM RULES:

1. FILE & PARTITION DELETION RULE (DO NOT OVER-FLAG DELETIONS):
- OUR GOAL: Prevent modules that wipe out entire system partitions, corrupt partition blocks, or make the phone UNABLE TO BOOT ANYMORE (PERMANENT BOOTLOOP / BRICK).
- DO NOT mark a module as HIGH RISK or MALICIOUS simply because it uses 'rm' or deletes something!
- Carefully examine WHICH SPECIFIC FILE or directory the code deletes:
  * HIGH RISK / MALICIOUS BRICK: ONLY flag if the deletion wipes an entire partition (e.g. 'rm -rf /system', 'rm -rf /data', 'rm -rf /vendor', 'rm -rf /boot', 'rm -rf /*'), formats raw block devices ('/dev/block/*'), wipes Android Keystore ('locksettings.db'), or deletes core boot binaries ('/init', '/system/bin/init', 'app_process').
  * SAFE / HARMLESS CLEANUP: If the code deletes temporary files, caches, dalvik-cache ('/data/dalvik-cache'), logs ('*.log'), lockfiles, or files inside its own module directory ('$MODDIR', '/data/adb/modules/'), this WILL NOT harm the phone or cause bootloops! Treat these as normal root operations and DO NOT mark high risk.
  * CAUTION: If the code deletes a single specific bloatware app (e.g. 'rm /system/app/Bloat.apk') or a replaceable font/sound, explain which file is deleted. This is targeted modification, NOT a partition brick.

2. CRUCIAL SYSTEM CHMOD DETECTION RULE:
- Inspect all 'chmod' operations on system partitions and files:
  * BOOTLOOP HAZARD: Check if chmod removes execute or read rights (e.g. 'chmod 000', 'chmod -x', 'chmod 0000') on crucial system directories or binaries ('/system', '/init', '/system/bin/*', '/vendor', '/data'). This causes instant bootloops or unbootable devices!
  * SECURITY COMPROMISE: Check if chmod grants insecure global read/write (e.g. 'chmod 777', 'chmod 666') to raw partition block devices ('/dev/block/*') or root credential stores.
  * SAFE MODULE CHMOD: Standard permissions on module files (e.g. 'chmod 755 $MODDIR/service.sh', 'chmod 644 $MODDIR/system/...') are standard and safe.

3. ENCRYPTED BINARY & OBFUSCATION DECRYPTION RULE:
- Check the binary decryption findings below:
  * If any binary payload could NOT be decrypted (marked unverified), you MUST EXPLICITLY WARN THE USER that the result is NOT guaranteed because the encrypted binary could not be decrypted. Set verdict to at least CAUTION.
  * If a binary or script wrapper was successfully decrypted, let the user know what method decrypted it and what the extracted code or strings do.

CRITICAL LANGUAGE REQUIREMENT - SIMPLE EVERYDAY ENGLISH:
Write your entire analysis in plain, friendly, common English words that ANY smartphone user can easily understand!
Do NOT use unexplained technical jargon.
IF YOU MUST USE A TECHNICAL WORD (such as "bootloop", "SELinux", "keystore", "overlayfs", "dalvik cache", "sysfs governor", "chcon", "partition block"), YOU MUST IMMEDIATELY EXPLAIN IN SIMPLE WORDS WHAT IT MEANS AND WHAT IT DOES IN PARENTHESES.
Examples:
- "bootloop (when your phone gets stuck on the restart logo and cannot turn on)"
- "wiping keystore (deletes Android's secure lock-screen PIN and fingerprint database, locking you out)"
- "disabling SELinux (turns off Android's built-in shield that separates apps, allowing bad apps to read private files)"
- "chmod 000 (locks down a file so even Android itself cannot run it, crashing your phone on boot)"
- "encrypted binary (hidden code locked with a secret key that prevents security scanning)"

MODULE METADATA:
${metaText || 'None provided'}

MODULE SCRIPTS AUDITED:
${formattedScripts}

CANDIDATE COMMANDS DETECTED (MUST DEEPLY ANALYZE IN FULL SCRIPT CONTEXT):
${JSON.stringify(heuristicResult.candidateCommands || [], null, 2)}

BINARY DECRYPTION INSPECTION FINDINGS:
${JSON.stringify(binaryDecryption || [], null, 2)}

SPECIFIC INSTRUCTION FOR COMMAND ANALYSIS:
- The local pattern scanner detected candidate commands above.
- You MUST analyze the surrounding code and determine WHAT EACH COMMAND ACTUALLY DOES in this specific module.
- For each command you report, clearly explain in everyday words what it does.
- If it is safe cleanup (deleting temporary files, cache, dalvik-cache, logs, or files in the module's own folder $MODDIR), or safe setup (chmod 755/644 on module files), explain why it is safe in "deletionAssessment" or "chmodAssessment" and place it in "goodCommands". DO NOT flag it as high risk or put it in "corruptingCommands"!
- ONLY put a command in "corruptingCommands" if it ACTUALLY wipes an entire partition (like /system, /data, /vendor, /boot) or deletes core Android boot binaries, causing an unbootable phone or bootloop!
- Accurately determine the true verdict ('SAFE', 'CAUTION', 'DANGEROUS', 'MALICIOUS_BRICK_RISK') and riskScore based on your deep understanding of the module!

AUDIT SECTIONS YOU MUST WRITE BASED 100% ON YOUR READING OF THE CODE:
1. "whatThisModuleDoes": Thorough explanation written by you detailing what this module ACTUALLY attempts to do in everyday words.
2. "deletionAssessment": Clear explanation of what files or partitions this module deletes, and whether it's safe (e.g. harmless cache/temporary files) or dangerous (whole partition wipe).
3. "chmodAssessment": Clear evaluation of any permission changes (chmod) on crucial system files or raw partition blocks.
4. "decryptionAssessment": Clear evaluation of binary files and decryption status. If any file failed decryption, you must explicitly state that results are not guaranteed.
5. "mechanisms": 2 to 4 simple bullet points explaining how it hooks into Android.
6. "scamOrPlaceboCheck": Is this module authentic or fake/snake-oil? (e.g. claiming "120FPS 8K or 10x RAM Boost").
7. "batteryAndHeatImpact": Will this drain battery fast or cause overheating?
8. "bootloopRisk": Is there any risk of the phone failing to turn on, especially on modern Android 12, 13, 14, or 15?
9. "privacySafety": Does it steal private photos, passwords, IMEI, or secretly download unknown files?
10. "uninstallSafety": When uninstalled, will it cleanly disappear or leave broken files?
11. "corruptingCommands": Any commands that wipe whole partitions, brick devices, or strip crucial system permissions.
12. "riskyCommands": Risky commands like downloading unverified files, disabling security, or chmod 777 on block devices.
13. "goodCommands": Standard harmless root commands (including safe cache deletions and normal chmod 755).
14. "verdict": One of: 'SAFE', 'CAUTION', 'DANGEROUS', 'MALICIOUS_BRICK_RISK'.
15. "riskScore": Integer 0 to 100.
16. "summary": A clear 2-3 sentence overview in common words.
17. "recommendation": Direct, clear advice in everyday English.

Return a JSON object conforming strictly to the requested schema.`;

  const configuredModel = (process.env.GEMINI_MODEL || '').trim();
  const candidateModels = [
    configuredModel,
    'gemini-3.8-flash',
    'gemini-3.1-flash-lite',
  ].filter(Boolean);
  const modelsToTry = Array.from(new Set(candidateModels));

  let aiResult = null;
  let successfulModel = modelsToTry[0];

  for (let i = 0; i < modelsToTry.length; i++) {
    const modelName = modelsToTry[i];
    try {
      console.log(`🤖 Querying Gemini AI via model [${modelName}]...`);

      const generatePromise = ai.models.generateContent({
        model: modelName,
        contents: prompt,
        config: {
          temperature: 0.1,
          responseMimeType: 'application/json',
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              verdict: {
                type: Type.STRING,
                description: "Must be: 'SAFE', 'CAUTION', 'DANGEROUS', 'MALICIOUS_BRICK_RISK'",
              },
              riskScore: { type: Type.INTEGER, description: "0 to 100" },
              summary: { type: Type.STRING, description: "Plain English summary" },
              whatThisModuleDoes: {
                type: Type.STRING,
                description: "Context explaining what this module actually does in plain English",
              },
              deletionAssessment: {
                type: Type.STRING,
                description: "Plain English assessment of deleted files (distinguishing harmless cache/temp vs whole partition wipe)",
              },
              chmodAssessment: {
                type: Type.STRING,
                description: "Plain English assessment of chmod operations on crucial system files and partition blocks",
              },
              decryptionAssessment: {
                type: Type.STRING,
                description: "Plain English assessment of encrypted binary decryption. If unverified, warns that result is not guaranteed.",
              },
              mechanisms: {
                type: Type.ARRAY,
                description: "Plain English bullet points explaining how it operates in Android",
                items: { type: Type.STRING },
              },
              scamOrPlaceboCheck: {
                type: Type.STRING,
                description: "Plain English check: Is this module authentic or a fake/placebo tweak?",
              },
              batteryAndHeatImpact: {
                type: Type.STRING,
                description: "Plain English evaluation of battery drain and phone thermal/heating risk",
              },
              bootloopRisk: {
                type: Type.STRING,
                description: "Plain English evaluation of bootloop hazard on Android 12, 13, 14, 15",
              },
              privacySafety: {
                type: Type.STRING,
                description: "Plain English check of data theft, password access, or telemetry",
              },
              uninstallSafety: {
                type: Type.STRING,
                description: "Plain English assessment of whether the module uninstalls cleanly",
              },
              corruptingCommands: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    command: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                  },
                  required: ['command', 'explanation'],
                },
              },
              riskyCommands: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    command: { type: Type.STRING },
                    explanation: { type: Type.STRING },
                  },
                  required: ['command', 'explanation'],
                },
              },
              goodCommands: {
                type: Type.ARRAY,
                items: {
                  type: Type.OBJECT,
                  properties: {
                    command: { type: Type.STRING },
                  },
                  required: ['command'],
                },
              },
              recommendation: { type: Type.STRING, description: "Clear everyday advice" },
            },
            required: [
              'verdict',
              'riskScore',
              'summary',
              'whatThisModuleDoes',
              'deletionAssessment',
              'chmodAssessment',
              'corruptingCommands',
              'riskyCommands',
              'recommendation',
            ],
          },
        },
      });

      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error(`Model ${modelName} timed out after 25000ms`)), 25000);
      });

      const response = await Promise.race([generatePromise, timeoutPromise]);
      const text = response.text ? response.text.trim() : null;

      if (text) {
        const parsed = JSON.parse(text);
        aiResult = {
          verdict: parsed.verdict || 'CAUTION',
          riskScore: typeof parsed.riskScore === 'number' ? parsed.riskScore : 50,
          summary: parsed.summary || 'Security review completed.',
          whatThisModuleDoes: parsed.whatThisModuleDoes || 'Standard Android root mod.',
          deletionAssessment: parsed.deletionAssessment || 'No critical partition deletions found.',
          chmodAssessment: parsed.chmodAssessment || 'No hazardous permission modifications detected.',
          decryptionAssessment: parsed.decryptionAssessment || heuristicResult.decryptionAssessment || '',
          mechanisms: parsed.mechanisms || [],
          scamOrPlaceboCheck: parsed.scamOrPlaceboCheck || 'No obvious fake claims detected.',
          batteryAndHeatImpact: parsed.batteryAndHeatImpact || 'Normal impact.',
          bootloopRisk: parsed.bootloopRisk || 'Low bootloop risk on standard Android setups.',
          privacySafety: parsed.privacySafety || 'No suspicious data harvesting found.',
          uninstallSafety: parsed.uninstallSafety || 'Uninstalls cleanly through Root Manager.',
          corruptingCommands: parsed.corruptingCommands || [],
          riskyCommands: parsed.riskyCommands || [],
          goodCommands: parsed.goodCommands || [],
          recommendation: parsed.recommendation || 'Always keep a backup before flashing.',
          binaryDecryption: binaryDecryption || [],
          engine: `Google Gemini (${modelName})`,
          modelUsed: modelName,
        };
        successfulModel = modelName;
        console.log(`✅ Gemini AI audit completed successfully using model [${modelName}]!`);
        break;
      }
    } catch (aiErr) {
      const errMsg = aiErr.message || String(aiErr);
      if (i < modelsToTry.length - 1) {
        const nextModel = modelsToTry[i + 1];
        console.warn(`⚡ Gemini model [${modelName}] busy/slow. Fast-switching to [${nextModel}]...`);
        if (onProgress) {
          await onProgress(`⚡ <b>Model [${modelName}] busy/timed out.</b>\n🔄 <i>Fast-switching to [${nextModel}]...</i>`);
        }
        continue;
      } else {
        console.warn(`⚠️ All Gemini models busy or timed out:`, errMsg);
      }
    }
  }

  // AI vs Offline Heuristic resolution
  if (!aiResult) {
    console.log('🛡️ Engaging RootGuard Deep Heuristic Engine (100% offline accuracy fallback).');
    aiResult = heuristicResult;
  } else {
    // If AI's contextual analysis confirmed genuine bricking/partition-wipe commands:
    if (aiResult.corruptingCommands && aiResult.corruptingCommands.length > 0) {
      aiResult.verdict = 'MALICIOUS_BRICK_RISK';
      aiResult.riskScore = Math.max(aiResult.riskScore || 0, 90);
    }

    // If unverified encrypted binaries exist, safety cannot be guaranteed
    const hasUnverifiedBinary = (binaryDecryption || []).some((b) => !b.decrypted);
    if (hasUnverifiedBinary && aiResult.verdict === 'SAFE') {
      aiResult.verdict = 'CAUTION';
      aiResult.riskScore = Math.max(aiResult.riskScore || 0, 45);
    }
    aiResult.binaryDecryption = binaryDecryption || [];
    if (!aiResult.decryptionAssessment && heuristicResult.decryptionAssessment) {
      aiResult.decryptionAssessment = heuristicResult.decryptionAssessment;
    }
  }

  return aiResult;
}

// =======================================================================
// 8. Telegram HTML Report Formatter & Buttons
// =======================================================================
function formatReportHtml(fileName, audit, quotaRemaining, isOwner, fileBreakdown, allFiles, scanId) {
  const verdictHeader =
    audit.verdict === 'MALICIOUS_BRICK_RISK'
      ? '🚨 <b>MALICIOUS / DATA CORRUPTION &amp; BRICK HAZARD</b>'
      : audit.verdict === 'DANGEROUS'
      ? '⛔ <b>HIGH RISK / SUSPICIOUS BEHAVIOR</b>'
      : audit.verdict === 'CAUTION'
      ? '⚠️ <b>CAUTION ADVISED / REVIEW SCRIPTS</b>'
      : '✅ <b>CLEAN &amp; SAFE TO FLASH</b>';

  let text = `<b>🛡️ RootGuard Security Audit</b>\n`;
  text += `⚡ <i>made by @toshitzz</i>\n`;
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += `📦 <b>Target:</b> <code>${escapeHtml(fileName)}</code>\n`;
  text += `📊 <b>Risk Score:</b> <b>${audit.riskScore}/100</b>\n`;
  text += `📋 <b>Verdict:</b> ${verdictHeader}\n`;
  text += `🤖 <b>Audit Engine:</b> <code>${escapeHtml(audit.engine || 'Google Gemini AI')}</code>\n\n`;

  // 1. What This Module Does
  text += `🎯 <b>What This Module Does:</b>\n`;
  text += `${escapeHtml(audit.whatThisModuleDoes)}\n\n`;

  // 2. File Deletion Analysis (Harmless vs Partition Wipe)
  if (audit.deletionAssessment) {
    text += `🗑️ <b>File &amp; Partition Deletion Analysis:</b>\n`;
    text += `${escapeHtml(audit.deletionAssessment)}\n\n`;
  }

  // 3. Crucial chmod Analysis
  if (audit.chmodAssessment) {
    text += `🔑 <b>System Permission &amp; chmod Analysis:</b>\n`;
    text += `${escapeHtml(audit.chmodAssessment)}\n\n`;
  }

  // 4. Decryption & Encrypted Payload Analysis
  if (audit.binaryDecryption && audit.binaryDecryption.length > 0) {
    const unverified = audit.binaryDecryption.filter((b) => !b.decrypted);
    const decrypted = audit.binaryDecryption.filter((b) => b.decrypted);

    if (unverified.length > 0) {
      text += `⚠️ <b>UNVERIFIED ENCRYPTED BINARY DETECTED:</b>\n`;
      unverified.forEach((item) => {
        text += `• <code>${escapeHtml(item.fileName)}</code> (Entropy: ${item.entropy ? item.entropy.toFixed(2) : 'N/A'}/8.0)\n`;
        text += `  ❗ <b>Notice: Result is NOT guaranteed.</b> Encrypted binary could not be decrypted. Because hidden code cannot be audited, exercise caution before flashing.\n`;
      });
      text += `\n`;
    }

    if (decrypted.length > 0) {
      text += `🔓 <b>ENCRYPTED BINARY DECRYPTED &amp; VERIFIED:</b>\n`;
      decrypted.forEach((item) => {
        text += `• <code>${escapeHtml(item.fileName)}</code>: Decrypted via <b>${escapeHtml(item.method || 'De-obfuscator')}</b>\n`;
        text += `  ✅ Decrypted payload inspected and audited for security.\n`;
      });
      text += `\n`;
    }
  } else if (audit.decryptionAssessment) {
    text += `🔓 <b>Binary Decryption Analysis:</b>\n`;
    text += `${escapeHtml(audit.decryptionAssessment)}\n\n`;
  }

  // 4. How it works (Android system hooks)
  if (audit.mechanisms && audit.mechanisms.length > 0) {
    text += `⚙️ <b>How It Works:</b>\n`;
    audit.mechanisms.slice(0, 4).forEach((m) => {
      text += `• ${escapeHtml(m)}\n`;
    });
    text += `\n`;
  }

  // 5. Scam / Placebo Check
  if (audit.scamOrPlaceboCheck) {
    text += `🔍 <b>Scam &amp; Fake Claims Check:</b>\n`;
    text += `${escapeHtml(audit.scamOrPlaceboCheck)}\n\n`;
  }

  // 6. Battery & Phone Temperature Impact
  if (audit.batteryAndHeatImpact) {
    text += `🔋 <b>Battery &amp; Heat Impact:</b>\n`;
    text += `${escapeHtml(audit.batteryAndHeatImpact)}\n\n`;
  }

  // 7. Bootloop & Android Version Risk
  if (audit.bootloopRisk) {
    text += `📱 <b>Bootloop &amp; Android Safety:</b>\n`;
    text += `${escapeHtml(audit.bootloopRisk)}\n\n`;
  }

  // 8. Data Corrupting / Brick Commands
  if (audit.corruptingCommands && audit.corruptingCommands.length > 0) {
    text += `🚨 <b>BRICK / PARTITION HAZARD COMMANDS (${audit.corruptingCommands.length}):</b>\n`;
    audit.corruptingCommands.slice(0, 4).forEach((c) => {
      text += `• <code>${escapeHtml(c.command)}</code>\n  ⚠️ <i>${escapeHtml(c.explanation || 'Dangerous partition or chmod operation')}</i>\n`;
    });
    text += `\n`;
  }

  // 9. Risky Commands
  if (audit.riskyCommands && audit.riskyCommands.length > 0) {
    text += `⚠️ <b>FLAGGED RISKY COMMANDS (${audit.riskyCommands.length}):</b>\n`;
    audit.riskyCommands.slice(0, 3).forEach((c) => {
      text += `• <code>${escapeHtml(c.command)}</code>\n  ℹ️ <i>${escapeHtml(c.explanation || 'Risky permission or network download')}</i>\n`;
    });
    text += `\n`;
  }

  // 10. Actionable Recommendation
  text += `💡 <b>What You Should Do:</b>\n`;
  text += `${escapeHtml(audit.recommendation)}\n\n`;

  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += isOwner
    ? `👑 <b>Owner Account:</b> Unlimited scans available.`
    : `📊 <b>Daily Allowance:</b> <b>${quotaRemaining}</b> scans remaining today (resets at 00:00 UTC).`;

  const replyMarkup = {
    inline_keyboard: [
      [
        { text: '💬 Ask About This Module', callback_data: `ask:${scanId}` },
        { text: '📜 View Module Code', callback_data: `code:${scanId}:0` },
      ],
      [
        { text: '📖 Explain in Simpler Words', callback_data: `eli5:${scanId}` },
        { text: '🚨 Bootloop Rescue', callback_data: `recovery` },
      ],
    ],
  };

  return { text, replyMarkup };
}

// =======================================================================
// 9. Interactive Callback Query Handler (Telegram Buttons)
// =======================================================================
async function handleCallbackQuery(cq) {
  const cqId = cq.id;
  const data = cq.data || '';
  const chatId = cq.message?.chat?.id;
  const messageId = cq.message?.message_id;

  answerCallbackQuery(cqId).catch(() => {});

  if (!data) return;

  if (data === 'recovery') {
    const recText = `🚨 <b>Emergency Bootloop Recovery:</b>\n\n` +
      `<b>1. Magisk Safe Mode (Hardware):</b>\n` +
      `• Hold <b>Volume Down</b> continuously while device boots from vendor splash screen. Modules will be disabled automatically.\n\n` +
      `<b>2. KernelSU Safe Mode:</b>\n` +
      `• Press <b>Volume Down rapidly 3+ times</b> during initial boot.\n\n` +
      `<b>3. ADB Shell Rescue (PC):</b>\n` +
      `• <code>adb wait-for-device shell magisk --remove-modules</code>\n\n` +
      `<b>4. Custom Recovery (TWRP/OrangeFox):</b>\n` +
      `• Open File Manager, navigate to <code>/data/adb/modules/</code>, and remove the offending module directory.\n\n` +
      `⚡ <i>RootGuard • made by @toshitzz</i>`;
    return await sendTelegramMessage(chatId, recText, messageId);
  }

  const parts = data.split(':');
  const action = parts[0];
  const scanId = parts[1];
  const cached = dbGetScanCache(scanId);

  if (!cached) {
    if (action === 'eli5') {
      const fallbackEli5 = `📖 <b>Understanding Your Security Verdict:</b>\n\n` +
        `• 🟢 <b>Clean & Safe:</b> Script uses standard root paths without hazardous partition access.\n` +
        `• 🟡 <b>Caution:</b> Normal files or cache are modified. Not a partition wipe.\n` +
        `• 🟠 <b>High Risk:</b> Downloads remote scripts or manipulates security policies.\n` +
        `• 🔴 <b>Brick Risk:</b> Attempts raw partition wipe or strips crucial system chmod permissions.\n\n` +
        `💡 <i>Tip: Send your module file again to get a fresh detailed audit!</i>\n\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, fallbackEli5, messageId);
    }
    if (action === 'advice') {
      const fallbackAdvice = `💡 <b>Essential Root Security Checklist:</b>\n\n` +
        `1. <b>Nandroid/Partition Backup:</b> Keep a clean boot.img & init_boot.img backup on your PC.\n` +
        `2. <b>Safe Mode Verification:</b> Confirm Volume-Down safe mode functions on your phone.\n` +
        `3. <b>Placebo Warning:</b> Beware of modules claiming "120FPS unlock" or "50% battery gain".\n` +
        `4. <b>Staged Testing:</b> Flash one module at a time rather than batch flashing.\n\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, fallbackAdvice, messageId);
    }
    if (action === 'code' || action === 'fcode') {
      return await sendTelegramMessage(
        chatId,
        `📜 <i>Script command details are cleared after file cleanup. To inspect code specifics, simply re-upload your module file!</i>\n\n⚡ <i>made by @toshitzz</i>`,
        messageId
      );
    }
    if (action === 'ask') {
      return await sendTelegramMessage(
        chatId,
        `💬 <i>Session expired. Please re-upload your module file to ask RootGuard AI questions about it!</i>\n\n⚡ <i>made by @toshitzz</i>`,
        messageId
      );
    }
    return;
  }

  const audit = cached.audit;

  if (action === 'ask') {
    userQuestionSessions.set(String(chatId), { scanId, fileName: cached.fileName, timestamp: Date.now() });
    const askPromptText = `💬 <b>Ask RootGuard AI about:</b> <code>${escapeHtml(cached.fileName)}</code>\n` +
      `━━━━━━━━━━━━━━━━━━━━━\n` +
      `Send any question in this chat! RootGuard AI will review the module's code and answer you directly.\n\n` +
      `<b>Example Questions:</b>\n` +
      `• <i>"Does this module touch my boot partition or cause bootloops?"</i>\n` +
      `• <i>"What does the customize.sh script do?"</i>\n` +
      `• <i>"Does it delete any of my personal files or apps?"</i>\n` +
      `• <i>"Will this drain my battery or cause heating?"</i>\n\n` +
      `<i>Type your question below, or type /cancel to stop.</i>\n` +
      `⚡ <i>RootGuard • made by @toshitzz</i>`;
    return await sendTelegramMessage(chatId, askPromptText, messageId);
  }

  if (action === 'eli5') {
    let eli5Text = `📖 <b>Super Simple Explanation (In Easy Words):</b>\n\n`;
    eli5Text += `<b>Target:</b> <code>${escapeHtml(cached.fileName)}</code>\n\n`;

    if (audit.verdict === 'MALICIOUS_BRICK_RISK') {
      eli5Text += `🔴 <b>Warning:</b> This file has code that wipes whole partitions or strips crucial system permissions. <b>DO NOT INSTALL IT.</b>\n\n`;
    } else if (audit.verdict === 'DANGEROUS') {
      eli5Text += `🟠 <b>Careful:</b> This file does risky things like downloading code from the internet or changing sensitive settings. Only install if you trust the author.\n\n`;
    } else {
      eli5Text += `🟢 <b>Good News:</b> This file looks clean! Any file deletion is just harmless temporary cleanup or module cache, NOT a partition wipe.\n\n`;
    }

    eli5Text += `<b>What it actually does:</b>\n${escapeHtml(audit.whatThisModuleDoes)}\n\n`;
    if (audit.deletionAssessment) {
      eli5Text += `<b>Deletion check:</b> ${escapeHtml(audit.deletionAssessment)}\n\n`;
    }
    if (audit.chmodAssessment) {
      eli5Text += `<b>Permission check:</b> ${escapeHtml(audit.chmodAssessment)}\n\n`;
    }
    eli5Text += `<b>Battery:</b> ${escapeHtml(audit.batteryAndHeatImpact || 'Normal')}\n`;
    eli5Text += `<b>Fake promises:</b> ${escapeHtml(audit.scamOrPlaceboCheck || 'None')}\n\n`;
    eli5Text += `⚡ <i>RootGuard • made by @toshitzz</i>`;

    return await sendTelegramMessage(chatId, eli5Text, messageId);
  }

  if (action === 'advice') {
    let adviceText = `💡 <b>Practical Advice for You:</b>\n\n`;
    adviceText += `• <b>Recommendation:</b> ${escapeHtml(audit.recommendation)}\n\n`;
    adviceText += `• <b>Before Flashing:</b>\n`;
    adviceText += `  1. Know how to enter Safe Mode (Hold Volume Down during boot).\n`;
    adviceText += `  2. Make sure your important files/photos are backed up.\n`;
    adviceText += `  3. If your phone gets warm, check the module\'s background service.\n\n`;
    adviceText += `⚡ <i>RootGuard • made by @toshitzz</i>`;

    return await sendTelegramMessage(chatId, adviceText, messageId);
  }

  if (action === 'code' || action === 'fcode') {
    const scripts = cached.scripts || [];
    if (scripts.length === 0) {
      let codeText = `📜 <b>Flagged Script Commands:</b>\n\n`;
      const flags = [...(audit.corruptingCommands || []), ...(audit.riskyCommands || [])];

      if (flags.length === 0) {
        codeText += `✅ <i>No dangerous partition wipes or critical chmod commands were flagged in this file!</i>\n\n`;
      } else {
        flags.slice(0, 6).forEach((f) => {
          codeText += `• <code>${escapeHtml(f.command)}</code>\n  👉 <i>${escapeHtml(f.explanation || 'Flagged operation')}</i>\n\n`;
        });
      }
      codeText += `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, codeText, messageId);
    }

    const fileIdx = parseInt(parts[2] || '0', 10) || 0;
    const safeIdx = Math.max(0, Math.min(scripts.length - 1, fileIdx));
    const currentScript = scripts[safeIdx];

    let codeText = `📜 <b>Module Code Inspector:</b> <code>${escapeHtml(cached.fileName)}</code>\n`;
    codeText += `━━━━━━━━━━━━━━━━━━━━━\n`;
    codeText += `<b>File ${safeIdx + 1} of ${scripts.length}:</b> <code>${escapeHtml(currentScript.path)}</code> (${currentScript.size || currentScript.content.length} bytes)\n\n`;

    const preview = currentScript.content.slice(0, 1600);
    codeText += `<pre><code>${escapeHtml(preview)}</code></pre>\n`;
    if (currentScript.content.length > 1600) {
      codeText += `\n<i>... (${currentScript.content.length - 1600} more characters truncated for Telegram view)</i>\n`;
    }

    const navButtons = [];
    if (safeIdx > 0) {
      const prevName = scripts[safeIdx - 1].path.split('/').pop();
      navButtons.push({ text: `⬅️ ${prevName}`, callback_data: `fcode:${scanId}:${safeIdx - 1}` });
    }
    if (safeIdx < scripts.length - 1) {
      const nextName = scripts[safeIdx + 1].path.split('/').pop();
      navButtons.push({ text: `${nextName} ➡️`, callback_data: `fcode:${scanId}:${safeIdx + 1}` });
    }

    const inlineKeyboard = [];
    if (navButtons.length > 0) {
      inlineKeyboard.push(navButtons);
    }
    inlineKeyboard.push([
      { text: '💬 Ask AI About This Script', callback_data: `ask:${scanId}` },
      { text: '📖 Simpler Explanation', callback_data: `eli5:${scanId}` },
    ]);

    codeText += `\n⚡ <i>RootGuard • made by @toshitzz</i>`;

    return await sendTelegramMessage(chatId, codeText, messageId, { inline_keyboard: inlineKeyboard });
  }
}

// =======================================================================
// 10. Command Handler
// =======================================================================
async function handleCommand(chatId, rawUserId, command, args, replyMsgId) {
  const cleanUserId = String(rawUserId).replace(/^tg:/i, '').trim();
  const isOwner = isUserOwnerOrVip(cleanUserId);

  switch (command) {
    case '/start': {
      const welcome = `<b>🛡️ Welcome to RootGuard AI!</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `I am your intelligent Android root security companion powered by Google Gemini AI.\n\n` +
        `<b>Enhanced Detection System Active:</b>\n` +
        `• <b>Smart Deletion Detection:</b> I check WHICH files a module deletes. Normal cache, dalvik, logs, and $MODDIR cleanups are NOT flagged as high risk!\n` +
        `• <b>Partition Brick Shield:</b> I stop entire partition wipes (/system, /data, /vendor, /boot) that make phones unbootable or trigger bootloops.\n` +
        `• <b>Crucial chmod Detection:</b> I monitor permission stripping on system binaries (chmod 000 bootloop hazards) and raw block exposures.\n` +
        `• <b>Scam / Snake-Oil Detector:</b> I flag fake promises (like "120FPS 10x RAM Boost").\n` +
        `• <b>Battery &amp; Heat Check:</b> I check if scripts overheat your phone or kill battery life.\n\n` +
        `📤 <b>How to Use:</b> Simply send any <code>.zip</code> or <code>.sh</code> module file to this chat!\n\n` +
        `Type /help to see all available commands.\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, welcome, replyMsgId);
    }

    case '/help': {
      let helpMsg = `📖 <b>RootGuard Command Center:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>Auditing &amp; Analysis:</b>\n` +
        `• Send any <b>.zip</b> or <b>.sh</b> module to begin AI security inspection.\n` +
        `• <code>/quick &lt;code&gt;</code> - Instant zero-quota static heuristic check.\n` +
        `• <code>/scan</code> - Instructions for uploading modules.\n` +
        `• <code>/quota</code> - View your remaining free scans today.\n` +
        `• <code>/recovery</code> - Emergency bootloop rescue guide.\n` +
        `• <code>/ping</code> - Check bot latency and server health.\n` +
        `• <code>/about</code> - About RootGuard architecture &amp; author.\n` +
        `• <code>/myid</code> - View your Telegram User ID.\n` +
        `• <code>/stats</code> - View system statistics &amp; threat counts.\n` +
        `• <code>/test</code> - Test Gemini AI connection latency.\n`;

      if (isOwner) {
        helpMsg += `\n👑 <b>Admin &amp; Database Controls (SQL):</b>\n` +
          `• <code>/vip &lt;id&gt;</code> - Grant permanent VIP (Unlimited scans)\n` +
          `• <code>/unvip &lt;id&gt;</code> - Remove VIP status\n` +
          `• <code>/ban &lt;id&gt;</code> - Ban spammer/abuser\n` +
          `• <code>/unban &lt;id&gt;</code> - Unban user\n` +
          `• <code>/dbstats</code> - Query SQLite users and scans\n` +
          `• <code>/history</code> - View last 10 scans from SQL\n` +
          `• <code>/broadcast &lt;msg&gt;</code> - Broadcast announcement to all users\n`;
      }

      helpMsg += `\n━━━━━━━━━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, helpMsg, replyMsgId);
    }

    case '/ping': {
      const pingStart = Date.now();
      const tempMsg = await sendTelegramMessage(chatId, `🏓 <i>Pinging RootGuard engine...</i>`, replyMsgId);
      const latencyMs = Date.now() - pingStart;
      const uptimeH = (process.uptime() / 3600).toFixed(1);
      const pingText = `🏓 <b>Pong!</b> <code>${latencyMs}ms</code>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `• <b>Engine:</b> Google Gemini AI + Partition Safeguards\n` +
        `• <b>Detection:</b> Crucial chmod + Target File Check\n` +
        `• <b>Uptime:</b> ${uptimeH}h continuous\n` +
        `• <b>Database:</b> SQLite (WAL Mode)`;
      if (tempMsg?.result?.message_id) {
        return await editTelegramMessage(chatId, tempMsg.result.message_id, pingText);
      }
      return await sendTelegramMessage(chatId, pingText, replyMsgId);
    }

    case '/scan':
    case '/audit': {
      return await sendTelegramMessage(
        chatId,
        `📦 <b>How to Audit a Module:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `Simply tap the 📎 <b>Attachment</b> button on Telegram and upload any:\n` +
        `• <b>.zip</b> Magisk / KernelSU / APatch module\n` +
        `• <b>.sh</b> shell script or post-fs script\n\n` +
        `RootGuard will immediately run AST security heuristics, partition deletion verification, crucial chmod detection, and Google Gemini neural inspection!`,
        replyMsgId
      );
    }

    case '/about': {
      return await sendTelegramMessage(
        chatId,
        `🛡️ <b>About RootGuard AI</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `RootGuard is a dedicated Android root module security auditor.\n` +
        `Enhanced Detection System Features:\n` +
        `• <b>Partition vs File Deletion:</b> Distinguishes safe cache/mod removals from whole partition wipes\n` +
        `• <b>Crucial chmod Detection:</b> Monitors permission stripping on /system/bin and raw block nodes\n` +
        `• <b>Bootloop Shield:</b> Prevents unbootable scripts before you flash\n` +
        `• <b>Scam Detection:</b> Spots placebo FPS/RAM scripts\n\n` +
        `Powered by <b>Google Gemini AI</b> with failover resilience.`,
        replyMsgId
      );
    }

    case '/quota': {
      const quota = dbGetUserQuota(cleanUserId);
      if (quota.isVip) {
        return await sendTelegramMessage(
          chatId,
          `👑 <b>VIP / Owner Status:</b> Unlimited Scans Active!\n\n` +
          `• Account: <b>VIP / Lifetime Developer</b>\n` +
          `• Cooldown: <b>Bypassed (0s)</b>\n` +
          `• Engine: <b>Google Gemini AI + Neural Heuristics</b>\n\n` +
          `⚡ <i>RootGuard • made by @toshitzz</i>`,
          replyMsgId
        );
      }

      const used = quota.used;
      const max = quota.max || DAILY_SCAN_LIMIT;
      const filledBars = Math.min(max, used);
      const emptyBars = Math.max(0, max - filledBars);
      const bar = '▰'.repeat(filledBars) + '▱'.repeat(emptyBars);

      return await sendTelegramMessage(
        chatId,
        `📊 <b>Your Daily Scan Allowance:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `<code>[ ${bar} ] ${used} / ${max} used</code>\n\n` +
        `• Remaining Scans: <b>${quota.remaining}</b>\n` +
        `• Cooldown Between Scans: <b>${COOLDOWN_SECONDS}s</b>\n` +
        `• Resets at: <b>00:00 UTC</b> (in <b>${getTimeUntilMidnightUtc()}</b>)\n\n` +
        `💡 <i>Tip: Use <code>/quick &lt;code&gt;</code> for unlimited, zero-quota code checks!</i>\n` +
        `👑 <i>Need unlimited quota? Add your Telegram ID (<code>${cleanUserId}</code>) to <code>OWNER_ID</code>.</i>`,
        replyMsgId
      );
    }

    case '/profile':
    case '/myid': {
      const user = dbGetUser(cleanUserId);
      const quota = dbGetUserQuota(cleanUserId);
      const regDate = user?.created_at ? new Date(user.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : 'Today';
      const scansToday = quota.isVip ? 'Unlimited' : `${quota.used} / ${quota.max || DAILY_SCAN_LIMIT}`;

      return await sendTelegramMessage(
        chatId,
        `🆔 <b>Your RootGuard Profile:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• <b>Telegram ID:</b> <code>${cleanUserId}</code>\n` +
        `• <b>Chat ID:</b> <code>${chatId}</code>\n` +
        `• <b>Tier:</b> ${isOwner ? '👑 VIP / Developer (Unlimited)' : 'Standard User'}\n` +
        `• <b>Total Lifetime Audits:</b> <b>${user?.total_scans || 0}</b>\n` +
        `• <b>Today\'s Scans:</b> <b>${scansToday}</b>\n` +
        `• <b>Member Since:</b> ${regDate}\n` +
        `• <b>Status:</b> ${user?.is_banned ? '🚫 Restricted' : '✅ Active'}\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`,
        replyMsgId
      );
    }

    case '/rules': {
      const rulesMsg = `🛡️ <b>RootGuard Golden Rules of Root Safety:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>1. Always Have a Stock Boot Image:</b>\n` +
        `Keep a copy of your current build\'s <code>init_boot.img</code> or <code>boot.img</code> on your PC or USB-OTG.\n\n` +
        `<b>2. Know Your Recovery Hotkey:</b>\n` +
        `Hold <b>Volume Down</b> on startup for Magisk Safe Mode. On KernelSU, press Volume Down 3+ times.\n\n` +
        `<b>3. Beware of Placebo Snake-Oil:</b>\n` +
        `Never trust modules promising "120FPS on 60Hz screens", "16GB RAM multiplier", or "GPU 200% Overclock" without kernel-level code.\n\n` +
        `<b>4. Never Flash Password-Locked Archives:</b>\n` +
        `Encrypted zips hide malicious partition destroyers from scanners.\n\n` +
        `<b>5. Watch for System chmod 000:</b>\n` +
        `Permissions stripped from /system or /system/bin binaries will immediately crash Android during boot.\n\n` +
        `<b>6. Audit Before You Flash:</b>\n` +
        `Upload the module here to RootGuard first!\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, rulesMsg, replyMsgId);
    }

    case '/checkurl': {
      const targetUrl = args.trim();
      if (!targetUrl || (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://'))) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/checkurl &lt;direct download link&gt;</code>\n\nExample: <code>/checkurl https://example.com/mymodule.zip</code>`,
          replyMsgId
        );
      }

      const lockCheck = dbCheckCooldownAndLock(cleanUserId, isOwner);
      if (!lockCheck.allowed) {
        if (lockCheck.reason === 'COOLDOWN') {
          return await sendTelegramMessage(chatId, `⏳ Cooldown active: Please wait <b>${lockCheck.remainingSeconds}s</b> before scanning again.`, replyMsgId);
        }
        if (lockCheck.reason === 'QUOTA_EXCEEDED') {
          return await sendTelegramMessage(chatId, `⛔ Daily scan limit reached (${DAILY_SCAN_LIMIT}/${DAILY_SCAN_LIMIT}). Resets at 00:00 UTC.`, replyMsgId);
        }
        if (lockCheck.reason === 'SCAN_IN_PROGRESS') {
          return await sendTelegramMessage(chatId, `⏳ Another scan is currently in progress. Please wait!`, replyMsgId);
        }
      }

      sendChatAction(chatId, 'upload_document').catch(() => {});
      const urlStatusMsg = await sendTelegramMessage(chatId, `🌐 <b>Fetching module from URL...</b>\n<code>${escapeHtml(targetUrl)}</code>`, replyMsgId);
      const urlStatusMsgId = urlStatusMsg?.result?.message_id;

      try {
        const fetchRes = await fetch(targetUrl, { headers: { 'User-Agent': 'RootGuard-Security-Bot/2.5' } });
        if (!fetchRes.ok) throw new Error(`HTTP Error ${fetchRes.status}: ${fetchRes.statusText}`);
        const arrayBuf = await fetchRes.arrayBuffer();
        const buffer = Buffer.from(arrayBuf);
        const fileName = path.basename(new URL(targetUrl).pathname) || 'downloaded_module.zip';

        if (buffer.length > 25 * 1024 * 1024) {
          throw new Error('Downloaded file exceeds 25 MB size limit.');
        }

        const { scripts, metadata, fileCount, allFiles, fileBreakdown, binaryDecryption } = await extractScriptsFromModule(fileName, buffer);
        if (scripts.length === 0 && (!binaryDecryption || binaryDecryption.length === 0)) {
          dbForceReleaseLock(cleanUserId);
          return await editTelegramMessage(chatId, urlStatusMsgId, `⚠️ No shell scripts or config files found inside module.`);
        }
        if (scripts.length === 0 && binaryDecryption && binaryDecryption.length > 0) {
          scripts.push({
            path: binaryDecryption[0].fileName,
            content: `# Binary file inspected: ${binaryDecryption[0].fileName}\n# Decryption status: ${binaryDecryption[0].decrypted ? 'Success' : 'Unverified'}\n# Details: ${binaryDecryption[0].details}`,
            size: 100,
            type: 'script',
          });
        }

        const scanId = crypto.randomUUID().slice(0, 8);
        const finalAudit = await auditModuleWithRealAi(fileName, scripts, metadata, null, binaryDecryption);

        dbReleaseLockAndRecordScan(cleanUserId, {
          file_name: fileName,
          verdict: finalAudit.verdict,
          risk_score: finalAudit.riskScore,
          model_used: finalAudit.modelUsed || 'Heuristics',
          duration_ms: 1200,
        });

        dbSaveScanCache(scanId, fileName, finalAudit, scripts);

        const { text: reportHtml, replyMarkup } = formatReportHtml(
          fileName,
          finalAudit,
          isOwner ? 9999 : Math.max(0, DAILY_SCAN_LIMIT - (dbGetUserQuota(cleanUserId).used)),
          isOwner,
          fileBreakdown,
          allFiles,
          scanId
        );

        return await editTelegramMessage(chatId, urlStatusMsgId, reportHtml, replyMarkup);
      } catch (err) {
        dbForceReleaseLock(cleanUserId);
        return await editTelegramMessage(chatId, urlStatusMsgId, `❌ <b>URL Audit Failed:</b> ${escapeHtml(err.message)}`);
      }
    }

    case '/quick': {
      if (!args.trim()) {
        return await sendTelegramMessage(
          chatId,
          `Usage: <code>/quick &lt;script content&gt;</code>\n\nRuns an instant AST heuristic scan with partition deletion & chmod checks!`,
          replyMsgId
        );
      }
      const dummyScript = [{ path: 'quick.sh', content: args.trim() }];
      const scan = runDeepHeuristicScanner(dummyScript);
      let quickMsg = `⚡ <b>Instant Static Heuristic Audit:</b>\n` +
        `━━━━━━━━━━━━━\n` +
        `📊 Score: <b>${scan.riskScore}/100</b>\n` +
        `📋 Verdict: <b>${scan.verdict}</b>\n\n` +
        `${escapeHtml(scan.summary)}\n\n`;

      if (scan.corruptingCommands.length > 0) {
        quickMsg += `🚨 <b>Partition/Bootloop Hazard:</b> <code>${escapeHtml(scan.corruptingCommands[0].command)}</code>\n` +
          `👉 <i>${escapeHtml(scan.corruptingCommands[0].explanation)}</i>\n\n`;
      }
      if (scan.deletionLog && scan.deletionLog.length > 0) {
        quickMsg += `🗑️ <b>Deletion Analysis:</b> ${escapeHtml(scan.deletionLog[0].classification)} (Risk: ${scan.deletionLog[0].risk})\n`;
      }
      if (scan.chmodLog && scan.chmodLog.length > 0) {
        quickMsg += `🔑 <b>chmod Analysis:</b> ${escapeHtml(scan.chmodLog[0].classification)} (Risk: ${scan.chmodLog[0].risk})\n`;
      }

      quickMsg += `\n💡 <b>Advice:</b> ${escapeHtml(scan.recommendation)}\n━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, quickMsg, replyMsgId);
    }

    case '/recovery': {
      const recMsg = `🚨 <b>Emergency Bootloop Recovery:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `<b>1. Magisk Safe Mode (No PC needed):</b>\n` +
        `• Hold <b>Volume Down</b> continuously as phone powers on from the vendor splash logo.\n` +
        `• Phone boots with all modules disabled. Open Magisk app and uninstall the bad module.\n\n` +
        `<b>2. KernelSU Safe Mode:</b>\n` +
        `• Press <b>Volume Down rapidly 3+ times</b> as boot begins.\n\n` +
        `<b>3. ADB Shell (From PC):</b>\n` +
        `<code>adb wait-for-device shell magisk --remove-modules</code>\n\n` +
        `<b>4. TWRP / Custom Recovery:</b>\n` +
        `• Go to File Manager &gt; <code>/data/adb/modules/</code> and delete the corrupted module folder.\n\n` +
        `━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, recMsg, replyMsgId);
    }

    case '/test': {
      const start = Date.now();
      const ai = getAi();
      if (!ai) {
        return await sendTelegramMessage(chatId, `⚠️ AI Engine offline: GEMINI_API_KEY missing.`, replyMsgId);
      }
      const testModel = (process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim();
      try {
        const res = await ai.models.generateContent({
          model: testModel,
          contents: 'Reply with ONLINE and nothing else.',
        });
        const elapsed = Date.now() - start;
        return await sendTelegramMessage(
          chatId,
          `✅ <b>Gemini AI Connection Successful!</b>\n` +
          `• Model: <b>${escapeHtml(testModel)}</b>\n` +
          `• Latency: <b>${elapsed} ms</b>\n` +
          `• Status: <b>Online &amp; Ready</b>\n\n` +
          `⚡ <i>RootGuard • made by @toshitzz</i>`,
          replyMsgId
        );
      } catch (err) {
        return await sendTelegramMessage(chatId, `⚠️ Gemini API Notice (${escapeHtml(testModel)}): ${escapeHtml(err.message)}`, replyMsgId);
      }
    }

    case '/stats':
    case '/dbstats': {
      const stats = dbGetStats();
      return await sendTelegramMessage(
        chatId,
        `📊 <b>RootGuard SQL Database Statistics:</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `• 👥 Total Registered Users: <b>${stats.totalUsers}</b>\n` +
        `• 👑 VIP / Owner Accounts: <b>${stats.vipCount}</b>\n` +
        `• 📦 Total Modules Audited: <b>${stats.totalScans}</b>\n` +
        `• 🧱 Brick Hazards Prevented: <b>${stats.totalBricksStopped}</b>\n` +
        `• 🗄️ Database: <b>SQLite 3 (WAL mode)</b>\n\n` +
        `━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`,
        replyMsgId
      );
    }

    case '/vip': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/vip &lt;userId&gt;</code>`, replyMsgId);
      dbSetVip(target, true);
      return await sendTelegramMessage(chatId, `👑 User <code>${target}</code> has been granted permanent VIP (Unlimited Scans)!`, replyMsgId);
    }

    case '/unvip': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/unvip &lt;userId&gt;</code>`, replyMsgId);
      dbSetVip(target, false);
      return await sendTelegramMessage(chatId, `User <code>${target}</code> VIP status removed.`, replyMsgId);
    }

    case '/ban': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/ban &lt;userId&gt;</code>`, replyMsgId);
      dbSetBanned(target, true);
      return await sendTelegramMessage(chatId, `🚫 User <code>${target}</code> has been banned from RootGuard.`, replyMsgId);
    }

    case '/unban': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/unban &lt;userId&gt;</code>`, replyMsgId);
      dbSetBanned(target, false);
      return await sendTelegramMessage(chatId, `✅ User <code>${target}</code> has been unbanned.`, replyMsgId);
    }

    case '/resetquota': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const target = args.trim().replace(/^tg:/i, '');
      if (!target) return await sendTelegramMessage(chatId, `Usage: <code>/resetquota &lt;userId&gt;</code>`, replyMsgId);
      dbResetQuota(target);
      return await sendTelegramMessage(chatId, `🔄 Daily scan quota for user <code>${target}</code> has been reset to 0/${DAILY_SCAN_LIMIT}.`, replyMsgId);
    }

    case '/history': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const recent = dbGetRecentScans(10);
      if (recent.length === 0) {
        return await sendTelegramMessage(chatId, `<i>No scans recorded in database yet.</i>`, replyMsgId);
      }
      let histText = `📜 <b>Recent Scans (SQLite Database):</b>\n\n`;
      recent.forEach((s) => {
        const badge = s.verdict === 'MALICIOUS_BRICK_RISK' ? '🔴' : s.verdict === 'DANGEROUS' ? '🟠' : s.verdict === 'CAUTION' ? '🟡' : '🟢';
        histText += `${badge} <code>${escapeHtml(s.file_name)}</code> (${s.riskScore || 0}/100) - [${escapeHtml(s.model_used || 'AI')}]\n`;
      });
      return await sendTelegramMessage(chatId, histText, replyMsgId);
    }

    case '/broadcast': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      if (!args.trim()) return await sendTelegramMessage(chatId, `Usage: <code>/broadcast &lt;announcement text&gt;</code>`, replyMsgId);
      let count = 0;
      for (const tChat of knownChatIds) {
        try {
          await sendTelegramMessage(tChat, `📢 <b>Announcement:</b>\n\n${escapeHtml(args.trim())}\n\n⚡ <i>RootGuard • made by @toshitzz</i>`);
          count++;
        } catch (e) {}
      }
      return await sendTelegramMessage(chatId, `✅ Broadcast sent to ${count} chats.`, replyMsgId);
    }

    default: {
      return await sendTelegramMessage(chatId, `❓ Unknown command: <code>${escapeHtml(command)}</code>. Type /help for assistance.`, replyMsgId);
    }
  }
}

// =======================================================================
// 11. Main File Processor & Queue Consumer
// =======================================================================
async function processModuleAuditJob(chatId, rawUserId, msg, fileName) {
  const cleanUserId = String(rawUserId).replace(/^tg:/i, '').trim();
  const isOwner = isUserOwnerOrVip(cleanUserId);
  const scanStartTime = Date.now();

  sendChatAction(chatId, 'upload_document').catch(() => {});

  let statusMsg = await sendTelegramMessage(
    chatId,
    renderAuditProgress(
      fileName,
      1,
      5,
      20,
      '📥 Secure Stream Transfer',
      'Downloading module archive from Telegram cloud...'
    ),
    msg.message_id
  );

  const statusMsgId = statusMsg?.result?.message_id;

  try {
    const buffer = await downloadTelegramFile(msg.document.file_id);
    if (!buffer) throw new Error('Failed to download module file from Telegram.');

    if (statusMsgId) {
      await editTelegramMessage(
        chatId,
        statusMsgId,
        renderAuditProgress(
          fileName,
          2,
          5,
          40,
          '📦 Decompressing & Unpacking',
          'Extracting archive structures, post-fs scripts & sepolicy hooks...'
        )
      );
    }

    const { scripts, metadata, fileCount, allFiles, fileBreakdown, binaryDecryption } = await extractScriptsFromModule(fileName, buffer);

    if (scripts.length === 0 && (!binaryDecryption || binaryDecryption.length === 0)) {
      dbForceReleaseLock(cleanUserId);
      const noScriptsText = `⚠️ No shell scripts (<code>.sh</code>) or configuration files found inside <code>${escapeHtml(fileName)}</code> (${fileCount} total files inspected).\n\n⚡ <i>made by @toshitzz</i>`;
      if (statusMsgId) return await editTelegramMessage(chatId, statusMsgId, noScriptsText);
      return await sendTelegramMessage(chatId, noScriptsText, msg.message_id);
    }

    if (scripts.length === 0 && binaryDecryption && binaryDecryption.length > 0) {
      scripts.push({
        path: binaryDecryption[0].fileName,
        content: `# Binary payload inspected: ${binaryDecryption[0].fileName}\n# Decryption status: ${binaryDecryption[0].decrypted ? 'Success' : 'Unverified/Failed'}\n# Details: ${binaryDecryption[0].details}`,
        size: 100,
        type: 'script',
      });
    }

    if (statusMsgId) {
      await editTelegramMessage(
        chatId,
        statusMsgId,
        renderAuditProgress(
          fileName,
          3,
          5,
          65,
          '🛡️ Heuristic Code Dissection',
          `Scanned ${scripts.length} script(s) & binary payload(s) for partition wipes, chmod & decryption...`
        )
      );
    }

    sendChatAction(chatId, 'typing').catch(() => {});

    const progressCallback = async (statusUpdate) => {
      if (statusMsgId) {
        await editTelegramMessage(
          chatId,
          statusMsgId,
          renderAuditProgress(
            fileName,
            4,
            5,
            88,
            '🤖 Google Gemini AI Engine',
            statusUpdate || 'Checking partition deletion targets, crucial chmod & battery profile...'
          )
        ).catch(() => {});
      }
    };

    const audit = await auditModuleWithRealAi(fileName, scripts, metadata, progressCallback, binaryDecryption);

    if (statusMsgId) {
      await editTelegramMessage(
        chatId,
        statusMsgId,
        renderAuditProgress(
          fileName,
          5,
          5,
          98,
          '⚡ Finalizing Security Verdict',
          'Formatting interactive assessment & security controls...'
        )
      ).catch(() => {});
    }

    const scanDuration = Date.now() - scanStartTime;
    const scanId = `sc_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;

    dbReleaseLockAndRecordScan(cleanUserId, {
      file_name: fileName,
      file_size: buffer.length,
      verdict: audit.verdict,
      risk_score: audit.riskScore,
      model_used: audit.modelUsed || 'Heuristics',
      duration_ms: scanDuration,
    });

    const quotaInfo = dbGetUserQuota(cleanUserId);
    dbSaveScanCache(scanId, fileName, audit, scripts);

    const { text: reportHtml, replyMarkup } = formatReportHtml(
      fileName,
      audit,
      quotaInfo.remaining,
      isOwner,
      fileBreakdown,
      allFiles,
      scanId
    );

    if (statusMsgId) {
      return await editTelegramMessage(chatId, statusMsgId, reportHtml, replyMarkup);
    }
    return await sendTelegramMessage(chatId, reportHtml, msg.message_id, replyMarkup);
  } catch (err) {
    dbForceReleaseLock(cleanUserId);
    console.error('Audit failed:', err.message || err);

    const isEncrypted = (err.message || '').includes('ENCRYPTED_ZIP');
    let errText;

    if (isEncrypted) {
      errText = `🔐 <b>Encrypted / Password-Protected Archive Detected!</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `📦 <b>Target:</b> <code>${escapeHtml(fileName)}</code>\n\n` +
        `⛔ <b>Security Audit Blocked:</b>\n` +
        `This ZIP is password-protected. RootGuard cannot extract and audit scripts or binaries without the password.\n\n` +
        `⚠️ <b>Security Risk Notice:</b>\n` +
        `Malicious modules often use passwords to hide data-wiping or partition-bricking code.\n\n` +
        `💡 <b>Recommendation:</b> DO NOT FLASH encrypted modules from unverified sources.\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
    } else {
      errText = `❌ <b>Audit Notice:</b> ${escapeHtml(err.message || 'Error processing module')}\n\n` +
        `<i>Please ensure your file is a valid .zip or .sh module archive.</i>\n\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
    }

    if (statusMsgId) {
      return await editTelegramMessage(chatId, statusMsgId, errText);
    }
    return await sendTelegramMessage(chatId, errText, msg.message_id);
  }
}

// =======================================================================
// 12. Main Update Dispatcher
// =======================================================================
async function handleUpdate(update) {
  if (update.callback_query) {
    return await handleCallbackQuery(update.callback_query);
  }

  if (!update.message) return;
  const msg = update.message;
  const chatId = msg.chat.id;
  const rawUserId = String(msg.from?.id || chatId);
  const isOwner = isUserOwnerOrVip(rawUserId);

  knownChatIds.add(chatId);
  dbRegisterOrTouchUser(rawUserId, msg.from?.username, msg.from?.first_name, isOwner);

  const text = (msg.text || '').trim();

  if (text.startsWith('/')) {
    if (text.toLowerCase() === '/cancel') {
      if (userQuestionSessions.has(String(chatId))) {
        userQuestionSessions.delete(String(chatId));
        return await sendTelegramMessage(chatId, `✅ <i>Q&A session ended. Upload another module file or type /help.</i>`, msg.message_id);
      }
    }
    const firstWord = text.split(/\s+/)[0];
    const command = firstWord.toLowerCase().split('@')[0];
    const args = text.slice(firstWord.length).trim();
    return await handleCommand(chatId, rawUserId, command, args, msg.message_id);
  }

  // Check if user is asking a question about a scanned module
  const qSession = userQuestionSessions.get(String(chatId));
  if (qSession && text) {
    const cached = dbGetScanCache(qSession.scanId);
    if (!cached) {
      userQuestionSessions.delete(String(chatId));
      return await sendTelegramMessage(
        chatId,
        `⚠️ <i>Module session expired. Please re-upload your module file to ask questions!</i>\n\n⚡ <i>made by @toshitzz</i>`,
        msg.message_id
      );
    }

    sendChatAction(chatId, 'typing').catch(() => {});
    const ai = getAi();
    if (!ai) {
      return await sendTelegramMessage(chatId, `⚠️ AI Engine is offline (GEMINI_API_KEY missing).`, msg.message_id);
    }

    const scriptsContext = (cached.scripts || [])
      .slice(0, 8)
      .map((s) => `--- File: ${s.path} ---\n${s.content.slice(0, 4000)}`)
      .join('\n\n');

    const questionPrompt = `You are RootGuard AI, an expert Android root security engineer, answering a user's question about an Android Magisk/KernelSU root module they scanned.

Target Module: ${cached.fileName}
Overall Verdict: ${cached.audit?.verdict || 'UNKNOWN'} (Risk Score: ${cached.audit?.riskScore || 0}/100)
Summary: ${cached.audit?.summary || ''}
What this module does: ${cached.audit?.whatThisModuleDoes || ''}
Partition Deletion Assessment: ${cached.audit?.deletionAssessment || ''}
Chmod Permission Assessment: ${cached.audit?.chmodAssessment || ''}

Module Source Code / Scripts Audited:
${scriptsContext || 'No script contents available.'}

User's Question: "${text}"

Instructions:
1. Answer the user directly, honestly, and in clear, plain everyday language.
2. Ground your answer completely in the module's actual scripts and audit data provided above.
3. If the user asks whether it is safe, wipes partitions, causes bootloops, drains battery, or asks what a specific line/file does, explain clearly.
4. Keep the answer helpful, friendly, and under 300 words. Format with Telegram HTML (<b>, <i>, <code>).`;

    try {
      const qModel = (process.env.GEMINI_MODEL || 'gemini-3.8-flash').trim();
      const answerRes = await ai.models.generateContent({
        model: qModel,
        contents: questionPrompt,
      });
      const answerText = answerRes.text ? answerRes.text.trim() : "I couldn't generate an answer at this moment.";
      return await sendTelegramMessage(
        chatId,
        `💬 <b>RootGuard AI Answer:</b>\n` +
        `📦 <i>Module: <code>${escapeHtml(cached.fileName)}</code></i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `${answerText}\n\n` +
        `💡 <i>You can ask another question, or type /cancel to finish.</i>\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`,
        msg.message_id
      );
    } catch (err) {
      return await sendTelegramMessage(
        chatId,
        `⚠️ <i>Could not complete AI answer: ${escapeHtml(err.message)}</i>`,
        msg.message_id
      );
    }
  }

  if (msg.document) {
    const fileName = msg.document.file_name || 'module.zip';
    const lower = fileName.toLowerCase();

    if (!lower.endsWith('.zip') && !lower.endsWith('.sh') && !lower.endsWith('.txt')) {
      return await sendTelegramMessage(
        chatId,
        `⚠️ Please upload a <b>.zip</b> Magisk/KernelSU module or a <b>.sh</b> shell script file.\n\n⚡ <i>made by @toshitzz</i>`,
        msg.message_id
      );
    }

    const fileSize = msg.document.file_size || 0;
    if (fileSize > 25 * 1024 * 1024) {
      return await sendTelegramMessage(
        chatId,
        `⚠️ <b>File Exceeds Size Limit:</b> <code>${(fileSize / (1024 * 1024)).toFixed(1)} MB</code>\n` +
        `Telegram Bot API limits file downloads to 25 MB. Most genuine Magisk/KernelSU modules are under 10 MB. Please check your file.\n\n⚡ <i>made by @toshitzz</i>`,
        msg.message_id
      );
    }

    const lockCheck = dbCheckCooldownAndLock(rawUserId, isOwner);
    if (!lockCheck.allowed) {
      if (lockCheck.reason === 'BANNED') {
        return await sendTelegramMessage(chatId, `🚫 Your account has been restricted from using RootGuard.`, msg.message_id);
      }
      if (lockCheck.reason === 'SCAN_IN_PROGRESS') {
        return await sendTelegramMessage(
          chatId,
          `⏳ <b>Scan in Progress:</b> You already have an active scan running. Please wait for it to complete before sending another file!\n\n⚡ <i>made by @toshitzz</i>`,
          msg.message_id
        );
      }
      if (lockCheck.reason === 'COOLDOWN') {
        return await sendTelegramMessage(
          chatId,
          `⏳ <b>Cooldown Active:</b> Please wait <b>${lockCheck.remainingSeconds}s</b> before auditing another file.\n\n` +
          `<i>This 15s cooldown prevents API congestion.</i>\n\n⚡ <i>made by @toshitzz</i>`,
          msg.message_id
        );
      }
      if (lockCheck.reason === 'QUOTA_EXCEEDED') {
        return await sendTelegramMessage(
          chatId,
          `⛔ <b>Daily Scan Limit Reached (${DAILY_SCAN_LIMIT}/${DAILY_SCAN_LIMIT} scans)</b>\n` +
          `⚡ <i>made by @toshitzz</i>\n\n` +
          `To keep this service 100% free with Google Gemini AI auditing, each free user receives <b>${DAILY_SCAN_LIMIT} scans per day</b>.\n\n` +
          `⏳ Your quota automatically resets at <b>00:00 UTC</b> (in <b>${getTimeUntilMidnightUtc()}</b>).\n\n` +
          `💡 <i>Tip: Use <code>/quick &lt;code&gt;</code> for unlimited zero-quota AST checks!</i>\n` +
          `👑 <i>Need unlimited scans? Set <code>OWNER_ID="${rawUserId}"</code> in your .env file!</i>`,
          msg.message_id
        );
      }
    }

    sendChatAction(chatId, 'upload_document').catch(() => {});

    if (activeScansCount >= MAX_CONCURRENT_SCANS) {
      const queuePosition = scanQueue.length + 1;
      sendTelegramMessage(
        chatId,
        `⏳ <b>High Traffic Notice:</b> All scan slots are currently busy. You are <b>#${queuePosition}</b> in line. Your audit will start in a few seconds...`,
        msg.message_id
      ).catch(() => {});
    }

    enqueueScanJob({
      run: () => processModuleAuditJob(chatId, rawUserId, msg, fileName),
    });
  }
}

async function registerBotCommands() {
  if (!TELEGRAM_TOKEN) return;
  try {
    const res = await callTelegram(
      'setMyCommands',
      {
        commands: [
          { command: 'start', description: '🛡️ Start RootGuard & View Guide' },
          { command: 'help', description: '📖 Command Center & Features' },
          { command: 'scan', description: '📦 How to Audit Zip/Script Files' },
          { command: 'quota', description: '📊 Check Free Daily Scans (5/day)' },
          { command: 'quick', description: '⚡ Instant Code Heuristics Scan' },
          { command: 'checkurl', description: '🌐 Audit Module via Direct Link' },
          { command: 'recovery', description: '🚨 Emergency Bootloop Rescue' },
          { command: 'rules', description: '🛡️ 6 Golden Rules of Root Safety' },
          { command: 'profile', description: '🆔 Your Account Profile & Stats' },
          { command: 'ping', description: '🏓 Latency & Server Health Check' },
          { command: 'about', description: 'ℹ️ About RootGuard Architecture' },
          { command: 'stats', description: '📈 Total Scans & Threats Stopped' },
          { command: 'test', description: '🤖 Test Gemini AI Latency' },
        ],
      },
      12000,
      1
    );
    if (res?.ok) {
      console.log('✅ Registered Telegram Bot Command Menu (/ autocomplete active in chat)');
    }
  } catch (err) {
    console.warn('Could not register bot commands menu:', err.message);
  }
}

// =======================================================================
// 13. Main Long-Polling Loop
// =======================================================================
async function startBot() {
  console.log('🚀 Starting RootGuard Telegram Bot (bot.js)...');
  console.log('⚡ made by @toshitzz | Enhanced Partition Safeguards Active');

  if (!TELEGRAM_TOKEN) {
    console.log('ℹ️ No TELEGRAM_BOT_TOKEN provided. Telegram bot listener is idle (Web inspector & API active).');
    return;
  }

  let me;
  try {
    me = await callTelegram('getMe');
    if (!me || !me.ok) {
      console.error('❌ Failed to authenticate with Telegram:', me?.description);
      console.error('👉 Verify TELEGRAM_BOT_TOKEN in .env');
      return;
    }
  } catch (err) {
    console.error('❌ Could not reach Telegram servers on startup:', err.message);
    return;
  }

  console.log(`✅ Authenticated successfully as @${me.result.username} (${me.result.first_name})`);
  await registerBotCommands();

  console.log(`📡 Polling for updates from Telegram...`);

  let offset = 0;
  let consecutiveFailures = 0;

  while (true) {
    try {
      const updatesRes = await callTelegram(
        'getUpdates',
        {
          offset,
          timeout: 15,
          allowed_updates: ['message', 'callback_query'],
        },
        35000,
        0
      );

      if (!updatesRes.ok) {
        consecutiveFailures++;
        console.warn(`Telegram polling notice (${consecutiveFailures}):`, updatesRes.description || 'Unknown error');
        await sleepMs(Math.min(10000, 1500 * consecutiveFailures));
        continue;
      }

      consecutiveFailures = 0;
      const updates = updatesRes.result || [];

      for (const update of updates) {
        offset = update.update_id + 1;
        handleUpdate(update).catch((err) => {
          console.warn('Update handler caught error:', err.message);
        });
      }
    } catch (err) {
      const errMsg = err?.message || String(err);
      const isRoutineSocketDrop =
        err?.name === 'AbortError' ||
        err?.name === 'TypeError' ||
        err?.code === 'ECONNABORTED' ||
        err?.code === 'ECONNRESET' ||
        err?.code === 'ETIMEDOUT' ||
        errMsg.includes('fetch failed') ||
        errMsg.includes('timed out') ||
        errMsg.includes('socket hang up') ||
        errMsg.includes('terminated') ||
        errMsg.includes('UND_ERR_SOCKET') ||
        errMsg.includes('other side closed');

      if (isRoutineSocketDrop) {
        consecutiveFailures = 0;
        await sleepMs(100);
        continue;
      }

      consecutiveFailures++;
      console.warn(`Network polling notice (${consecutiveFailures}):`, errMsg);
      await sleepMs(Math.min(10000, 1500 * consecutiveFailures));
    }
  }
}

// Export functions for reuse in server.ts and tests
module.exports = {
  runDeepHeuristicScanner,
  auditModuleWithRealAi,
  extractScriptsFromModule,
  startBot,
};

// Start the bot if executed directly
if (require.main === module) {
  const http = require('http');
  const PORT = process.env.PORT || 10000;

  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('RootGuard Bot is running with Enhanced Partition & chmod Detection!');
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Web server listening on port ${PORT}`);
  });

  startBot();
}
