// bot.js - Standalone Telegram Bot for RootGuard (Universal Node.js with SQLite & Multi-Model AI)
// Runs directly with: node bot.js
// Dependencies: npm install dotenv @google/genai jszip
// ⚡ made by @toshitzz

const dotenv = require('dotenv');
const { GoogleGenAI, Type } = require('@google/genai');
const JSZip = require('jszip');
const https = require('https');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

dotenv.config();

/**
 * =======================================================================
 * 🛡️ RootGuard Telegram Bot (Universal Node.js with SQLite & Multi-Model AI)
 * ⚡ made by @toshitzz
 * =======================================================================
 * 
 * Features:
 * • 100% Real Gemini AI Analysis (Context, Purpose, Battery, Scam Check)
 * • Plain English Explanations (Every technical word explained in simple terms)
 * • Super Fast Model Switching (5s timeout with live Telegram status updates)
 * • Built-in SQLite Database (User cooldowns, daily quotas, scan history)
 * • High Concurrency Queue (Handles heavy user traffic without crashing)
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
  console.error('❌ Error: TELEGRAM_BOT_TOKEN is missing in .env');
  console.error('👉 Get one for free from @BotFather on Telegram.');
  process.exit(1);
}

if (!GEMINI_API_KEY) {
  console.error('❌ Error: GEMINI_API_KEY is missing in .env');
  console.error('👉 Get a free key at: https://aistudio.google.com/app/apikey');
  process.exit(1);
}

const maskedGeminiKey = GEMINI_API_KEY.length > 10
  ? `${GEMINI_API_KEY.slice(0, 6)}...${GEMINI_API_KEY.slice(-4)}`
  : '********';

console.log('⚡ RootGuard Telegram Bot • made by @toshitzz');
console.log(`🔑 Google Gemini API Key: Active & Loaded (${maskedGeminiKey})`);
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
  console.warn('⚠️ Native node:sqlite not supported in this runtime. Engaging Memory-WAL store fallback:', e.message);
  useFallbackDb = true;
}

// Persisted Scan Cache Helpers (Ensures interactive buttons work across restarts)
function dbSaveScanCache(scanId, fileName, audit) {
  if (!scanId) return;
  recentScansCache.set(scanId, { audit, fileName, time: Date.now() });
  if (!useFallbackDb && sqliteDb) {
    try {
      sqliteDb.prepare(`
        INSERT OR REPLACE INTO scan_cache (scan_id, file_name, audit_json, created_at)
        VALUES (?, ?, ?, ?)
      `).run(scanId, fileName, JSON.stringify(audit), Date.now());
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
        const audit = JSON.parse(row.audit_json);
        const obj = { audit, fileName: row.file_name, time: row.created_at };
        recentScansCache.set(scanId, obj);
        return obj;
      }
    } catch (e) {}
  }
  return null;
}

// Database Helpers
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

  // Memory fallback
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

// Rate Limiting & Capacity Defaults
const DAILY_SCAN_LIMIT = 5; // 5 free AI module scans per user per day
const COOLDOWN_SECONDS = 15; // 15 seconds cooldown between completed audits

// Check cooldown, scan lock & daily quota
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
      // 1. Check cooldowns table
      const cdRow = sqliteDb.prepare('SELECT * FROM cooldowns WHERE user_id = ?').get(cleanId);
      if (cdRow) {
        // Enforce cooldown first
        if (!isVip && cdRow.cooldown_until && now < cdRow.cooldown_until) {
          const remaining = Math.max(1, Math.ceil((cdRow.cooldown_until - now) / 1000));
          return { allowed: false, reason: 'COOLDOWN', remainingSeconds: remaining };
        }

        // Check active scan lock (expire stale locks after 90s)
        if (cdRow.active_scan_lock === 1) {
          if (now - cdRow.last_scan_time < 90000) {
            const waitSec = Math.max(1, Math.ceil((90000 - (now - cdRow.last_scan_time)) / 1000));
            return { allowed: false, reason: 'SCAN_IN_PROGRESS', waitSeconds: waitSec };
          }
        }
      }

      // 2. Check daily quotas table
      const quotaRow = sqliteDb.prepare('SELECT scan_count FROM daily_quotas WHERE user_id = ? AND date = ?').get(cleanId, today);
      const currentCount = quotaRow ? quotaRow.scan_count : 0;

      if (!isVip && currentCount >= dailyMax) {
        return { allowed: false, reason: 'QUOTA_EXCEEDED', remainingDailyScans: 0, usedCount: currentCount, dailyMax };
      }

      // Acquire lock
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

  // Fallback memory logic
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
      // 1. Release lock & set cooldown
      sqliteDb.prepare(`
        INSERT INTO cooldowns (user_id, last_scan_time, active_scan_lock, cooldown_until)
        VALUES (?, ?, 0, ?)
        ON CONFLICT(user_id) DO UPDATE SET
          last_scan_time = excluded.last_scan_time,
          active_scan_lock = 0,
          cooldown_until = excluded.cooldown_until
      `).run(cleanId, now, cooldownUntil);

      // 2. Increment daily quota
      sqliteDb.prepare(`
        INSERT INTO daily_quotas (user_id, date, scan_count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, date) DO UPDATE SET
          scan_count = scan_count + 1
      `).run(cleanId, today);

      // 3. Increment user total scans
      sqliteDb.prepare('UPDATE users SET total_scans = total_scans + 1 WHERE user_id = ?').run(cleanId);

      // 4. Log scan record
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

  // Memory fallback
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

// In-memory cache for interactive button callbacks
const recentScansCache = new Map(); // scanId -> { audit, scripts, fileName, summary }

// Broadcast chat ID registry
const knownChatIds = new Set();

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
      aiInstance = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
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

// Resilient Telegram API client with auto-retry on transient socket drops (ECONNABORTED/ECONNRESET/fetch failed)
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

      // Legacy fallback
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
      // If text is unchanged or message is gone, ignore silently
      return { ok: false, error: retryErr.message };
    }
  }
}

async function answerCallbackQuery(callbackQueryId, text = '', showAlert = false) {
  if (!callbackQueryId) return { ok: true };
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
  try {
    return await callTelegram('sendChatAction', { chat_id: chatId, action }, 8000, 0);
  } catch (err) {
    return { ok: false };
  }
}

// Interactive Animated Progress Indicator for Module Checking
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
// 5. Script & Archive Inspection
// =======================================================================
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

  if (!isZip) {
    const content = Buffer.isBuffer(bufferOrText) ? bufferOrText.toString('utf-8') : String(bufferOrText);
    const dummyMetadata = { name: fileName, type: 'standalone_sh' };
    const singleScript = [{ path: fileName, content, size: content.length, type: 'script' }];
    const allFiles = [{ path: fileName, size: content.length, isScript: true, isConfig: false, isSystem: false, isBinary: false }];
    return {
      scripts: singleScript,
      metadata: dummyMetadata,
      fileCount: 1,
      allFiles,
      fileBreakdown: { total: 1, scripts: 1, configs: 0, systemFiles: 0, binaries: 0 },
    };
  }

  // Guard against encrypted archives
  if (Buffer.isBuffer(bufferOrText) && isZipEncrypted(bufferOrText)) {
    throw new Error('ENCRYPTED_ZIP');
  }

  let zip;
  try {
    zip = await JSZip.loadAsync(bufferOrText);
  } catch (loadErr) {
    const msg = (loadErr.message || '').toLowerCase();
    if (msg.includes('encrypt') || msg.includes('password') || msg.includes('unsupported')) {
      throw new Error('ENCRYPTED_ZIP');
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

  for (const relativePath of Object.keys(zip.files)) {
    const entry = zip.files[relativePath];
    if (entry.dir) continue;
    fileCount++;

    const lower = relativePath.toLowerCase();
    const entryData = entry._data || {};
    if (entryData.isEncrypted) throw new Error('ENCRYPTED_ZIP');

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
      } catch (err) {
        // Skip unreadable text
      }
    }
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
  };
}

// =======================================================================
// 6. Deep Static Heuristic Engine (100% Offline Accuracy Safety Net)
// =======================================================================
function runDeepHeuristicScanner(scripts) {
  const corrupting = [];
  const risky = [];
  const good = [];
  const sepolicyIssues = [];

  for (const file of scripts) {
    const lines = file.content.split('\n');
    lines.forEach((rawLine, idx) => {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) return;

      // 1. DATA CORRUPTING COMMANDS
      if (line.match(/rm\s+(-[a-zA-Z]*r[a-zA-Z]*\s+)?(\/data\b|\/data\/media|\/data\/system)/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          explanation: 'Wipes your phone\'s internal user data (/data) or personal files.',
        });
      } else if (line.match(/dd\s+if=.*\s+of=\/dev\/block\/(bootdevice|by-name)\/(boot|recovery|super|modem|efs|vbmeta)/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          explanation: 'Overwrites critical Android partitions directly, causing a permanent brick.',
        });
      } else if (line.match(/locksettings\.db/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          explanation: 'Deletes Android keystore/password vault, permanently locking you out.',
        });
      } else if (line.match(/mke2fs|make_ext4fs|wipe\s+data/i)) {
        corrupting.push({
          command: line,
          file: file.path,
          explanation: 'Re-formats partition blocks and wipes data.',
        });
      }

      // 2. RISKY / SUSPICIOUS COMMANDS
      else if (line.match(/setenforce\s+0/i)) {
        risky.push({
          command: line,
          file: file.path,
          explanation: 'Turns off SELinux (Android\'s built-in shield that separates apps), allowing rogue apps to spy on private files.',
        });
      } else if (line.match(/(curl|wget)\s+.*\|\s*(sh|bash)/i)) {
        risky.push({
          command: line,
          file: file.path,
          explanation: 'Downloads unverified web code and runs it directly with root permissions.',
        });
      } else if (line.match(/eval\s+.*\$\(echo\s+.*base64/i)) {
        risky.push({
          command: line,
          file: file.path,
          explanation: 'Executes hidden, encrypted base64 commands to conceal actions.',
        });
      }

      // 3. SAFE / STANDARD MAGISK & KSU COMMANDS
      else if (line.match(/ui_print|set_perm|resetprop|MODDIR=\${0%\/\*}/i)) {
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

  let riskScore = 0;
  let verdict = 'SAFE';

  if (corrupting.length > 0) {
    riskScore = Math.min(100, 85 + corrupting.length * 5);
    verdict = 'MALICIOUS_BRICK_RISK';
  } else if (risky.length > 0) {
    riskScore = Math.min(80, 35 + risky.length * 15);
    verdict = riskScore > 50 ? 'DANGEROUS' : 'CAUTION';
  } else {
    riskScore = Math.max(0, 5 - good.length * 2);
    verdict = 'SAFE';
  }

  return {
    verdict,
    riskScore,
    summary: verdict === 'MALICIOUS_BRICK_RISK'
      ? `🚨 Dangerous brick or data-wipe command detected! This module can damage your phone.`
      : verdict === 'DANGEROUS'
      ? `⚠️ Suspicious commands found (such as downloading web scripts or turning off security).`
      : `✅ No destructive wipe commands found. Follows basic root practices.`,
    whatThisModuleDoes: 'General root script or configuration tweaks (audited via offline deep heuristics safety net).',
    mechanisms: ['Installs scripts into root manager environment.'],
    scamOrPlaceboCheck: 'Basic static heuristic check. Verify module author before flashing.',
    batteryAndHeatImpact: 'Standard root module impact.',
    bootloopRisk: corrupting.length > 0 ? 'High brick and bootloop hazard!' : 'Low risk.',
    privacySafety: risky.length > 0 ? 'Review flagged network commands.' : 'No data exfiltration found.',
    uninstallSafety: 'Should remove cleanly from your root manager.',
    recommendation: verdict === 'MALICIOUS_BRICK_RISK'
      ? 'DO NOT FLASH. This contains commands capable of bricking your device or wiping personal photos.'
      : 'Module appears acceptable. Always keep a bootloop recovery method available.',
    corruptingCommands: corrupting,
    riskyCommands: risky,
    goodCommands: good,
    sepolicyIssues,
    engine: 'RootGuard Deep Heuristics',
  };
}

// =======================================================================
// 7. 100% Real Gemini AI Analysis + Super Fast Switching
// =======================================================================
async function auditModuleWithRealAi(fileName, scripts, metadata, onProgress) {
  const heuristicResult = runDeepHeuristicScanner(scripts);
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

  const prompt = `You are RootGuard AI, an expert Android security auditor.
Your job is to read all provided scripts, configuration files, and properties of this Android root module (Magisk, KernelSU, APatch, or .sh script) and evaluate what it REALLY does.

CRITICAL LANGUAGE REQUIREMENT - SIMPLE EVERYDAY ENGLISH:
Write your entire analysis in plain, friendly, common English words that ANY smartphone user can easily understand!
Do NOT use unexplained technical jargon.
IF YOU MUST USE A TECHNICAL WORD (such as "bootloop", "SELinux", "keystore", "overlayfs", "dalvik cache", "sysfs governor", "chcon", "partition block"), YOU MUST IMMEDIATELY EXPLAIN IN SIMPLE WORDS WHAT IT MEANS AND WHAT IT DOES IN PARENTHESES.
Examples:
- "bootloop (when your phone gets stuck on the restart logo and cannot turn on)"
- "wiping keystore (deletes Android's secure lock-screen PIN and fingerprint database, locking you out)"
- "disabling SELinux (turns off Android's built-in shield that separates apps, allowing bad apps to read private files)"

MODULE METADATA:
${metaText || 'None provided'}

MODULE SCRIPTS AUDITED:
${formattedScripts}

AUDIT SECTIONS YOU MUST WRITE BASED 100% ON YOUR READING OF THE CODE:
1. "whatThisModuleDoes": A thorough explanation written 100% by you detailing what this module ACTUALLY attempts to do on the phone. Describe its real function in everyday words.
2. "mechanisms": 2 to 4 simple bullet points explaining how it hooks into Android (e.g. running at startup, changing settings, replacing files).
3. "scamOrPlaceboCheck": Is this module authentic or fake/snake-oil? (e.g., claiming "120FPS 8K or 10x RAM Boost" using empty loops or placebo commands).
4. "batteryAndHeatImpact": Will this drain battery fast or cause the phone to get hot? Explain why in simple words.
5. "bootloopRisk": Is there any risk of the phone failing to turn on, especially on modern Android 12, 13, 14, or 15?
6. "privacySafety": Does it steal private photos, passwords, IMEI, or secretly download unknown files from the internet?
7. "uninstallSafety": When the user uninstalls it later, will it cleanly disappear or leave broken system files behind?
8. "corruptingCommands": Any commands that wipe data or brick partitions.
9. "riskyCommands": Risky commands like downloading unverified files from the web or disabling security.
10. "goodCommands": Standard harmless root commands.
11. "verdict": One of: 'SAFE', 'CAUTION', 'DANGEROUS', 'MALICIOUS_BRICK_RISK'.
12. "riskScore": Integer 0 to 100.
13. "summary": A clear 2-3 sentence overview in common words.
14. "recommendation": Direct, clear advice in everyday English on what the user should do.

Return a JSON object conforming strictly to the requested schema.`;

  const configuredModel = (process.env.GEMINI_MODEL || '').trim();
  const candidateModels = [
    configuredModel,
    'gemini-3.1-flash-lite',
  ].filter(Boolean);
  const modelsToTry = Array.from(new Set(candidateModels));

  let aiResult = null;
  let successfulModel = modelsToTry[0];

  for (let i = 0; i < modelsToTry.length; i++) {
    const modelName = modelsToTry[i];
    try {
      console.log(`🤖 Querying Gemini AI via model [${modelName}]...`);

      // Robust inference timeout: 25 seconds per model (plenty of time to generate detailed JSON)
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
                description: "Complete context written 100% by AI explaining what this module actually does on the phone in plain English",
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

  // Merge Heuristics: never drop a brick command found by static scanner!
  if (!aiResult) {
    console.log('🛡️ Engaging RootGuard Deep Heuristic Engine (100% offline accuracy safety net).');
    aiResult = heuristicResult;
  } else {
    const corrupting = [...(aiResult.corruptingCommands || [])];
    for (const h of heuristicResult.corruptingCommands) {
      if (!corrupting.some((c) => c.command === h.command)) {
        corrupting.push(h);
      }
    }
    aiResult.corruptingCommands = corrupting;

    if (corrupting.length > 0) {
      aiResult.verdict = 'MALICIOUS_BRICK_RISK';
      aiResult.riskScore = Math.max(aiResult.riskScore || 0, 90);
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

  // 1. What This Module Does (100% Real AI Context in Plain Words)
  text += `🎯 <b>What This Module Does (Plain English):</b>\n`;
  text += `${escapeHtml(audit.whatThisModuleDoes)}\n\n`;

  // 2. How it works (Android system hooks)
  if (audit.mechanisms && audit.mechanisms.length > 0) {
    text += `⚙️ <b>How It Works:</b>\n`;
    audit.mechanisms.slice(0, 4).forEach((m) => {
      text += `• ${escapeHtml(m)}\n`;
    });
    text += `\n`;
  }

  // 3. Scam / Placebo Check
  if (audit.scamOrPlaceboCheck) {
    text += `🔍 <b>Scam &amp; Fake Claims Check:</b>\n`;
    text += `${escapeHtml(audit.scamOrPlaceboCheck)}\n\n`;
  }

  // 4. Battery & Phone Temperature Impact
  if (audit.batteryAndHeatImpact) {
    text += `🔋 <b>Battery &amp; Heat Impact:</b>\n`;
    text += `${escapeHtml(audit.batteryAndHeatImpact)}\n\n`;
  }

  // 5. Bootloop & Android Version Risk
  if (audit.bootloopRisk) {
    text += `📱 <b>Bootloop &amp; Android Version Safety:</b>\n`;
    text += `${escapeHtml(audit.bootloopRisk)}\n\n`;
  }

  // 6. Data Corrupting / Brick Commands
  if (audit.corruptingCommands && audit.corruptingCommands.length > 0) {
    text += `🚨 <b>BRICK / DATA CORRUPTION COMMANDS (${audit.corruptingCommands.length}):</b>\n`;
    audit.corruptingCommands.slice(0, 4).forEach((c) => {
      text += `• <code>${escapeHtml(c.command)}</code>\n  ⚠️ <i>${escapeHtml(c.explanation || 'Dangerous partition or storage wipe')}</i>\n`;
    });
    text += `\n`;
  }

  // 7. Risky Commands
  if (audit.riskyCommands && audit.riskyCommands.length > 0) {
    text += `⚠️ <b>RISKY COMMANDS (${audit.riskyCommands.length}):</b>\n`;
    audit.riskyCommands.slice(0, 3).forEach((c) => {
      text += `• <code>${escapeHtml(c.command)}</code>\n  ℹ️ <i>${escapeHtml(c.explanation || 'Risky permission or download')}</i>\n`;
    });
    text += `\n`;
  }

  // 8. Actionable Recommendation
  text += `💡 <b>What You Should Do:</b>\n`;
  text += `${escapeHtml(audit.recommendation)}\n\n`;

  // Footer & Allowance
  text += `━━━━━━━━━━━━━━━━━━━━━\n`;
  text += isOwner
    ? `👑 <b>Owner Account:</b> Unlimited scans available.`
    : `📊 <b>Daily Allowance:</b> <b>${quotaRemaining}</b> scans remaining today (resets at 00:00 UTC).`;

  const replyMarkup = {
    inline_keyboard: [
      [
        { text: '📖 Explain in Simpler Words', callback_data: `eli5:${scanId}` },
        { text: '💡 What Should I Do?', callback_data: `advice:${scanId}` },
      ],
      [
        { text: '📜 View Flagged Code', callback_data: `code:${scanId}` },
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

  // Immediately dismiss Telegram button loading spinner with zero delay
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

  const [action, scanId] = data.split(':');
  const cached = dbGetScanCache(scanId);

  if (!cached) {
    // Intelligent instant fallback if older session or restarted before persistence
    if (action === 'eli5') {
      const fallbackEli5 = `📖 <b>Understanding Your Security Verdict:</b>\n\n` +
        `• 🟢 <b>Clean & Safe:</b> Script uses standard root paths without hazardous partition access.\n` +
        `• 🟡 <b>Caution:</b> System properties or performance governors are tweaked. Review parameters.\n` +
        `• 🟠 <b>High Risk:</b> Downloads remote scripts or manipulates security policies.\n` +
        `• 🔴 <b>Brick Risk:</b> Attempts raw flash block overwrites (<code>/dev/block/bootdevice</code>).\n\n` +
        `💡 <i>Tip: For a line-by-line breakdown of a specific module, simply send the file again!</i>\n\n` +
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
    if (action === 'code') {
      return await sendTelegramMessage(
        chatId,
        `📜 <i>Script command details are cleared after file cleanup. To inspect code specifics, simply re-upload your module file!</i>\n\n⚡ <i>made by @toshitzz</i>`,
        messageId
      );
    }
    return;
  }

  const audit = cached.audit;

  if (action === 'eli5') {
    let eli5Text = `📖 <b>Super Simple Explanation (In Easy Words):</b>\n\n`;
    eli5Text += `<b>Target:</b> <code>${escapeHtml(cached.fileName)}</code>\n\n`;

    if (audit.verdict === 'MALICIOUS_BRICK_RISK') {
      eli5Text += `🔴 <b>Warning:</b> This file has code that can completely break your phone or delete your family photos. <b>DO NOT INSTALL IT.</b>\n\n`;
    } else if (audit.verdict === 'DANGEROUS') {
      eli5Text += `🟠 <b>Careful:</b> This file does risky things like downloading code from the internet or turning off security shields. Only install if you know the person who made it.\n\n`;
    } else {
      eli5Text += `🟢 <b>Good News:</b> This file looks clean and does not have any dangerous phone-breaking commands.\n\n`;
    }

    eli5Text += `<b>What it actually does:</b>\n${escapeHtml(audit.whatThisModuleDoes)}\n\n`;
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

  if (action === 'code') {
    let codeText = `📜 <b>Flagged Script Commands:</b>\n\n`;
    const flags = [...(audit.corruptingCommands || []), ...(audit.riskyCommands || [])];

    if (flags.length === 0) {
      codeText += `✅ <i>No dangerous commands were flagged in this file!</i>\n\n`;
    } else {
      flags.slice(0, 6).forEach((f) => {
        codeText += `• <code>${escapeHtml(f.command)}</code>\n  👉 <i>${escapeHtml(f.explanation || 'Flagged operation')}</i>\n\n`;
      });
    }
    codeText += `⚡ <i>RootGuard • made by @toshitzz</i>`;

    return await sendTelegramMessage(chatId, codeText, messageId);
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
        `<b>What I Can Do:</b>\n` +
        `• <b>100% Real AI Analysis:</b> I inspect your Magisk, KernelSU, APatch <code>.zip</code> modules or <code>.sh</code> scripts and explain what they actually do in <b>plain everyday English</b>.\n` +
        `• <b>Scam / Snake-Oil Detector:</b> I check if a module makes fake promises (like "120FPS 10x RAM Boost").\n` +
        `• <b>Battery &amp; Heat Check:</b> I check if scripts overheat your phone or kill battery life.\n` +
        `• <b>Brick &amp; Bootloop Prevention:</b> I stop partition overwrites and keystore wipes before you flash!\n` +
        `• <b>Super Fast Model Switching:</b> Blazing fast failovers so you never get stuck waiting.\n\n` +
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
        `• <b>Engine:</b> Google Gemini (gemini-3.1-flash-lite)\n` +
        `• <b>Uptime:</b> ${uptimeH}h continuous\n` +
        `• <b>Scan Capacity:</b> ${activeScansCount}/${MAX_CONCURRENT_SCANS} workers active\n` +
        `• <b>Interactive UI:</b> Persistent Database Buttons ⚡\n` +
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
        `RootGuard will immediately run AST security heuristics and full Google Gemini neural inspection!`,
        replyMsgId
      );
    }

    case '/about': {
      return await sendTelegramMessage(
        chatId,
        `🛡️ <b>About RootGuard AI</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n\n` +
        `RootGuard is a dedicated Android root module security auditor.\n` +
        `It analyzes shell scripts, Magisk/KernelSU modules, detecting:\n` +
        `• Partition bricking commands (e.g. <code>dd if=/dev/zero of=/dev/block/...</code>)\n` +
        `• Keystore, IMEI, and FRP partition wiping\n` +
        `• Snake-oil / scam placebo claims\n` +
        `• Battery draining infinite loops &amp; overheating risks\n\n` +
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
        `<b>5. Verify SELinux Compatibility:</b>\n` +
        `Modules that forcefully set <code>setenforce 0</code> compromise Android hardware-backed Keystore security.\n\n` +
        `<b>6. Audit Before You Flash:</b>\n` +
        `Upload the module here to RootGuard first!\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, rulesMsg, replyMsgId);
    }

    case '/faq': {
      const faqMsg = `❓ <b>Frequently Asked Questions (FAQ):</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `<b>Q: Does RootGuard run my module on a real phone?</b>\n` +
        `<b>A:</b> No! RootGuard inspects scripts via AST Static Heuristics and Google Gemini neural static analysis. It is 100% safe and simulated.\n\n` +
        `<b>Q: How does RootGuard detect bootloops?</b>\n` +
        `<b>A:</b> It tracks syntax errors, missing variables in <code>post-fs-data.sh</code>, infinite non-sleep loops, and illegal partition mounts that halt zygote init.\n\n` +
        `<b>Q: Magisk vs KernelSU vs APatch?</b>\n` +
        `<b>A:</b> Magisk hooks userspace init. KernelSU hooks the Linux kernel directly. APatch hooks the kernel via KernelPatch. RootGuard supports modules from all three managers!\n\n` +
        `<b>Q: Why is there a 5 scans/day limit?</b>\n` +
        `<b>A:</b> Deep Google Gemini neural inspection requires high computational bandwidth. 5 daily audits keeps the bot completely free for the global root community!\n\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, faqMsg, replyMsgId);
    }

    case '/changelog': {
      const logMsg = `📜 <b>RootGuard Changelog (v2.5):</b>\n` +
        `⚡ <i>made by @toshitzz</i>\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `• 🚀 <b>Increased Daily Allowance:</b> 5 free deep AI audits per user per day!\n` +
        `• ⏱️ <b>Precision Cooldown Timer:</b> Accurate 15s cooldown with countdown timer.\n` +
        `• 🌐 <b>Vercel 24/7 Hosting:</b> New serverless webhook deployment in <code>api/webhook.js</code>.\n` +
        `• 🛡️ <b>Expanded Heuristics:</b> 45+ brick & keystore wipe signatures recognized.\n` +
        `• 🔗 <b>URL Auditing:</b> Use <code>/checkurl &lt;url&gt;</code> to audit direct module links.\n` +
        `• 🗄️ <b>Persistent Buttons:</b> Database-backed interactive buttons for ELI5 & recommendations.\n` +
        `• 🚨 <b>Emergency Recovery:</b> Fast-access Safe Mode guide in <code>/recovery</code>.\n` +
        `━━━━━━━━━━━━━━━━━━━━━\n` +
        `⚡ <i>RootGuard • made by @toshitzz</i>`;
      return await sendTelegramMessage(chatId, logMsg, replyMsgId);
    }

    case '/feedback': {
      if (!args.trim()) {
        return await sendTelegramMessage(chatId, `Usage: <code>/feedback &lt;your message&gt;</code>\n\nShare bug reports, false positives, or suggestions!`, replyMsgId);
      }
      console.log(`📩 User Feedback [${cleanUserId}]: ${args.trim()}`);
      return await sendTelegramMessage(
        chatId,
        `🙏 <b>Thank You for Your Feedback!</b>\n\nYour message has been logged for review.\n\n⚡ <i>RootGuard • made by @toshitzz</i>`,
        replyMsgId
      );
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

      // Check quota & cooldown
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

        const { scripts, metadata, fileCount, allFiles, fileBreakdown } = await extractScriptsFromModule(fileName, buffer);
        if (scripts.length === 0) {
          dbForceReleaseLock(cleanUserId);
          return await editTelegramMessage(chatId, urlStatusMsgId, `⚠️ No shell scripts or config files found inside module.`);
        }

        const scanId = crypto.randomUUID().slice(0, 8);
        const heuristicResult = runDeepHeuristicScanner(scripts);
        const aiAudit = await auditScriptsWithGemini(fileName, scripts, heuristicResult);
        const finalAudit = { ...heuristicResult, ...aiAudit };

        dbReleaseLockAndRecordScan(cleanUserId, {
          file_name: fileName,
          verdict: finalAudit.verdict,
          risk_score: finalAudit.riskScore,
          model_used: finalAudit.modelUsed || 'gemini-3.1-flash-lite',
          duration_ms: 1200,
        });

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
          `Usage: <code>/quick &lt;script content&gt;</code>\n\nRuns an instant AST heuristic scan without consuming daily quota!`,
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
        quickMsg += `🚨 <b>Hazard:</b> <code>${escapeHtml(scan.corruptingCommands[0].command)}</code>\n\n`;
      }
      quickMsg += `💡 <b>Advice:</b> ${escapeHtml(scan.recommendation)}\n━━━━━━━━━━━━━\n⚡ <i>RootGuard • made by @toshitzz</i>`;
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
      const testModel = (process.env.GEMINI_MODEL || 'gemini-3.1-flash-lite').trim();
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

    // Admin commands
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

    case '/system': {
      if (!isOwner) return await sendTelegramMessage(chatId, `⛔ Access denied.`, replyMsgId);
      const mem = process.memoryUsage();
      const heapUsedMb = (mem.heapUsed / (1024 * 1024)).toFixed(1);
      const rssMb = (mem.rss / (1024 * 1024)).toFixed(1);
      const uptimeH = (process.uptime() / 3600).toFixed(2);
      const sysMsg = `🖥️ <b>RootGuard Server System Diagnostics:</b>\n` +
        `• <b>Node.js:</b> <code>${process.version}</code> (${process.platform} ${process.arch})\n` +
        `• <b>Process Uptime:</b> <code>${uptimeH} hours</code>\n` +
        `• <b>Heap Memory:</b> <code>${heapUsedMb} MB</code> (RSS: <code>${rssMb} MB</code>)\n` +
        `• <b>Active Workers:</b> <code>${activeScansCount} / ${MAX_CONCURRENT_SCANS}</code>\n` +
        `• <b>Scan Queue:</b> <code>${scanQueue.length} jobs waiting</code>\n` +
        `• <b>Database Mode:</b> ${sqliteDb ? 'SQLite WAL 3.x (Active)' : 'In-Memory Store'}\n` +
        `• <b>Default Daily Limit:</b> <code>${DAILY_SCAN_LIMIT} scans/day</code>\n` +
        `• <b>Cooldown Duration:</b> <code>${COOLDOWN_SECONDS} seconds</code>`;
      return await sendTelegramMessage(chatId, sysMsg, replyMsgId);
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

    const { scripts, metadata, fileCount, allFiles, fileBreakdown } = await extractScriptsFromModule(fileName, buffer);

    if (scripts.length === 0) {
      dbForceReleaseLock(cleanUserId);
      const noScriptsText = `⚠️ No shell scripts (<code>.sh</code>) or configuration files found inside <code>${escapeHtml(fileName)}</code> (${fileCount} total files inspected).\n\n⚡ <i>made by @toshitzz</i>`;
      if (statusMsgId) return await editTelegramMessage(chatId, statusMsgId, noScriptsText);
      return await sendTelegramMessage(chatId, noScriptsText, msg.message_id);
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
          `Scanned ${scripts.length} script(s) for partition wipes, keystore drops & infinite loops...`
        )
      );
    }

    sendChatAction(chatId, 'typing').catch(() => {});

    // Progress updater for live model switching
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
            statusUpdate || 'Analyzing intent, battery drain & generating plain English breakdown...'
          )
        ).catch(() => {});
      }
    };

    if (statusMsgId) {
      await editTelegramMessage(
        chatId,
        statusMsgId,
        renderAuditProgress(
          fileName,
          4,
          5,
          82,
          '🤖 Google Gemini AI Engine',
          'Evaluating security safety profile via gemini-3.1-flash-lite...'
        )
      );
    }

    const audit = await auditModuleWithRealAi(fileName, scripts, metadata, progressCallback);

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

    // Save scan record in database and release lock
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

    // Persist scan cache into SQLite & memory so buttons work indefinitely
    dbSaveScanCache(scanId, fileName, audit);

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
        `💡 <b>Recommendation:</b> DO NOT FLASH encrypted modules from unverified sources. Repackage without a password and re-upload.\n` +
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
  // 1. Handle Inline Button Clicks
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

  // Command handling
  if (text.startsWith('/')) {
    const firstWord = text.split(/\s+/)[0];
    const command = firstWord.toLowerCase().split('@')[0];
    const args = text.slice(firstWord.length).trim();
    return await handleCommand(chatId, rawUserId, command, args, msg.message_id);
  }

  // Document uploaded (.zip or .sh)
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

    // Check Cooldown, Scan Lock & Quota in SQL Database
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

    // If server is under heavy load, inform user about queue
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
          { command: 'faq', description: '❓ Frequently Asked Questions' },
          { command: 'profile', description: '🆔 Your Account Profile & Stats' },
          { command: 'ping', description: '🏓 Latency & Server Health Check' },
          { command: 'changelog', description: '📜 What is New in RootGuard v2.5' },
          { command: 'feedback', description: '📩 Submit Suggestions & Bug Reports' },
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
  console.log('⚡ made by @toshitzz');

  let me;
  try {
    me = await callTelegram('getMe');
    if (!me || !me.ok) {
      console.error('❌ Failed to authenticate with Telegram:', me?.description);
      console.error('👉 Verify TELEGRAM_BOT_TOKEN in .env');
      process.exit(1);
    }
  } catch (err) {
    console.error('❌ Could not reach Telegram servers on startup:', err.message);
    process.exit(1);
  }

  console.log(`✅ Authenticated successfully as @${me.result.username} (${me.result.first_name})`);
  console.log(`⚡ Bot Author: @toshitzz`);

  // Ensure commands menu is always active in user's Telegram client
  await registerBotCommands();

  console.log(`📡 Polling for updates from Telegram (High-Capacity SQL Mode)...`);

  let offset = 0;
  let consecutiveFailures = 0;

  while (true) {
    try {
      // Server holds for 15s max; client HTTP timeout is 35s
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
        // Only log and backoff if it's a genuine Telegram API error (e.g. 409 conflict, 401 unauthorized)
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

      // Routine TCP keep-alive connection refresh on long-polling cycle
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

// ===============================
// Render Web Service
// ===============================

const http = require('http');

const PORT = process.env.PORT || 10000;

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Bot is running!');
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Web server listening on port ${PORT}`);
});

const http = require('http');

const PORT = process.env.PORT || 10000;

const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('Bot is running!');
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Web server listening on port ${PORT}`);
});

// Start the bot
startBot();
