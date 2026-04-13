/**
 * RSROLEPLAY Engine - Cloudflare Workers + D1
 * Auto-Installing Serverless Version
 */

// ── CONSTANTS ────────────────────────────────────────────────────────
const SECURITY_HEADERS = {
  'X-Content-Type-Options':  'nosniff',
  'X-Frame-Options':         'DENY',
  'X-XSS-Protection':        '1; mode=block',
  'Referrer-Policy':         'strict-origin-when-cross-origin',
};

// ── UTILITIES ────────────────────────────────────────────────────────
function generateId() {
  return Date.now().toString(36).padStart(11, '0') + '-' + crypto.randomUUID().replace(/-/g, '').substring(0, 8);
}

function str(val, max) {
  if (typeof val !== 'string') return null;
  const s = val.trim();
  if (s.length === 0 || s.length > max) return null;
  return s;
}

function int(val, min, max) {
  const n = Number(val);
  if (!Number.isInteger(n) || n < min || n > max) return null;
  return n;
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...SECURITY_HEADERS, ...extraHeaders },
  });
}

function errResponse(msg, status = 400) {
  return jsonResponse({ error: msg }, status);
}

// ── CRYPTO ───────────────────────────────────────────────────────────
async function pbkdf2(password, saltHex = null) {
  const enc = new TextEncoder();
  let salt;
  if (saltHex) {
    salt = new Uint8Array(saltHex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
  } else {
    salt = crypto.getRandomValues(new Uint8Array(16));
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const hashBuffer = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100_000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const toHex = arr => Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
  return { hash: toHex(new Uint8Array(hashBuffer)), salt: toHex(salt) };
}

async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await pbkdf2(password, storedSalt);
  if (hash.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ storedHash.charCodeAt(i);
  return diff === 0;
}

// ── D1 WRAPPER & AUTO-SETUP ──────────────────────────────────────────
class DB {
  constructor(d1) { this.d1 = d1; }

  async get(sql, params = []) {
    return (await this.d1.prepare(sql).bind(...params).first()) ?? null;
  }

  async all(sql, params = []) {
    const r = await this.d1.prepare(sql).bind(...params).all();
    return r.results ?? [];
  }

  async run(sql, params = []) {
    return this.d1.prepare(sql).bind(...params).run();
  }

  async findOne(table, where) {
    const keys = Object.keys(where);
    const sql  = `SELECT * FROM ${table} WHERE ${keys.map(k => `${k} = ?`).join(' AND ')} LIMIT 1`;
    return this.get(sql, keys.map(k => where[k]));
  }

  async insert(table, doc) {
    const keys = Object.keys(doc);
    const sql  = `INSERT INTO ${table} (${keys.join(', ')}) VALUES (${keys.map(() => '?').join(', ')})`;
    return this.run(sql, keys.map(k => doc[k]));
  }

  async update(table, where, set) {
    const setKeys   = Object.keys(set);
    const whereKeys = Object.keys(where);
    const sql = `UPDATE ${table} SET ${setKeys.map(k => `${k} = ?`).join(', ')} WHERE ${whereKeys.map(k => `${k} = ?`).join(' AND ')}`;
    return this.run(sql, [...setKeys.map(k => set[k]), ...whereKeys.map(k => where[k])]);
  }

  async delete(table, where) {
    const keys = Object.keys(where);
    const sql  = `DELETE FROM ${table} WHERE ${keys.map(k => `${k} = ?`).join(' AND ')}`;
    return this.run(sql, keys.map(k => where[k]));
  }
}

// Automatically creates tables if they are missing
async function checkAndInitDB(db) {
  try {
    await db.get('SELECT 1 FROM users LIMIT 1');
  } catch (e) {
    // If the query fails, it means the tables don't exist. Run Auto-Setup.
    console.log("Initializing Database Schema...");
    await db.d1.exec(`
      CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER);
      CREATE TABLE IF NOT EXISTS user_sessions (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, session_token TEXT UNIQUE NOT NULL, csrf_token TEXT NOT NULL, expires_at INTEGER, created_at INTEGER);
      CREATE TABLE IF NOT EXISTS ip_blocks (id TEXT PRIMARY KEY, failed_attempts INTEGER DEFAULT 0, locked_until INTEGER);
      CREATE TABLE IF NOT EXISTS personas (id TEXT PRIMARY KEY, name TEXT NOT NULL, avatar TEXT, description TEXT, system_prompt TEXT, user_persona TEXT, greeting_message TEXT);
      CREATE TABLE IF NOT EXISTS chat_sessions (id TEXT PRIMARY KEY, label TEXT, persona_id TEXT, created_at INTEGER);
      CREATE TABLE IF NOT EXISTS chat_history (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, group_id TEXT NOT NULL, is_main INTEGER DEFAULT 1, role TEXT NOT NULL, content TEXT NOT NULL, timestamp INTEGER);
      CREATE TABLE IF NOT EXISTS memory_state (id TEXT PRIMARY KEY, session_id TEXT UNIQUE NOT NULL, summarize_threshold INTEGER DEFAULT 50, summarize_count INTEGER DEFAULT 30, context_count INTEGER DEFAULT 20, history_fetch_count INTEGER DEFAULT 50, include_old_summary INTEGER DEFAULT 1, last_summarized_timestamp INTEGER DEFAULT 0, sketchboard_active INTEGER DEFAULT 1, current_summary TEXT);
      CREATE TABLE IF NOT EXISTS sketchboard (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, content TEXT NOT NULL, is_active INTEGER DEFAULT 1, created_at INTEGER);
      CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, name TEXT, provider TEXT NOT NULL, model TEXT NOT NULL, api_key TEXT, custom_url TEXT, key_mode TEXT NOT NULL, is_primary INTEGER DEFAULT 0, created_at INTEGER);
    `);
  }
}

// ── AUTH HELPERS ─────────────────────────────────────────────────────
function getIP(req) {
  return req.headers.get('cf-connecting-ip') ?? '0.0.0.0';
}

async function checkBlock(req, db) {
  const block = await db.findOne('ip_blocks', { id: getIP(req) });
  if (block?.locked_until && Date.now() < block.locked_until) {
    const diff = Math.ceil((block.locked_until - Date.now()) / 1000);
    return `IP locked. Try in ${Math.floor(diff / 60)}m ${diff % 60}s.`;
  }
  return null;
}

async function failLogin(req, db) {
  const ip    = getIP(req);
  const block = await db.findOne('ip_blocks', { id: ip });
  const attempts = (block?.failed_attempts ?? 0) + 1;
  const locked_until = attempts >= 3 ? Date.now() + 30 * 60 * 1000 : null;
  if (block) {
    await db.update('ip_blocks', { id: ip }, { failed_attempts: attempts, locked_until });
  } else {
    await db.insert('ip_blocks', { id: ip, failed_attempts: attempts, locked_until });
  }
}

async function clearBlock(req, db) {
  await db.delete('ip_blocks', { id: getIP(req) });
}

async function auth(req, db) {
  const cookie = req.headers.get('Cookie') ?? '';
  const match  = cookie.match(/aiphp_sess=([A-Za-z0-9\-]+)/);
  if (!match) return null;
  const token = match[1];
  if (!/^[0-9a-f-]{36}$/i.test(token)) return null;

  const session = await db.findOne('user_sessions', { session_token: token });
  if (!session) return null;
  if (session.expires_at < Date.now()) {
    await db.delete('user_sessions', { session_token: token });
    return null;
  }
  return session;
}

// ── MEMORY & CONTEXT ─────────────────────────────────────────────────
async function getMem(sid, db) {
  let row = await db.findOne('memory_state', { session_id: sid });
  if (!row) {
    const global = await db.findOne('memory_state', { session_id: 'global' });
    row = {
      id: generateId(),
      session_id:               sid,
      summarize_threshold:      global?.summarize_threshold      ?? 50,
      summarize_count:          global?.summarize_count          ?? 30,
      context_count:            global?.context_count            ?? 20,
      history_fetch_count:      global?.history_fetch_count      ?? 50,
      include_old_summary:      global?.include_old_summary      ?? 1,
      last_summarized_timestamp: 0,
      sketchboard_active:       global?.sketchboard_active       ?? 1,
      current_summary:          null,
    };
    await db.insert('memory_state', row);
  }
  return row;
}

async function buildCtx(sid, userMsg, db, beforeTs = null) {
  const sessionDoc = await db.findOne('chat_sessions', { id: sid });
  const pid = sessionDoc?.persona_id ?? null;

  let bot = pid ? await db.findOne('personas', { id: pid }) : null;
  if (!bot) {
    const personas = await db.all('SELECT * FROM personas LIMIT 1');
    bot = personas[0] ?? null;
  }

  const mem = await getMem(sid, db);
  const sysParts = [];
  if (bot?.system_prompt)  sysParts.push(bot.system_prompt);
  if (bot?.user_persona)   sysParts.push('About the user: ' + bot.user_persona);

  if (mem.sketchboard_active === 1) {
    const pins = await db.all('SELECT * FROM sketchboard WHERE session_id = ? AND is_active = 1', [sid]);
    if (pins.length > 0) sysParts.push('Key facts (Sketchboard):\n- ' + pins.map(p => p.content).join('\n- '));
  }

  const msgs = [];
  if (sysParts.length > 0) msgs.push({ role: 'system', content: sysParts.join('\n\n') });
  if (mem.current_summary) msgs.push({ role: 'system', content: 'Previous summary:\n' + mem.current_summary });

const ctxCount = Math.max(1, Math.min(mem.context_count ?? 20, 100));
  
  let history;
  if (beforeTs) {
    // FIXED: Always fetch the exact immediate history prior to the regenerated message, ignoring summary markers
    history = await db.all(
      `SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 AND timestamp < ?
       ORDER BY timestamp DESC LIMIT ?`,
      [sid, beforeTs, ctxCount]
    );
  } else {
    // FIXED: Always fetch the latest messages verbatim to guarantee immediate conversational tone
    history = await db.all(
      `SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1
       ORDER BY timestamp DESC LIMIT ?`,
      [sid, ctxCount]
    );
  }
  history.reverse();

  for (const h of history) {
    // Strip <think> blocks so they don't consume context tokens
    const cleanContent = h.content.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
    msgs.push({ role: h.role === 'bot' ? 'assistant' : 'user', content: cleanContent });
  }
  if (userMsg) msgs.push({ role: 'user', content: userMsg });
  return msgs;
}

// ── LLM ──────────────────────────────────────────────────────────────
const THINKING_EFFORTS = new Set(['none', 'low', 'medium', 'high']);

function isThinking(model) {
  const m = model.toLowerCase();
  return ['qwen3', 'deepseek-r1', 'gpt-oss', ':thinking', '-think'].some(x => m.includes(x));
}

async function executeLLM(apiKeys, messages, mode, thinkingEffort, stream) {
  const effort = THINKING_EFFORTS.has(thinkingEffort) ? thinkingEffort : 'none';
  const keys = apiKeys.filter(k => k.key_mode === mode).sort((a, b) => b.is_primary - a.is_primary);
  if (keys.length === 0) throw new Error('No API keys configured for mode: ' + mode);

  let lastErr = '';
  for (const key of keys) {
    try {
const { provider } = key;
      const headers = { 
        'Content-Type': 'application/json', 
        'Accept': 'application/json',
        'Authorization': `Bearer ${key.api_key ?? ''}`,
        'User-Agent': 'curl/8.5.0'
      };
      
      let url;

      // ── 1. URL LOGIC ──
      if (provider === 'cloudflare') {
        // FIXED: Using the v1 completions URL required for newer Gemma models
        url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(key.custom_url)}/ai/v1/chat/completions`;
      } else {
        if      (provider === 'groq')       url = 'https://api.groq.com/openai/v1/chat/completions';
        else if (provider === 'mistral')    url = 'https://api.mistral.ai/v1/chat/completions';
        else if (provider === 'openrouter') {
          url = 'https://openrouter.ai/api/v1/chat/completions';
          headers['HTTP-Referer'] = 'http://localhost';
          headers['X-Title']      = 'AIPHP-Worker';
        } else if (provider === 'custom') {
          if (!key.custom_url) throw new Error('Custom provider requires a URL');
          url = key.custom_url;
        } else {
          throw new Error('Unknown provider: ' + provider);
        }
      }

      // ── 2. MODEL ID LOGIC ──
      const modelId = (provider === 'cloudflare' && !key.model.startsWith('@cf/')) 
                      ? `@cf/${key.model}` 
                      : key.model;

      const body = { model: modelId, messages, stream };

      // ── 3. PARAMETERS LOGIC ──
      if (mode === 'chat') {
        body.max_tokens = 4096;
        body.temperature = 0.85;
        body.top_p = 0.95;
        body.presence_penalty = 0.1;
        body.frequency_penalty = 0.1;

        // PHP FIX: ONLY inject thinking logic if we are in CHAT mode
// PHP FIX: ONLY inject thinking logic if we are in CHAT mode
        if (isThinking(key.model)) {
          if (provider === 'groq') {
            // Groq R1 models FORBID temperature, top_p, and penalties. 
            // We must remove them to avoid API rejection.
            delete body.temperature;
            delete body.top_p;
            delete body.presence_penalty; // <--- Added
            delete body.frequency_penalty; // <--- Added
            // Explicitly set reasoning_effort to "none" if effort is off
            body.reasoning_effort = (effort === 'none') ? 'none' : effort;
          } else if (provider === 'openrouter') {
            body.include_reasoning = true;
            if (effort !== 'none') body.reasoning = { effort };
          }
        }
      } else {
        // Summarize mode: Keep it very standard (Matching your PHP line 301)
        body.max_tokens = 2048;
        body.temperature = 0.8;
        // NEVER send reasoning_effort or penalties during summarization for Groq
      }

      const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
      if (!res.ok) { 
        const errorBody = await res.text();
        lastErr = `${provider} HTTP ${res.status}: ${errorBody.substring(0, 150)}`; 
        continue; 
      }

      if (stream) return { provider, stream: res.body };

      const data = await res.json();
      const msg = data.choices?.[0]?.message;
      if (!msg) throw new Error('No message returned from API');
      
      const content = msg.content ?? '';
      const reasoning = msg.reasoning ?? '';
      return reasoning ? `<think>\n${reasoning}\n</think>\n\n${content}` : content;

    } catch (e) { lastErr = e.message; }
  }
  throw new Error('All API keys failed. Last: ' + lastErr);
}
// ── SSE STREAM ───────────────────────────────────────────────────────
function createUnifiedStream(rawStream, provider, dbSaverCallback) {
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const reader = rawStream.getReader();
  const dec = new TextDecoder(), enc = new TextEncoder();

  async function run() {
    let fullContent = '', fullReasoning = '', buffer = '';
    let hasError = false;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += dec.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop();
        for (let line of lines) {
          line = line.trim();
          if (!line.startsWith('data:')) continue;
          const dataStr = line.slice(5).trim();
          if (!dataStr || dataStr === '[DONE]') continue;
          try {
            const parsed = JSON.parse(dataStr);
            let textChunk = '', reasoningChunk = '';
            
            // Cloudflare v1/chat/completions now uses standard OpenAI delta format
            const delta = parsed.choices?.[0]?.delta ?? {};
            textChunk = delta.content ?? '';
            reasoningChunk = delta.reasoning ?? '';
            if (reasoningChunk) {
              fullReasoning += reasoningChunk;
              await writer.write(enc.encode(`data: ${JSON.stringify({ reasoning: reasoningChunk })}\n\n`));
            }
            if (textChunk) {
              fullContent += textChunk;
              await writer.write(enc.encode(`data: ${JSON.stringify({ chunk: textChunk })}\n\n`));
            }
          } catch { /* malformed chunk */ }
        }
      }
    } catch (e) {
      hasError = true;
      await writer.write(enc.encode(`data: ${JSON.stringify({ error: e.message })}\n\n`));
    } finally {
      const finalOutput = fullReasoning
        ? `<think>\n${fullReasoning}\n</think>\n\n${fullContent}`
        : fullContent;
      const meta = await dbSaverCallback(finalOutput, hasError);
      
      // Ensure the frontend doesn't finalize a broken stream
      if (!hasError) {
        await writer.write(enc.encode(`data: ${JSON.stringify({ done: true, ...meta })}\n\n`));
      }
      await writer.close();
    }
  }
  run();
  return readable;
}

// ── MAIN ROUTER ──────────────────────────────────────────────────────
export default {
  async fetch(request, env) {
    if (!env.DB) {
      return new Response('D1 database binding "DB" not found. Check your Cloudflare settings.', { status: 500 });
    }

    const db     = new DB(env.DB);
    const url    = new URL(request.url);
    const action = url.searchParams.get('action');

    // Run Auto-Setup check on every request
    await checkAndInitDB(db);

    let body = {};
    if (request.method === 'POST') {
      try {
        const text = await request.text();
        if (text.length > 1_000_000) return errResponse('Request too large', 413);
        body = JSON.parse(text);
        if (typeof body !== 'object' || Array.isArray(body)) return errResponse('Invalid JSON body', 400);
      } catch { return errResponse('Invalid JSON body', 400); }
    }

    if (!action) {
      const first = await db.all('SELECT id FROM users LIMIT 1');
      const needsSetup = first.length === 0;
      const html = needsSetup ? getSetupHTML() : getAppHTML();
      return new Response(html, { headers: { 'Content-Type': 'text/html;charset=utf-8', ...SECURITY_HEADERS } });
    }

    // ── SETUP ────────────────────────────────────────────────────
    if (action === 'setup' && request.method === 'POST') {
      const existing = await db.all('SELECT id FROM users LIMIT 1');
      if (existing.length > 0) return errResponse('Already set up', 403);

      const username = str(body.username, 64);
      const password = str(body.password, 128);
      const confirm  = str(body.confirm,  128);
      if (!username)                  return errResponse('Invalid username');
      if (!password || password.length < 6) return errResponse('Password must be at least 6 characters');
      if (password !== confirm)       return errResponse('Passwords do not match');

      const { hash, salt } = await pbkdf2(password);
      const userId = generateId();
      await db.insert('users', { id: userId, username, password_hash: hash, salt, created_at: Date.now() });

      const personaId = generateId();
      await db.insert('personas', {
        id: personaId, name: 'System Assistant', avatar: 'AI',
        description: 'A helpful AI.', system_prompt: 'You are a helpful, concise assistant.',
        user_persona: 'The user is a developer.', greeting_message: 'Hello! How can I help?',
      });
      await db.insert('chat_sessions', { id: 'default', label: 'Default Session', persona_id: null, created_at: Date.now() });
      await db.insert('chat_history', {
        id: generateId(), session_id: 'default', group_id: 'g_' + generateId(),
        is_main: 1, role: 'bot', content: 'Hello! How can I help?', timestamp: Date.now(),
      });
      await db.insert('memory_state', {
        id: 'global', session_id: 'global', summarize_threshold: 50, summarize_count: 30,
        context_count: 20, history_fetch_count: 50, include_old_summary: 1,
        last_summarized_timestamp: 0, sketchboard_active: 1, current_summary: null,
      });
      return jsonResponse({ success: true });
    }

    // ── LOGIN ────────────────────────────────────────────────────
    if (action === 'login' && request.method === 'POST') {
      const block = await checkBlock(request, db);
      if (block) return errResponse(block, 429);

      const username = str(body.username, 64);
      const password = str(body.password, 128);
      if (!username || !password) return errResponse('Invalid credentials', 401);

      const user = await db.findOne('users', { username });
      if (!user) { await failLogin(request, db); return errResponse('Invalid credentials', 401); }

      const valid = await verifyPassword(password, user.password_hash, user.salt);
      if (!valid) { await failLogin(request, db); return errResponse('Invalid credentials', 401); }

      await clearBlock(request, db);
      await db.run('DELETE FROM user_sessions WHERE expires_at < ?', [Date.now()]);

      const token      = crypto.randomUUID();
      const csrf_token = crypto.randomUUID();
      await db.insert('user_sessions', {
        id: generateId(), user_id: user.id, session_token: token, csrf_token,
        expires_at: Date.now() + 30 * 24 * 60 * 60 * 1000, created_at: Date.now(),
      });
      return jsonResponse({ success: true, csrf_token, username: user.username }, 200, {
        'Set-Cookie': `aiphp_sess=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${30 * 24 * 3600}`,
      });
    }

    // ── AUTH WALL ────────────────────────────────────────────────
    const sessionDoc = await auth(request, db);
    if (!sessionDoc) return errResponse('Unauthorized', 401);

    if (request.method === 'POST') {
      const providedCsrf = request.headers.get('X-CSRF-Token');
      if (!providedCsrf || sessionDoc.csrf_token !== providedCsrf) {
        return errResponse('CSRF validation failed', 403);
      }
    }

    const rawSid = request.headers.get('X-Session-Id') ?? url.searchParams.get('session_id') ?? 'default';
    const sid    = str(rawSid, 100) ?? 'default';
    const userId = sessionDoc.user_id;

    try {
      switch (action) {

        case 'logout': {
          await db.delete('user_sessions', { id: sessionDoc.id });
          return jsonResponse({ success: true }, 200, {
            'Set-Cookie': 'aiphp_sess=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
          });
        }

        case 'getInitData': {
          const [personas, mem, sessions, curSess, user] = await Promise.all([
            db.all('SELECT * FROM personas ORDER BY id'),
            getMem(sid, db),
            db.all('SELECT * FROM chat_sessions ORDER BY created_at'),
            db.findOne('chat_sessions', { id: sid }),
            db.findOne('users', { id: userId }),
          ]);
          const current_persona_id = curSess?.persona_id ?? (personas[0]?.id ?? null);
          return jsonResponse({
            personas, current_persona_id, memory: mem,
            csrf_token: sessionDoc.csrf_token, session_id: sid,
            sessions, username: user?.username ?? '',
          });
        }

        case 'sendMessage': {
          const content = str(body.content, 20000);
          if (!content) return errResponse('Empty or too-long message');
          const thinkingEffort = THINKING_EFFORTS.has(body.thinking_effort) ? body.thinking_effort : 'none';

          // Lock the user timestamp
          const userTs = Date.now();
          const userMsgId = generateId();
          await db.insert('chat_history', {
            id: userMsgId, session_id: sid, group_id: 'g_' + generateId(),
            is_main: 1, role: 'user', content, timestamp: userTs,
          });

          const [ctxMsgs, apiKeys] = await Promise.all([
            buildCtx(sid, content, db),
            db.all('SELECT * FROM api_keys'),
          ]);

          let provider, stream;
          try {
            const res = await executeLLM(apiKeys, ctxMsgs, 'chat', thinkingEffort, true);
            provider = res.provider;
            stream = res.stream;
          } catch (e) {
            // Delete user message to prevent orphans if API errors out instantly
            await db.delete('chat_history', { id: userMsgId });
            return errResponse(e.message, 500);
          }

          const unifiedStream = createUnifiedStream(stream, provider, async (finalText, hasError) => {
            if (hasError) {
              // Complete Rollback: Delete user prompt if stream crashes halfway
              await db.delete('chat_history', { id: userMsgId });
              return {};
            }
            const botId   = generateId();
            const groupId = 'g_' + generateId();
            
            // Guarantee chronological order safely 
            let botTs = Date.now();
            if (botTs <= userTs) botTs = userTs + 1;
            
            await db.insert('chat_history', {
              id: botId, session_id: sid, group_id: groupId,
              is_main: 1, role: 'bot', content: finalText, timestamp: botTs,
            });
            const mem    = await getMem(sid, db);
            const lastTs = mem.last_summarized_timestamp ?? 0;
            const row    = await db.get(
              'SELECT COUNT(*) as c FROM chat_history WHERE session_id = ? AND is_main = 1 AND timestamp > ?',
              [sid, lastTs]
            );
            const shouldSummarize = (row?.c ?? 0) >= (mem.summarize_threshold ?? 50);
            return { bot_id: botId, group_id: groupId, should_summarize: shouldSummarize };
          });

          return new Response(unifiedStream, {
            headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS },
          });
        }

        case 'regenerate': {
          const groupId = str(body.group_id, 100);
          if (!groupId) return errResponse('Invalid group_id');
          const oldMsg = await db.get('SELECT * FROM chat_history WHERE group_id = ? AND is_main = 1 LIMIT 1', [groupId]);
          if (!oldMsg)              return errResponse('Not found', 404);
          if (oldMsg.session_id !== sid) return errResponse('Forbidden', 403);

          const [ctxMsgs, apiKeys] = await Promise.all([
            buildCtx(oldMsg.session_id, null, db, oldMsg.timestamp),
            db.all('SELECT * FROM api_keys'),
          ]);
          
          let provider, stream;
          try {
            const res = await executeLLM(apiKeys, ctxMsgs, 'chat', 'none', true);
            provider = res.provider;
            stream = res.stream;
          } catch (e) {
            return errResponse(e.message, 500);
          }

          const unifiedStream = createUnifiedStream(stream, provider, async (finalText, hasError) => {
            if (hasError) return {}; // Do not replace variant if stream fails at all
            await db.run('UPDATE chat_history SET is_main = 0 WHERE group_id = ?', [groupId]);
            const botId = generateId();
            await db.insert('chat_history', {
              id: botId, session_id: oldMsg.session_id,
              group_id: groupId, is_main: 1, role: 'bot', content: finalText, 
              timestamp: oldMsg.timestamp, // Reuse old timestamp to prevent context jumping!
            });
            return { bot_id: botId, content: finalText };
          });

          return new Response(unifiedStream, {
            headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...SECURITY_HEADERS },
          });
        }

        case 'triggerSummarize': {
          const [apiKeys, mem] = await Promise.all([
            db.all('SELECT * FROM api_keys'),
            getMem(sid, db),
          ]);
          const cnt    = Math.max(1, Math.min(mem.summarize_count ?? 30, 200));
          const lastTs = mem.last_summarized_timestamp ?? 0;

          let rows = await db.all(
            'SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 AND timestamp > ? ORDER BY timestamp DESC LIMIT ?',
            [sid, lastTs, cnt]
          );
          if (rows.length === 0 && lastTs > 0) {
            await db.update('memory_state', { session_id: sid }, { last_summarized_timestamp: 0 });
            rows = await db.all(
              'SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 ORDER BY timestamp DESC LIMIT ?',
              [sid, cnt]
            );
          }
          if (rows.length === 0) return jsonResponse({ success: true, summary: mem.current_summary ?? '' });

          rows.reverse();
          const lid   = rows[rows.length - 1].timestamp;
          const lines = rows.map(r => r.role.toUpperCase() + ': ' + r.content.replace(/<think>[\s\S]*?<\/think>/gi, '').trim()).join('\n');
          const old   = (mem.include_old_summary && mem.current_summary)
            ? 'Previous summary:\n' + mem.current_summary + '\n\n' : '';

          const messages = [
            { role: 'system', content: 'Summarize the chat history concisely. Keep key facts, decisions, names, and context.' },
            { role: 'user',   content: old + 'Messages:\n\n' + lines },
          ];
          
          let resultText;
          try {
            resultText = await executeLLM(apiKeys, messages, 'summarize', 'none', false);
          } catch (e) {
            return errResponse(e.message, 500);
          }
          
          const cleanSummary = resultText.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();

          await db.update('memory_state', { session_id: sid }, {
            current_summary: cleanSummary, last_summarized_timestamp: lid,
          });
          return jsonResponse({ success: true, summary: cleanSummary });
        }

        case 'getChatHistory': {
          const mem      = await getMem(sid, db);
          const limit    = Math.max(10, Math.min(mem.history_fetch_count ?? 50, 200));
          const beforeTs = parseInt(url.searchParams.get('before_timestamp') ?? '0', 10);

          const rows = beforeTs > 0
            ? await db.all('SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 AND timestamp < ? ORDER BY timestamp DESC LIMIT ?', [sid, beforeTs, limit])
            : await db.all('SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 ORDER BY timestamp DESC LIMIT ?', [sid, limit]);

          rows.reverse();
          const result = [];
          for (const msg of rows) {
            if (msg.role === 'bot') {
              const vars = await db.all('SELECT * FROM chat_history WHERE group_id = ? ORDER BY timestamp', [msg.group_id]);
              let ai = 0;
              vars.forEach((v, i) => { if (v.is_main === 1) ai = i; });
              msg.variants     = vars.map(v => v.content);
              msg.variant_ids  = vars.map(v => v.id);
              msg.active_index = ai;
              msg.id           = vars[ai]?.id ?? msg.id;
            }
            result.push(msg);
          }

          let hasMore = false;
          if (rows.length > 0) {
            const oldest = rows[0].timestamp;
            const more   = await db.all('SELECT id FROM chat_history WHERE session_id = ? AND is_main = 1 AND timestamp < ? LIMIT 1', [sid, oldest]);
            hasMore = more.length > 0;
          }
          return jsonResponse({ messages: result, has_more: hasMore });
        }

        case 'setMainVariant': {
          const id = str(body.id, 100);
          if (!id) return errResponse('Invalid id');
          const row = await db.findOne('chat_history', { id });
          if (!row)                  return errResponse('Not found', 404);
          if (row.session_id !== sid) return errResponse('Forbidden', 403);
          await db.run('UPDATE chat_history SET is_main = 0 WHERE group_id = ?', [row.group_id]);
          await db.update('chat_history', { id }, { is_main: 1 });
          return jsonResponse({ success: true });
        }

        case 'keepVersionOnly': {
          const id = str(body.id, 100);
          if (!id) return errResponse('Invalid id');
          const row = await db.findOne('chat_history', { id });
          if (!row)                  return errResponse('Not found', 404);
          if (row.session_id !== sid) return errResponse('Forbidden', 403);
          await db.run('DELETE FROM chat_history WHERE group_id = ? AND id != ?', [row.group_id, id]);
          await db.update('chat_history', { id }, { is_main: 1 });
          return jsonResponse({ success: true });
        }

        case 'editMessage': {
          const id      = str(body.id, 100);
          const content = str(body.content, 20000);
          if (!id || !content) return errResponse('Invalid input');
          const row = await db.findOne('chat_history', { id });
          if (!row)                  return errResponse('Not found', 404);
          if (row.session_id !== sid) return errResponse('Forbidden', 403);
          await db.update('chat_history', { id }, { content });
          return jsonResponse({ success: true });
        }

        case 'deleteMessage': {
          const id = str(body.id, 100);
          if (!id) return errResponse('Invalid id');
          const row = await db.findOne('chat_history', { id });
          if (!row)                  return errResponse('Not found', 404);
          if (row.session_id !== sid) return errResponse('Forbidden', 403);
          await db.run('DELETE FROM chat_history WHERE group_id = ?', [row.group_id]);
          return jsonResponse({ success: true });
        }

        case 'rewindChat': {
          const id = str(body.id, 100);
          if (!id) return errResponse('Invalid id');
          const row = await db.findOne('chat_history', { id });
          if (!row)                  return errResponse('Not found', 404);
          if (row.session_id !== sid) return errResponse('Forbidden', 403);
          await db.run('DELETE FROM chat_history WHERE session_id = ? AND timestamp > ?', [sid, row.timestamp]);
          return jsonResponse({ success: true });
        }

        case 'updateSummary': {
          const summary = (typeof body.summary === 'string' ? body.summary : '').substring(0, 20000);
          await db.update('memory_state', { session_id: sid }, { current_summary: summary });
          return jsonResponse({ success: true });
        }

        case 'manageKeys': {
          const op = str(body.op, 20);
          if (op === 'list') {
            const keys = await db.all('SELECT * FROM api_keys ORDER BY is_primary DESC, id');
            return jsonResponse(keys.map(k => ({ ...k, masked_key: k.api_key ? k.api_key.substring(0, 7) + '...' : '', api_key: undefined })));
          }
          if (op === 'add' || op === 'edit') {
            const provider  = str(body.provider,   50);
            const model     = str(body.model,      200);
            const keyMode   = str(body.key_mode,   20);
            const name      = str(body.name,       100) ?? '';
            const customUrl = typeof body.custom_url === 'string' ? body.custom_url.trim().substring(0, 500) : '';
            const apiKeyVal = typeof body.api_key  === 'string' ? body.api_key.trim().substring(0, 300) : '';
            const isPrimary = body.is_primary ? 1 : 0;

            if (!provider || !model || !keyMode) return errResponse('provider, model, key_mode required');
            if (!['groq','mistral','openrouter','cloudflare','custom'].includes(provider)) return errResponse('Unknown provider');
            if (!['chat','summarize'].includes(keyMode)) return errResponse('Invalid key_mode');

            if (isPrimary) await db.run('UPDATE api_keys SET is_primary = 0 WHERE key_mode = ?', [keyMode]);

            if (op === 'add') {
              await db.insert('api_keys', {
                id: generateId(), name, provider, model, key_mode: keyMode,
                api_key: apiKeyVal, custom_url: customUrl, is_primary: isPrimary, created_at: Date.now(),
              });
            } else {
              const id = str(body.id, 100);
              if (!id) return errResponse('Missing id');
              const setFields = { name, provider, model, key_mode: keyMode, custom_url: customUrl, is_primary: isPrimary };
              if (apiKeyVal) setFields.api_key = apiKeyVal;
              await db.update('api_keys', { id }, setFields);
            }
            return jsonResponse({ success: true });
          }
          if (op === 'delete') {
            const id = str(body.id, 100);
            if (!id) return errResponse('Invalid id');
            await db.delete('api_keys', { id });
            return jsonResponse({ success: true });
          }
          return errResponse('Unknown op');
        }

case 'testKey': {
          const id = str(body.id, 100);
          if (!id) return errResponse('Invalid id');
          const k = await db.findOne('api_keys', { id });
          if (!k) return errResponse('Key not found', 404);

          let url;
          if (k.provider === 'cloudflare') url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(k.custom_url)}/ai/v1/chat/completions`;
          else if (k.provider === 'groq') url = 'https://api.groq.com/openai/v1/chat/completions';
          else if (k.provider === 'mistral') url = 'https://api.mistral.ai/v1/chat/completions';
          else if (k.provider === 'openrouter') url = 'https://openrouter.ai/api/v1/chat/completions';
          else url = k.custom_url;

          const modelId = (k.provider === 'cloudflare' && !k.model.startsWith('@cf/')) ? `@cf/${k.model}` : k.model;

          try {
            const res = await fetch(url, {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${k.api_key ?? ''}`,
                'User-Agent': 'curl/8.5.0'
              },
              body: JSON.stringify({
                model: modelId,
                messages: [{ role: 'user', content: 'Say "ok" only.' }],
                max_tokens: 5,
                stream: false
              })
            });

            if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`);
            return jsonResponse({ ok: true, model: k.model, provider: k.provider });
          } catch (e) {
            return jsonResponse({ ok: false, error: e.message.substring(0, 200) });
          }
        }

        case 'managePersonas': {
          const op = str(body.op, 20);
          if (op === 'list') return jsonResponse(await db.all('SELECT * FROM personas ORDER BY id'));
          if (op === 'add' || op === 'edit') {
            const name = str(body.name, 100);
            if (!name) return errResponse('Name required');
            const payload = {
              name,
              avatar:           str(body.avatar,           50)    ?? 'AI',
              description:      str(body.description,      500)   ?? '',
              system_prompt:    str(body.system_prompt,    10000) ?? '',
              user_persona:     str(body.user_persona,     5000)  ?? '',
              greeting_message: str(body.greeting_message, 2000)  ?? '',
            };
            if (op === 'add') {
              await db.insert('personas', { id: generateId(), ...payload });
            } else {
              const id = str(body.id, 100);
              if (!id) return errResponse('Missing id');
              await db.update('personas', { id }, payload);
            }
            return jsonResponse({ success: true });
          }
          if (op === 'delete') {
            const id = str(body.id, 100);
            if (!id) return errResponse('Invalid id');
            await db.delete('personas', { id });
            await db.run('UPDATE chat_sessions SET persona_id = NULL WHERE persona_id = ?', [id]);
            return jsonResponse({ success: true });
          }
          return errResponse('Unknown op');
        }

        case 'setSessionPersona': {
          const sessionId = str(body.session_id, 100) ?? sid;
          const personaId = typeof body.persona_id === 'string' && body.persona_id.trim() ? body.persona_id.trim() : null;
          await db.update('chat_sessions', { id: sessionId }, { persona_id: personaId });
          return jsonResponse({ success: true });
        }

        case 'updateMemoryConfig': {
          const m = body.memory;
          if (typeof m !== 'object' || !m) return errResponse('Invalid memory config');
          const cfg = {
            summarize_threshold:  int(m.summarize_threshold,  5, 500)  ?? 50,
            summarize_count:      int(m.summarize_count,      5, 500)  ?? 30,
            context_count:        int(m.context_count,        5, 200)  ?? 20,
            history_fetch_count:  int(m.history_fetch_count,  10, 500) ?? 50,
            include_old_summary:  m.include_old_summary ? 1 : 0,
          };
          await Promise.all([
            db.update('memory_state', { session_id: sid },      cfg),
            db.update('memory_state', { session_id: 'global' }, cfg),
          ]);
          return jsonResponse({ success: true });
        }

        case 'updateAccount': {
          const user        = await db.findOne('users', { id: userId });
          const currentPass = str(body.current_password, 128);
          if (!currentPass) return errResponse('Current password required');
          if (!(await verifyPassword(currentPass, user.password_hash, user.salt))) return errResponse('Current password incorrect', 403);

          const newUsername = str(body.username, 64);
          if (!newUsername) return errResponse('Invalid username');
          const existing = await db.findOne('users', { username: newUsername });
          if (existing && existing.id !== userId) return errResponse('Username already taken', 409);

          const update = { username: newUsername };
          const newPass = str(body.password, 128);
          if (newPass) {
            if (newPass.length < 6) return errResponse('Password min 6 chars');
            const { hash, salt } = await pbkdf2(newPass);
            update.password_hash = hash;
            update.salt          = salt;
          }
          await db.update('users', { id: userId }, update);
          return jsonResponse({ success: true });
        }

        case 'manageSketchboard': {
          const op = str(body.op, 20);
          if (op === 'list') {
            const [pins, mem] = await Promise.all([
              db.all('SELECT * FROM sketchboard WHERE session_id = ? ORDER BY created_at DESC', [sid]),
              getMem(sid, db),
            ]);
            return jsonResponse({ pins, global_active: mem.sketchboard_active ?? 1 });
          }
          if (op === 'add') {
            const content = str(body.content, 2000);
            if (!content) return errResponse('Empty content');
            await db.insert('sketchboard', { id: generateId(), session_id: sid, content, is_active: 1, created_at: Date.now() });
            return jsonResponse({ success: true });
          }
          if (op === 'edit') {
            const id = str(body.id, 100), content = str(body.content, 2000);
            if (!id || !content) return errResponse('Invalid input');
            await db.run('UPDATE sketchboard SET content = ? WHERE id = ? AND session_id = ?', [content, id, sid]);
            return jsonResponse({ success: true });
          }
          if (op === 'delete') {
            const id = str(body.id, 100);
            if (!id) return errResponse('Invalid id');
            await db.run('DELETE FROM sketchboard WHERE id = ? AND session_id = ?', [id, sid]);
            return jsonResponse({ success: true });
          }
          if (op === 'togglePin') {
            const id = str(body.id, 100);
            if (!id) return errResponse('Invalid id');
            const p = await db.get('SELECT * FROM sketchboard WHERE id = ? AND session_id = ?', [id, sid]);
            if (!p) return errResponse('Not found', 404);
            await db.run('UPDATE sketchboard SET is_active = ? WHERE id = ? AND session_id = ?', [p.is_active ? 0 : 1, id, sid]);
            return jsonResponse({ success: true });
          }
          if (op === 'toggleGlobal') {
            await db.update('memory_state', { session_id: sid }, { sketchboard_active: body.active ? 1 : 0 });
            return jsonResponse({ success: true });
          }
          return errResponse('Unknown op');
        }

        case 'manageSessions': {
          const op = str(body.op, 20);
          if (op === 'switch') {
            const sessionId = str(body.session_id, 100);
            if (!sessionId) return errResponse('Invalid session_id');
            const exist = await db.findOne('chat_sessions', { id: sessionId });
            if (!exist) return errResponse('Not found', 404);
            return jsonResponse({ success: true, session_id: sessionId });
          }
          if (op === 'new') {
            const label     = str(body.label, 100) ?? 'New Session';
            const personaId = typeof body.persona_id === 'string' && body.persona_id.trim() ? body.persona_id.trim() : null;
            const id = generateId();
            await db.insert('chat_sessions', { id, label, persona_id: personaId, created_at: Date.now() });
            const bot = personaId
              ? await db.findOne('personas', { id: personaId })
              : (await db.all('SELECT * FROM personas LIMIT 1'))[0] ?? null;
            if (bot?.greeting_message) {
              await db.insert('chat_history', {
                id: generateId(), session_id: id, group_id: 'g_' + generateId(),
                is_main: 1, role: 'bot', content: bot.greeting_message, timestamp: Date.now(),
              });
            }
            return jsonResponse({ success: true, session_id: id, label });
          }
          if (op === 'rename') {
            const sessionId = str(body.session_id, 100), label = str(body.label, 100);
            if (!sessionId || !label) return errResponse('Invalid input');
            await db.update('chat_sessions', { id: sessionId }, { label });
            return jsonResponse({ success: true });
          }
          if (op === 'delete') {
            const sessionId = str(body.session_id, 100);
            if (!sessionId) return errResponse('Invalid session_id');
            if (sessionId === 'default') return errResponse('Cannot delete default session');
            await Promise.all([
              db.run('DELETE FROM chat_history WHERE session_id = ?',  [sessionId]),
              db.run('DELETE FROM memory_state  WHERE session_id = ?', [sessionId]),
              db.run('DELETE FROM sketchboard   WHERE session_id = ?', [sessionId]),
              db.delete('chat_sessions', { id: sessionId }),
            ]);
            return jsonResponse({ success: true });
          }
          return errResponse('Unknown op');
        }

        case 'exportData': {
          const rows = await db.all('SELECT * FROM chat_history WHERE session_id = ? AND is_main = 1 ORDER BY timestamp', [sid]);
          const out  = rows.map(r => `{${r.role === 'user' ? 'user' : 'bot'}}\n${r.content.trim()}\n{/${r.role === 'user' ? 'user' : 'bot'}}`).join('\n\n');
          return new Response(out, {
            headers: { 'Content-Type': 'text/plain;charset=utf-8', 'Content-Disposition': `attachment; filename="chat_${Date.now()}.txt"`, ...SECURITY_HEADERS },
          });
        }

        case 'importData': {
          if (typeof body.data !== 'string') return errResponse('Invalid data');
          if (body.data.length > 500_000)    return errResponse('Import too large', 413);
          const regex = /\{(user|bot)\}\s*([\s\S]*?)\s*\{\/(user|bot)\}/g;
          let match, cnt = 0;
          while ((match = regex.exec(body.data)) !== null && cnt < 2000) {
            if (match[1] !== match[3]) continue;
            const content = match[2].trim().substring(0, 20000);
            if (!content) continue;
            await db.insert('chat_history', {
              id: generateId(), session_id: sid, group_id: 'g_' + generateId(),
              is_main: 1, role: match[1], content, timestamp: Date.now() + cnt,
            });
            cnt++;
          }
          return jsonResponse({ success: true, imported: cnt });
        }

        case 'nukeServer': {
          const user = await db.findOne('users', { id: userId });
          const pass = str(body.password, 128);
          if (!pass) return errResponse('Password required');
          if (!(await verifyPassword(pass, user.password_hash, user.salt))) return errResponse('Wrong password', 403);

          await Promise.all([
            db.run('DELETE FROM chat_history'),
            db.run('DELETE FROM memory_state'),
            db.run('DELETE FROM sketchboard'),
            db.run('DELETE FROM personas'),
            db.run('DELETE FROM api_keys'),
            db.run('DELETE FROM ip_blocks'),
            db.run('DELETE FROM chat_sessions'),
            db.run('DELETE FROM user_sessions'),
          ]);
          const { hash, salt } = await pbkdf2(crypto.randomUUID());
          await db.update('users', { id: userId }, {
            username: crypto.randomUUID().substring(0, 8), password_hash: hash, salt,
          });
          return jsonResponse({ success: true }, 200, {
            'Set-Cookie': 'aiphp_sess=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0',
          });
        }

        default:
          return errResponse('Unknown action', 404);
      }
    } catch (e) {
      console.error('Handler error:', e);
      return errResponse(e.message || 'Internal server error', 500);
    }
  },
};

// ── HTML PAGES ───────────────────────────────────────────────────────

// Full application injected safely to prevent templating string collisions.
function getAppHTML() {
  return `<!DOCTYPE html>
<html lang="en" class="light">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>RSROLEPLAY Engine</title>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
<script src="https://unpkg.com/lucide@latest"></script>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.css">
<script src="https://cdn.jsdelivr.net/npm/katex@0.16.9/dist/katex.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/marked-katex-extension@5.0.0/lib/index.umd.js"></script>
<script>tailwind.config={darkMode:'class',theme:{extend:{fontFamily:{sans:['Inter','-apple-system','sans-serif']},animation:{'pulse-slow':'pulse 3s cubic-bezier(0.4,0,0.6,1) infinite','slide-up':'slideUp .25s ease-out forwards'},keyframes:{slideUp:{'0%':{transform:'translateY(6px)',opacity:'0'},'100%':{transform:'translateY(0)',opacity:'1'}}}}}}</script>
<style>
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:#e5e5e5;border-radius:10px}.dark ::-webkit-scrollbar-thumb{background:#404040}
.hf{display:none!important}
.swipeable{transition:transform .18s ease-out;touch-action:pan-y}.swiping{transition:none}
.msg-content p{margin-bottom:.5em}.msg-content p:last-child{margin-bottom:0}
.msg-content code{background:rgba(127,127,127,.18);padding:.15em .35em;border-radius:4px;font-family:monospace;font-size:.85em}
.msg-content pre{background:rgba(127,127,127,.1);padding:1em;border-radius:8px;overflow-x:auto;margin-bottom:1em;border:1px solid rgba(127,127,127,.12)}
.msg-content pre code{background:transparent;padding:0}
.msg-content strong{font-weight:600}.msg-content ul{list-style-type:disc;padding-left:1.5em;margin-bottom:.5em}.msg-content ol{list-style-type:decimal;padding-left:1.5em;margin-bottom:.5em}
.msg-content h1,.msg-content h2,.msg-content h3{font-weight:700;margin:.6em 0 .3em}
.msg-content table{border-collapse:collapse;width:100%;margin:.5em 0}.msg-content th,.msg-content td{border:1px solid #ccc;padding:.3em .6em}.dark .msg-content th,.dark .msg-content td{border-color:#444}
</style>
</head>
<body class="bg-white dark:bg-black text-black dark:text-white font-sans h-[100dvh] flex overflow-hidden transition-colors duration-300" onclick="closeAllDropdowns()">

<div id="global-dropdown" class="fixed w-52 bg-white dark:bg-[#111] border border-gray-200 dark:border-gray-800 rounded-lg shadow-xl hf py-1 z-[9999]"></div>
<div id="toast" class="fixed bottom-32 md:bottom-24 left-1/2 -translate-x-1/2 bg-black dark:bg-white text-white dark:text-black px-4 py-2 rounded-full text-xs shadow-lg z-[9999] hf pointer-events-none animate-slide-up whitespace-nowrap"></div>

<!-- LOGIN -->
<div id="login-screen" class="fixed inset-0 bg-gray-50 dark:bg-[#0a0a0a] flex items-center justify-center z-50">
  <div class="w-[calc(100%-2rem)] max-w-sm bg-white dark:bg-[#111] border border-gray-200 dark:border-gray-800 rounded-2xl shadow-2xl p-6 md:p-8 mx-auto">
    <div class="flex items-center space-x-3 mb-8"><div class="w-8 h-8 bg-black dark:bg-white rounded-md flex items-center justify-center"><span class="text-white dark:text-black text-xs font-bold">AI</span></div><h1 class="text-xl font-bold tracking-tight">RSROLEPLAY Engine</h1></div>
    <div id="login-error" class="hf mb-4 text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg"></div>
    <div class="space-y-4">
      <div><label class="block text-xs font-medium text-gray-500 mb-1">Username</label><input id="login-user" type="text" placeholder="admin" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-sm outline-none focus:border-black dark:focus:border-white transition-colors"></div>
      <div><label class="block text-xs font-medium text-gray-500 mb-1">Password</label><input id="login-pass" type="password" placeholder="••••••" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-sm outline-none focus:border-black dark:focus:border-white transition-colors"></div>
      <button id="login-btn" onclick="doLogin()" class="w-full bg-black dark:bg-white text-white dark:text-black py-3 rounded-lg text-sm font-medium hover:opacity-80 transition-opacity flex items-center justify-center space-x-2"><span>Sign In</span></button>
    </div>
  </div>
</div>

<!-- APP -->
<div id="app" class="hf flex w-full h-full relative">

<!-- Sidebar Overlay (Mobile) -->
<div id="sidebar-overlay" onclick="toggleSidebar()" class="fixed inset-0 bg-black/50 z-30 md:hidden hf backdrop-blur-sm opacity-0 transition-opacity duration-300"></div>

<!-- Left Sidebar -->
<aside id="left-sidebar" class="fixed inset-y-0 left-0 w-64 transform -translate-x-full md:relative md:translate-x-0 border-r border-gray-200 dark:border-gray-800 flex flex-col justify-between bg-gray-50 dark:bg-[#111] flex-shrink-0 z-40 transition-transform duration-300">
  <div>
    <div class="h-16 flex items-center px-6 border-b border-gray-200 dark:border-gray-800 justify-between">
      <div class="flex items-center">
        <div class="w-6 h-6 bg-black dark:bg-white rounded-sm flex items-center justify-center mr-3"><span class="text-white dark:text-black text-[10px] font-bold">AI</span></div>
        <h1 class="font-semibold tracking-tight text-sm">RSROLEPLAY Engine</h1>
      </div>
      <button onclick="toggleSidebar()" class="md:hidden text-gray-500"><i data-lucide="x" class="w-4 h-4"></i></button>
    </div>
    <nav class="p-4 space-y-1">
      <button onclick="closeSidebarOnMobile();closeModals()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md bg-black dark:bg-white text-white dark:text-black"><i data-lucide="message-square" class="w-4 h-4"></i><span>Current Chat</span></button>
      <button onclick="openModal('sessions-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="folder-open" class="w-4 h-4"></i><span>Manage Sessions</span></button>
      <button onclick="openModal('persona-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="users" class="w-4 h-4"></i><span>Personas & Prompts</span></button>
      <button onclick="openModal('memory-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="brain" class="w-4 h-4"></i><span>Memory Rules</span></button>
      <button onclick="openModal('keys-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="key" class="w-4 h-4"></i><span>API Endpoints</span></button>
      <button onclick="openModal('sync-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="refresh-cw" class="w-4 h-4"></i><span>Data Sync</span></button>
      <button onclick="toggleTheme()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="moon" id="theme-icon" class="w-4 h-4"></i><span>Toggle Theme</span></button>
    </nav>
  </div>
  <div class="p-4 border-t border-gray-200 dark:border-gray-800 space-y-1">
    <button onclick="openModal('account-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="user-cog" class="w-4 h-4"></i><span id="sidebar-uname">Account</span></button>
    <button onclick="openModal('nuke-modal');closeSidebarOnMobile()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors"><i data-lucide="settings" class="w-4 h-4"></i><span>Nuke Server!</span></button>
    <button onclick="doLogout()" class="w-full flex items-center space-x-3 px-3 py-2 text-sm font-medium rounded-md text-red-500 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"><i data-lucide="log-out" class="w-4 h-4"></i><span>Logout</span></button>
    <a href="https://miku.us.kg" target="_blank" class="block pt-4 pb-2 text-center text-[10px] text-gray-400 hover:text-black dark:hover:text-white transition-colors">RSROLEPLAY 2026 - Made by @redsus.vn</a>
  </div>
</aside>

<!-- Main Chat Area -->
<main class="flex-1 flex flex-col h-full relative min-w-0 bg-white dark:bg-black">
  <header class="h-16 border-b border-gray-200 dark:border-gray-800 flex items-center justify-between px-4 sm:px-6 bg-white/80 dark:bg-black/80 backdrop-blur-md sticky top-0 z-10">
    <div class="flex items-center space-x-2 sm:space-x-3">
      <button onclick="toggleSidebar()" class="md:hidden p-1.5 -ml-1 text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="menu" class="w-5 h-5"></i></button>
      
      <button id="header-persona-btn" onclick="togglePersonaDropdown(event)" class="flex items-center space-x-2 sm:space-x-3 text-left hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg p-1.5 -ml-1.5 transition-colors focus:outline-none" title="Change Persona for this session">
        <div class="w-8 h-8 rounded-full bg-gray-200 dark:bg-gray-800 flex items-center justify-center border border-gray-300 dark:border-gray-700 overflow-hidden flex-shrink-0" id="header-avatar"><span class="text-xs font-bold text-gray-600 dark:text-gray-300">AI</span></div>
        <div>
            <h2 class="text-[13px] sm:text-sm font-semibold flex items-center space-x-1"><span id="header-name">System Assistant</span><i data-lucide="chevron-down" class="w-3.5 h-3.5 text-gray-400"></i></h2>
            <div class="flex items-center text-[10px] sm:text-xs text-gray-500 dark:text-gray-400"><span class="w-2 h-2 rounded-full bg-green-500 animate-pulse-slow mr-1.5"></span><span id="header-sess" class="truncate max-w-[120px] sm:max-w-[200px]">default</span></div>
        </div>
      </button>

    </div>
    <button onclick="toggleSketchboard();event.stopPropagation();" class="flex items-center space-x-1.5 sm:space-x-2 px-2.5 sm:px-3 py-1.5 border border-gray-200 dark:border-gray-800 rounded-full hover:bg-gray-50 dark:hover:bg-gray-900 transition-colors text-xs font-medium">
      <span id="sketch-led" class="w-2 h-2 rounded-full bg-gray-400 flex-shrink-0 transition-colors"></span><i data-lucide="pin" class="w-3.5 h-3.5 sm:hidden"></i><span class="hidden sm:inline">Sketchboard</span>
      <span id="sketch-count" class="bg-gray-100 dark:bg-gray-800 px-1.5 py-0.5 rounded text-gray-600 dark:text-gray-300">0</span>
    </button>
  </header>
  <div id="summarize-banner" class="absolute top-16 left-0 right-0 bg-blue-600 text-white text-xs py-2 flex items-center justify-center space-x-2 hf z-20">
    <i data-lucide="loader" class="w-3 h-3 animate-spin"></i><span>Summarizing Memory...</span>
  </div>
  <div id="load-more-banner" class="absolute top-16 left-0 right-0 bg-gray-100 dark:bg-gray-900 text-gray-500 text-xs py-2 flex items-center justify-center space-x-2 hf z-20">
    <i data-lucide="loader" class="w-3 h-3 animate-spin"></i><span>Loading older messages...</span>
  </div>
  <div id="chat-container" class="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6"></div>
  
  <div class="w-full flex-shrink-0 bg-white dark:bg-black pt-2 pb-6 px-4 sm:pt-4 sm:pb-6 sm:px-6 z-10 relative">
    <div class="absolute bottom-full left-0 right-0 h-8 bg-gradient-to-t from-white dark:from-black to-transparent pointer-events-none"></div>
    <button id="scroll-btn" onclick="scrollToBottom()" class="hf absolute bottom-full mb-4 right-4 md:right-6 z-20 w-9 h-9 rounded-full bg-black dark:bg-white text-white dark:text-black shadow-lg flex items-center justify-center hover:opacity-80 transition-opacity">
      <i data-lucide="chevron-down" class="w-5 h-5"></i>
    </button>
    <div class="max-w-3xl mx-auto relative">
      <div class="border border-gray-200 dark:border-gray-800 rounded-xl bg-white dark:bg-[#111] shadow focus-within:border-black dark:focus-within:border-white focus-within:ring-1 focus-within:ring-black dark:focus-within:ring-white transition-all">
        <textarea id="chat-input" rows="1" class="w-full bg-transparent p-3 sm:p-4 pr-12 resize-none outline-none text-base md:text-sm max-h-40 placeholder-gray-400 dark:placeholder-gray-600" placeholder="Message AIPHP..."></textarea>
        <!-- Toolbar row -->
        <div class="flex items-center justify-between px-2 pb-2">
          <!-- Thinking toggle -->
          <div class="flex items-center space-x-2">
            <button id="think-btn" onclick="toggleThinkingPicker(event)" title="Enable thinking / reasoning"
              class="flex items-center space-x-1.5 px-2 py-1 rounded-full text-xs font-medium border border-gray-200 dark:border-gray-700 text-gray-500 dark:text-gray-400 hover:border-purple-400 hover:text-purple-600 dark:hover:text-purple-400 transition-colors">
              <i data-lucide="brain-circuit" class="w-3.5 h-3.5"></i>
              <span id="think-label">Think: Off</span>
            </button>
            <div id="think-picker" class="hf absolute bottom-14 left-2 sm:left-6 bg-white dark:bg-[#111] border border-gray-200 dark:border-gray-700 rounded-xl shadow-xl p-3 z-30 w-48 sm:w-52" onclick="event.stopPropagation()">
              <p class="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-2">Thinking Effort</p>
              <div class="space-y-1" id="think-options">
                <button onclick="setThinkingEffort('none')"    class="think-opt w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors flex items-center justify-between"><span>Off</span></button>
                <button onclick="setThinkingEffort('low')"     class="think-opt w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors flex items-center justify-between"><span>Low</span><span class="text-[10px] text-gray-400">faster</span></button>
                <button onclick="setThinkingEffort('medium')"  class="think-opt w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors flex items-center justify-between"><span>Medium</span><span class="text-[10px] text-gray-400">balanced</span></button>
                <button onclick="setThinkingEffort('high')"    class="think-opt w-full text-left px-3 py-2 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors flex items-center justify-between"><span>High</span><span class="text-[10px] text-gray-400">thorough</span></button>
              </div>
              <p class="text-[10px] text-gray-400 mt-2 leading-relaxed">Works well with reasoning models (DeepSeek, Qwen3).</p>
            </div>
          </div>
          <button id="send-btn" onclick="handleSend()" class="p-1.5 sm:p-2 bg-black dark:bg-white text-white dark:text-black rounded-md hover:opacity-80 disabled:opacity-30 transition-opacity">
            <i data-lucide="corner-down-left" class="w-4 h-4"></i>
          </button>
        </div>
      </div>
    </div>
  </div>
</main>

<!-- Sketchboard Overlay on mobile -->
<div id="sketchboard-overlay" onclick="toggleSketchboard()" class="fixed inset-0 bg-black/50 z-40 md:hidden hf backdrop-blur-sm opacity-0 transition-opacity duration-300"></div>

<!-- Sketchboard -->
<aside id="sketchboard-sidebar" class="w-full sm:w-80 max-w-full border-l border-gray-200 dark:border-gray-800 bg-gray-50 dark:bg-[#111] absolute right-0 top-0 bottom-0 transform translate-x-full transition-transform duration-300 z-50 flex flex-col shadow-2xl sm:shadow-none" onclick="event.stopPropagation()">
  <div class="h-16 flex items-center justify-between px-4 border-b border-gray-200 dark:border-gray-800">
    <div class="flex items-center space-x-3">
      <h2 class="font-semibold flex items-center space-x-2"><i data-lucide="pin" class="w-4 h-4"></i><span>Sketchboard</span></h2>
      <button id="global-sketch-toggle" onclick="toggleGlobalSketchboard()" class="text-green-500 hover:text-gray-500 transition-colors" title="Toggle Sketchboard Context">
        <i data-lucide="toggle-right" class="w-5 h-5"></i>
      </button>
    </div>
    <button onclick="toggleSketchboard()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
  </div>
  <div class="p-4 flex-1 overflow-y-auto">
    <div class="flex space-x-2 mb-4">
      <input type="text" id="new-pin-input" placeholder="Add custom pin..." class="flex-1 border border-gray-200 dark:border-gray-700 bg-white dark:bg-black rounded-md px-3 py-2 text-sm outline-none focus:border-black dark:focus:border-white text-base md:text-sm" onkeydown="if(event.key==='Enter')addPin()">
      <button onclick="addPin()" class="bg-black dark:bg-white text-white dark:text-black px-3 rounded-md text-sm hover:opacity-80"><i data-lucide="plus" class="w-4 h-4"></i></button>
    </div>
    <ul id="pins-list" class="space-y-2"></ul>
  </div>
</aside>
</div><!-- end #app -->

<!-- MODALS -->
<div id="modal-backdrop" class="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 hf flex items-center justify-center p-2 sm:p-4 opacity-0 transition-opacity duration-200" onclick="closeModalsOnBackdrop(event)">

  <!-- Sessions -->
  <div id="sessions-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-3xl rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col max-h-[95vh] overflow-hidden" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]">
      <div><h3 class="font-bold text-lg">Manage Sessions</h3><p class="text-xs text-gray-500 mt-0.5">Your conversation history</p></div>
      <button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
    </div>
    <div class="p-4 sm:p-6 flex-1 overflow-y-auto">
        <div class="flex justify-between items-center mb-4">
            <h4 class="font-semibold text-sm">All Sessions</h4>
            <button onclick="newSession()" class="text-xs bg-black dark:bg-white text-white dark:text-black px-3 py-1.5 rounded-md hover:opacity-80 flex items-center"><i data-lucide="plus" class="w-3.5 h-3.5 mr-1"></i>New Session</button>
        </div>
        <div class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3" id="sessions-list"></div>
    </div>
  </div>

  <!-- Personas -->
  <div id="persona-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-4xl rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col max-h-[95vh] overflow-hidden" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]">
      <div><h3 class="font-bold text-lg" id="personas-title">Personas & Prompts</h3><p class="text-xs text-gray-500 mt-0.5">Define custom AI behaviors</p></div>
      <button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
    </div>
    
    <div id="personas-list-view" class="p-4 sm:p-6 overflow-y-auto flex-1">
      <div id="personas-list-container" class="space-y-3"></div>
      <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-800 flex justify-end">
        <button onclick="showPersonaForm(null)" class="w-full sm:w-auto bg-black dark:bg-white text-white dark:text-black px-4 py-2 rounded-md text-sm font-medium hover:opacity-80 flex justify-center items-center"><i data-lucide="plus" class="w-4 h-4 mr-1"></i>Create New Persona</button>
      </div>
    </div>

    <div id="personas-form-view" class="p-4 sm:p-6 flex-1 overflow-y-auto hf">
      <div class="flex flex-col md:flex-row gap-4 md:gap-8">
        <div class="w-full md:w-1/2 space-y-4">
          <div>
            <label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Avatar</label>
            <div class="flex space-x-3 items-center">
              <div class="w-14 h-14 rounded-xl bg-gray-100 dark:bg-[#111] border border-gray-200 dark:border-gray-700 flex items-center justify-center overflow-hidden flex-shrink-0"><span id="persona-avatar-preview" class="text-xl font-bold text-gray-400">AI</span></div>
              <input type="text" id="persona-avatar" placeholder="URL or 2-letter initials" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-blue-500 transition-colors">
            </div>
          </div>
          <div><label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">Bot Name</label><input type="text" id="persona-name" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-blue-500"></div>
          <div><label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">Description</label><textarea id="persona-desc" rows="2" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-blue-500 resize-none"></textarea></div>
          <div><label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">Greeting Message</label><textarea id="persona-first-msg" rows="2" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-blue-500 resize-none"></textarea></div>
        </div>
        <div class="w-full md:w-1/2 flex flex-col gap-4">
          <div class="flex-1 flex flex-col"><label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">System Prompt</label><textarea id="persona-prompt" class="flex-1 w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 sm:p-4 text-base md:text-sm outline-none focus:border-blue-500 resize-none min-h-[140px]"></textarea></div>
          <div class="flex-1 flex flex-col"><label class="block text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-1">User Persona</label><textarea id="persona-user" class="flex-1 w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 sm:p-4 text-base md:text-sm outline-none focus:border-blue-500 resize-none min-h-[80px]"></textarea></div>
        </div>
      </div>
      <input type="hidden" id="persona-edit-id">
      <div class="mt-6 pt-4 border-t border-gray-200 dark:border-gray-800 flex justify-end space-x-3">
        <button onclick="hidePersonaForm()" class="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-md">Cancel</button>
        <button onclick="savePersona()" class="w-full sm:w-auto bg-black dark:bg-white text-white dark:text-black px-6 py-2 rounded-lg text-sm font-medium hover:opacity-80">Save Persona</button>
      </div>
    </div>
  </div>

  <!-- Memory -->
  <div id="memory-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-2xl rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col max-h-[95vh]" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]">
      <div><h3 class="font-semibold text-base sm:text-lg">Memory & Summarization</h3><p id="mem-session-label" class="text-xs text-gray-500 mt-0.5">Session: —</p></div>
      <button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
    </div>
    <div class="p-4 sm:p-6 space-y-5 overflow-y-auto">
      <div>
        <div class="flex justify-between items-center mb-2">
          <label class="text-xs font-medium text-gray-500">Summary <span class="text-gray-400 font-normal">(editable)</span></label>
          <div class="flex items-center space-x-2 sm:space-x-3">
            <span id="sum-save-hint" class="hf text-xs text-green-600">Saved ✓</span>
            <button onclick="saveSummaryEdit()" class="text-xs bg-black dark:bg-white text-white dark:text-black px-2 py-1 sm:px-3 rounded-md hover:opacity-80">Save Edit</button>
            <button onclick="triggerSummarize()" class="text-xs text-blue-600 dark:text-blue-400 hover:underline">Regenerate</button>
          </div>
        </div>
        <textarea id="memory-summary-ta" rows="6" class="w-full border border-gray-200 dark:border-gray-700 rounded-md p-3 text-xs bg-gray-50 dark:bg-[#111] font-mono text-gray-700 dark:text-gray-300 outline-none focus:border-black dark:focus:border-white resize-y" placeholder="No summary yet. Regenerate to create one."></textarea>
      </div>
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Summarize Threshold <span class="text-gray-400">(msgs)</span></label><input type="number" id="mem-threshold" min="5" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Messages to Summarize</label><input type="number" id="mem-count" min="5" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Context Window <span class="text-gray-400">(last N for AI)</span></label><input type="number" id="mem-context" min="5" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">History Display Fetch</label><input type="number" id="mem-fetch" min="10" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
      </div>
      <label class="flex items-center space-x-3 cursor-pointer"><input type="checkbox" id="mem-include-old" class="rounded border-gray-300"><span class="text-sm text-gray-700 dark:text-gray-300">Include Previous Summary when re-summarizing</span></label>
    </div>
    <div class="px-4 sm:px-6 py-4 border-t border-gray-200 dark:border-gray-800 flex justify-end bg-gray-50 dark:bg-[#111]">
      <button onclick="saveMemorySettings()" class="w-full sm:w-auto bg-black dark:bg-white text-white dark:text-black px-4 py-2 rounded-md text-sm font-medium hover:opacity-80">Apply Rules</button>
    </div>
  </div>

  <!-- API Keys -->
  <div id="keys-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-2xl rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col max-h-[95vh]" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]">
      <h3 class="font-semibold text-base sm:text-lg" id="keys-title">API Endpoints</h3>
      <button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
    </div>
    <div id="keys-list-view" class="p-4 sm:p-6 overflow-y-auto">
      <div id="keys-list-container" class="space-y-3"></div>
      <div class="mt-4 pt-4 border-t border-gray-200 dark:border-gray-800 flex justify-end">
        <button onclick="showKeyForm(null)" class="w-full sm:w-auto bg-black dark:bg-white text-white dark:text-black px-4 py-2 rounded-md text-sm font-medium hover:opacity-80 flex justify-center items-center"><i data-lucide="plus" class="w-4 h-4 mr-1"></i>Add Endpoint</button>
      </div>
    </div>
    <div id="keys-form-view" class="p-4 sm:p-6 hf overflow-y-auto">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
        <div>
            <label class="block text-xs font-medium text-gray-500 mb-1">Provider Format</label>
            <select id="key-provider" class="w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#0a0a0a] rounded-md p-2 text-base md:text-sm outline-none">
                <option value="groq">Groq</option>
                <option value="mistral">Mistral</option>
                <option value="openrouter">OpenRouter</option>
                <option value="cloudflare">Cloudflare AI (Worker)</option>
                <option value="custom">Custom (OpenAI Compatible)</option>
            </select>
        </div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Model ID</label><input type="text" id="key-model" placeholder="e.g. mistral-large-latest" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div id="custom-url-container" class="hf sm:col-span-2">
            <label class="block text-xs font-medium text-gray-500 mb-1" id="custom-url-label">Custom API URL</label>
            <input type="text" id="key-custom-url" placeholder="http://localhost:11434/v1/chat/completions" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white">
        </div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Mode</label><select id="key-mode" class="w-full border border-gray-200 dark:border-gray-700 bg-white dark:bg-[#0a0a0a] rounded-md p-2 text-base md:text-sm outline-none"><option value="chat">Chat (Main Bot)</option><option value="summarize">Summarize (Background)</option></select></div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">API Key / CF Token</label><input type="password" id="key-value" placeholder="sk-... (optional for local)" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div><label class="block text-xs font-medium text-gray-500 mb-1">Label (optional)</label><input type="text" id="key-name" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
        <div class="flex items-end mt-2 sm:mt-0"><label class="flex items-center space-x-2 cursor-pointer text-sm"><input type="checkbox" id="key-primary" class="rounded border-gray-300"><span>Set as Primary</span></label></div>
      </div>
      <input type="hidden" id="key-edit-id">
      <div id="key-form-error" class="hf mb-3 text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg"></div>
      <div class="flex justify-end space-x-3">
        <button onclick="hideKeyForm()" class="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-md">Cancel</button>
        <button onclick="saveKey()" class="bg-black dark:bg-white text-white dark:text-black px-4 py-2 rounded-md text-sm hover:opacity-80">Save Key</button>
      </div>
    </div>
  </div>

  <!-- Sync -->
  <div id="sync-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-md rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]"><h3 class="font-semibold text-lg">Data Sync</h3><button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button></div>
    <div class="p-4 sm:p-6 space-y-4">
      <div onclick="exportData()" class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 text-center hover:border-black dark:hover:border-white transition-colors cursor-pointer">
        <i data-lucide="download" class="w-6 h-6 mx-auto mb-2 text-gray-700 dark:text-gray-300"></i><h4 class="font-medium text-sm">Download TXT</h4><p class="text-xs text-gray-500 mt-1">Exports as {user}/{bot} tags.</p>
      </div>
      <div class="border border-dashed border-gray-200 dark:border-gray-700 rounded-lg p-4 text-center hover:border-black dark:hover:border-white transition-colors cursor-pointer relative bg-gray-50 dark:bg-[#111]">
        <input type="file" accept=".txt" class="absolute inset-0 w-full h-full opacity-0 cursor-pointer" onchange="importData(event)">
        <i data-lucide="upload" class="w-6 h-6 mx-auto mb-2 text-gray-700 dark:text-gray-300"></i><h4 class="font-medium text-sm">Import Session</h4><p class="text-xs text-gray-500 mt-1">Upload a .txt exported file.</p>
      </div>
    </div>
  </div>

  <!-- Account -->
  <div id="account-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-md rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]"><h3 class="font-semibold text-lg">Account Settings</h3><button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button></div>
    <div class="p-4 sm:p-6 space-y-4">
      <div id="acct-error" class="hf text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg"></div>
      <div id="acct-success" class="hf text-sm text-green-600 bg-green-50 dark:bg-green-900/20 px-3 py-2 rounded-lg"></div>
      <div><label class="block text-xs font-medium text-gray-500 mb-1">New Username</label><input type="text" id="acct-username" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
      <div><label class="block text-xs font-medium text-gray-500 mb-1">New Password <span class="text-gray-400">(blank = keep current)</span></label><input type="password" id="acct-newpass" placeholder="••••••" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
      <div><label class="block text-xs font-medium text-gray-500 mb-1">Current Password <span class="text-red-500">*</span></label><input type="password" id="acct-curpass" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-black dark:focus:border-white"></div>
    </div>
    <div class="px-4 sm:px-6 py-4 border-t border-gray-200 dark:border-gray-800 flex justify-end bg-gray-50 dark:bg-[#111]"><button onclick="saveAccount()" class="w-full sm:w-auto bg-black dark:bg-white text-white dark:text-black px-6 py-2.5 rounded-lg text-sm font-medium hover:opacity-80">Save Changes</button></div>
  </div>

  <!-- Nuke -->
  <div id="nuke-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-md rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]"><h3 class="font-semibold text-lg text-red-600">Danger Zone</h3><button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button></div>
    <div class="p-4 sm:p-6 space-y-4">
      <p class="text-sm text-gray-600 dark:text-gray-400">Drops all data, scrambles your account, and logs you out. Irreversible.</p>
      <input type="password" id="nuke-pass" placeholder="Enter current password" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-md p-2 text-base md:text-sm outline-none focus:border-red-500">
      <div id="nuke-error" class="hf text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg"></div>
      <button onclick="nukeServer()" class="w-full bg-red-600 text-white px-4 py-2 rounded-md text-sm font-medium hover:bg-red-700 flex items-center justify-center space-x-2"><i data-lucide="alert-triangle" class="w-4 h-4"></i><span>Nuke Server (Wipe DB)</span></button>
    </div>
  </div>

  <!-- Edit Pin Modal -->
  <div id="edit-pin-modal" class="modal-content bg-white dark:bg-[#0a0a0a] w-[calc(100%-1rem)] max-w-lg rounded-xl shadow-2xl border border-gray-200 dark:border-gray-800 hf flex flex-col" onclick="event.stopPropagation()">
    <div class="px-4 sm:px-6 py-4 border-b border-gray-200 dark:border-gray-800 flex justify-between items-center bg-gray-50 dark:bg-[#111]">
      <h3 class="font-semibold text-lg">Edit Sketchboard Pin</h3>
      <button onclick="closeModals()" class="text-gray-500 hover:text-black dark:hover:text-white"><i data-lucide="x" class="w-5 h-5"></i></button>
    </div>
    <div class="p-4 sm:p-6">
      <textarea id="edit-pin-ta" rows="6" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-base md:text-sm outline-none focus:border-black dark:focus:border-white resize-y" placeholder="Pin content..."></textarea>
      <input type="hidden" id="edit-pin-id">
    </div>
    <div class="px-4 sm:px-6 py-4 border-t border-gray-200 dark:border-gray-800 flex justify-end space-x-3 bg-gray-50 dark:bg-[#111]">
      <button onclick="closeModals()" class="px-4 py-2 text-sm text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-md">Cancel</button>
      <button onclick="savePinEdit()" class="bg-black dark:bg-white text-white dark:text-black px-6 py-2 rounded-lg text-sm font-medium hover:opacity-80">Save Pin</button>
    </div>
  </div>
</div>

<script>
marked.setOptions({breaks:true,gfm:true});
marked.use(window.markedKatex({ throwOnError: false, displayMode: true }));

const S={
    csrf:'',username:'',session:'default',sessionLabel:'default',
    generating:false,
    personas:[], currentPersonaId:null,
    memory:{},sessions:[],
    msgs:[],hasMore:false,loadingOlder:false,
    userScrolled:false,
    pins:[], sketchGlobal:true,
    editingKeyId:null, editingPersonaId:null,
    thinkingEffort:'none',
};

const $=id=>document.getElementById(id);

async function api(action,data={},method='POST'){
    const o={method,headers:{'Content-Type':'application/json','X-CSRF-Token':S.csrf,'X-Session-Id':S.session}};
    if(method!=='GET')o.body=JSON.stringify(data);
    try{
        const r=await fetch(\`?action=\${action}\`,o);
        if (r.status === 401 && action !== 'login' && action !== 'getInitData') { window.location.reload(); return; }
        return r.json();
    }catch{return{error:'Network error'};}
}

async function* parseStream(response) {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while(true) {
        const {done, value} = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, {stream: true});
        let lines = buffer.split('\\n');
        buffer = lines.pop();
        for(let line of lines) {
            line = line.trim();
            if(!line.startsWith('data:')) continue;
            const payload = line.slice(5).trim();
            if(payload && payload !== '[DONE]') {
                try { yield JSON.parse(payload); } catch(e) {}
            }
        }
    }
}

function toast(msg,dur=2400){const t=$('toast');t.textContent=msg;t.classList.remove('hf');clearTimeout(t._t);t._t=setTimeout(()=>t.classList.add('hf'),dur);}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function formatContent(rawText) {
    if (!rawText) return '';
    let thoughtHtml = '';
    let mainText = rawText;

    const thinkMatch = mainText.match(/<think>([\\s\\S]*?)<\\/think>/i);
    if (thinkMatch) {
        const thoughtContent = thinkMatch[1].trim();
        thoughtHtml = \`
            <details class="mb-3 group/think">
                <summary class="cursor-pointer text-xs font-semibold text-gray-500 hover:text-gray-700 dark:hover:text-gray-300 select-none flex items-center w-max">
                    <span class="border border-gray-200 dark:border-gray-700 rounded-md px-2 py-1 flex items-center space-x-1.5 bg-gray-50 dark:bg-[#1a1a1a]">
                        <i data-lucide="brain-circuit" class="w-3.5 h-3.5"></i>
                        <span>Thought Process</span>
                        <i data-lucide="chevron-down" class="w-3.5 h-3.5 transition-transform group-open/think:rotate-180"></i>
                    </span>
                </summary>
                <div class="mt-2 text-sm text-gray-500 dark:text-gray-400 border-l-2 border-gray-300 dark:border-gray-700 pl-3 py-1 whitespace-pre-wrap font-mono overflow-x-auto">
                    \${esc(thoughtContent)}
                </div>
            </details>
        \`;
        mainText = mainText.replace(/<think>([\\s\\S]*?)<\\/think>/i, '').trim();
    }

    const parsedHtml = marked.parse(mainText);
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = parsedHtml;

    const preBlocks = tempDiv.querySelectorAll('pre');
    preBlocks.forEach((pre) => {
        const codeEl = pre.querySelector('code');
        const lang = (codeEl && codeEl.className) ? codeEl.className.replace('language-', '') : 'code';

        const wrapper = document.createElement('div');
        wrapper.className = 'code-block-wrapper relative my-4 rounded-lg overflow-hidden border border-[rgba(127,127,127,0.12)] bg-[rgba(127,127,127,0.05)]';
        
        const topBar = document.createElement('div');
        topBar.className = 'flex items-center justify-between px-3 py-1.5 bg-[rgba(127,127,127,0.08)] border-b border-[rgba(127,127,127,0.12)]';
        topBar.innerHTML = \`
            <span class="text-xs font-mono text-gray-500 lowercase">\${lang}</span>
            <button onclick="copyCodeBlock(this)" class="flex items-center space-x-1.5 text-xs text-gray-500 hover:text-black dark:hover:text-white transition-colors">
                <i data-lucide="copy" class="w-3.5 h-3.5"></i>
                <span class="copy-label">Copy</span>
            </button>
        \`;
        pre.className = '!m-0 !border-0 !rounded-none !bg-transparent p-3 overflow-x-auto';
        pre.parentNode.insertBefore(wrapper, pre);
        wrapper.appendChild(topBar);
        wrapper.appendChild(pre);
    });

    return thoughtHtml + tempDiv.innerHTML;
}

function toggleThinkingPicker(e) {
    e.stopPropagation();
    $('think-picker').classList.toggle('hf');
}
function copyCodeBlock(btn) {
    const wrapper = btn.closest('.code-block-wrapper');
    const codeEl = wrapper.querySelector('code');
    if (codeEl) {
        navigator.clipboard.writeText(codeEl.innerText).then(() => {
            const label = btn.querySelector('.copy-label');
            const icon = btn.querySelector('[data-lucide]'); 
            label.innerText = 'Copied!';
            if (icon) { icon.setAttribute('data-lucide', 'check'); lucide.createIcons(); }
            setTimeout(() => {
                label.innerText = 'Copy';
                if (icon) { icon.setAttribute('data-lucide', 'copy'); lucide.createIcons(); }
            }, 2000);
        }).catch(() => toast('Failed to copy code'));
    }
}
function setThinkingEffort(effort) {
    S.thinkingEffort = effort;
    const labels = {'none': 'Think: Off','low': 'Think: Low','medium': 'Think: Medium','high': 'Think: High'};
    const lbl = $('think-label');
    if (lbl) lbl.textContent = labels[effort] || 'Think: Off';
    const picker = $('think-picker');
    if (picker) picker.classList.add('hf');
}

function toggleSidebar() {
    const sb = $('left-sidebar');
    const ov = $('sidebar-overlay');
    const isClosed = sb.classList.contains('-translate-x-full');
    if (isClosed) {
        sb.classList.remove('-translate-x-full');
        ov.classList.remove('hf');
        requestAnimationFrame(() => ov.classList.remove('opacity-0'));
    } else {
        sb.classList.add('-translate-x-full');
        ov.classList.add('opacity-0');
        setTimeout(() => ov.classList.add('hf'), 300);
    }
}
function closeSidebarOnMobile() {
    if (window.innerWidth < 768 && !$('left-sidebar').classList.contains('-translate-x-full')) {
        toggleSidebar();
    }
}
function toggleSketchboard(){
    const sb = $('sketchboard-sidebar');
    const ov = $('sketchboard-overlay');
    const isClosed = sb.classList.contains('translate-x-full');
    sb.classList.toggle('translate-x-full');
    if(isClosed) {
        ov.classList.remove('hf');
        requestAnimationFrame(() => ov.classList.remove('opacity-0'));
    } else {
        ov.classList.add('opacity-0');
        setTimeout(() => ov.classList.add('hf'), 300);
    }
}

document.addEventListener('DOMContentLoaded', async ()=>{
    if(document.cookie.includes('aiphp_theme=dark'))applyTheme(true);
    lucide.createIcons();
    const ta=$('chat-input');
    ta.addEventListener('input',function(){this.style.height='auto';this.style.height=this.scrollHeight+'px';});
ta.addEventListener('keydown', e => {
        if (e.key === 'Enter' && !e.shiftKey) {
            // Allow default new line behavior on mobile screens (<768px)
            if (window.innerWidth < 768) return; 
            e.preventDefault();
            handleSend();
        }
    });
    $('persona-avatar').addEventListener('input',updateAvatarPreview);
    $('login-pass').addEventListener('keydown',e=>{if(e.key==='Enter')doLogin();});
    
    $('key-provider').addEventListener('change', e => {
        const p = e.target.value;
        const cont = $('custom-url-container');
        cont.classList.remove('hf');
        if (p === 'custom') {
            $('custom-url-label').textContent = 'Custom API URL';
            $('key-custom-url').placeholder = 'http://localhost:11434/v1/chat/completions';
            $('key-model').placeholder = 'e.g. mistral-large-latest';
        } else if (p === 'cloudflare') {
            $('custom-url-label').textContent = 'Cloudflare Account ID';
            $('key-custom-url').placeholder = 'e.g. a3b5c7d...';
            $('key-model').placeholder = 'e.g. @cf/meta/llama-3-8b-instruct';
        } else {
            cont.classList.add('hf');
            $('key-model').placeholder = 'e.g. mistral-large-latest';
        }
    });

    const cc=$('chat-container');
    cc.addEventListener('scroll',()=>{
        const atBottom=cc.scrollHeight-cc.scrollTop-cc.clientHeight<80;
        S.userScrolled=!atBottom;
        $('scroll-btn').classList.toggle('hf',atBottom);
        if(cc.scrollTop<120&&S.hasMore&&!S.loadingOlder)loadOlderMessages();
    });

    try {
        const d = await api('getInitData',{},'GET');
        if(d && !d.error) {
            $('login-screen').classList.add('hf');
            $('app').classList.remove('hf');
            S.csrf=d.csrf_token; S.username=d.username; S.session=d.session_id;
            S.personas=d.personas||[];
            S.currentPersonaId = d.current_persona_id || (S.personas[0]?S.personas[0].id:null);
            S.memory=d.memory||{}; S.sessions=d.sessions||[];
            
            $('sidebar-uname').textContent=S.username;
            updateHeader(); populateMemoryForm();
            loadApiKeys(); loadSketchboard();
            await loadChatHistory();
        } else {
            $('login-screen').classList.remove('hf');
        }
    } catch(e) {
        $('login-screen').classList.remove('hf');
    }
});

async function doLogin(){
    const btn=$('login-btn'),err=$('login-error');
    err.classList.add('hf');
    btn.innerHTML='<svg class="animate-spin w-4 h-4 mr-2"viewBox="0 0 24 24"fill="none"stroke="currentColor"stroke-width="2"><path d="M21 12a9 9 0 11-9-9"/></svg>Signing in...';
    try{
        const r=await fetch('?action=login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:$('login-user').value.trim(),password:$('login-pass').value})});
        const d=await r.json();
        if(d.error){err.textContent=d.error;err.classList.remove('hf');btn.innerHTML='<span>Sign In</span>';return;}
        
        const initD = await fetch('?action=getInitData',{headers:{'X-Session-Id':S.session}}).then(x=>x.json());
        if(!initD || initD.error) throw new Error('Init failed');
        
        $('login-screen').classList.add('hf');
        $('app').classList.remove('hf');
        S.csrf=initD.csrf_token;S.session=initD.session_id;
        S.personas=initD.personas||[];
        S.currentPersonaId = initD.current_persona_id || (S.personas[0]?S.personas[0].id:null);
        S.memory=initD.memory||{};S.sessions=initD.sessions||[];
        $('sidebar-uname').textContent=initD.username;
        S.username = initD.username;
        
        updateHeader(); populateMemoryForm();
        loadApiKeys(); loadSketchboard();
        await loadChatHistory();
        setThinkingEffort('none');
    }catch{err.textContent='Connection error.';err.classList.remove('hf');btn.innerHTML='<span>Sign In</span>';}
}
async function doLogout(){await api('logout');location.reload();}

async function loadChatHistory(){
    $('chat-container').innerHTML='';
    S.msgs=[];S.hasMore=false;
    const d=await api('getChatHistory',{},'GET');
    S.msgs=d.messages||[];S.hasMore=d.has_more||false;
    renderAllMessages();
    scrollToBottom();
}

async function loadOlderMessages(){
    if(S.loadingOlder||!S.hasMore)return;
    S.loadingOlder=true;
    $('load-more-banner').classList.remove('hf');
    lucide.createIcons();
    const firstTimestamp = S.msgs.length > 0 ? S.msgs[0].timestamp : 0;
    const cc=$('chat-container'),prev=cc.scrollHeight;
    const url=\`?action=getChatHistory&before_timestamp=\${firstTimestamp}\`;
    const d=await fetch(url,{headers:{'X-CSRF-Token':S.csrf,'X-Session-Id':S.session}}).then(r=>r.json()).catch(()=>({messages:[],has_more:false}));
    const older=d.messages||[];S.hasMore=d.has_more||false;
    if(older.length){S.msgs=[...older,...S.msgs];prependMessages(older);cc.scrollTop=cc.scrollHeight-prev;}
    $('load-more-banner').classList.add('hf');
    S.loadingOlder=false;
}

function buildMsgEl(msg){
  const isBot=msg.role==='bot';
  const isGreeting = (!S.hasMore && S.msgs[0] && S.msgs[0].id === msg.id && isBot);
  
  // Find if this is the absolute newest bot message
  const latestBotMsg = S.msgs.slice().reverse().find(m => m.role === 'bot');
  const isLatest = (latestBotMsg && latestBotMsg.id === msg.id);

  const wrap=document.createElement('div');
  wrap.className=\`flex \${isBot?'justify-start':'justify-end'} group w-full relative\`;
  wrap.dataset.msgId=msg.id;

  if(isBot){
    const vars=msg.variants||[msg.content||''];
    const ids=msg.variant_ids||[msg.id];
    const ai=typeof msg.active_index==='number'?msg.active_index:0;
    const content=vars[ai]||'';
    const isLast=ai===vars.length-1;
    // Only show the < 1/2 > pill if it is the newest message
    const showPill=vars.length>1 && isLatest;
    
    const persona = S.personas.find(p => p.id == S.currentPersonaId) || S.personas[0] || {avatar: 'AI'};
    const av = persona.avatar || 'AI';
    const avatarHtml=av.startsWith('http')?\`<img src="\${esc(av)}"class="w-full h-full object-cover">\`:\`<span class="text-xs font-bold text-gray-600 dark:text-gray-400">\${esc(av.substring(0,2))}</span>\`;
    
    const pill=showPill&&!isGreeting?\`
      <div class="variant-pill flex items-center space-x-1.5 mt-2.5 text-xs text-gray-500 bg-gray-50 dark:bg-[#1a1a1a] w-max px-2 py-1.5 rounded-md border border-gray-200 dark:border-gray-800">
        <button onclick="changeVariation('\${msg.id}',-1)"\${ai===0?' disabled':''}class="hover:text-black dark:hover:text-white disabled:opacity-30 p-0.5"><i data-lucide="chevron-left"class="w-3.5 h-3.5"></i></button>
        <span class="min-w-[2.5rem] text-center">\${ai+1}/\${vars.length}</span>
        <button onclick="changeVariation('\${msg.id}',1)"\${isLast?' disabled':''}class="hover:text-black dark:hover:text-white disabled:opacity-30 p-0.5"><i data-lucide="chevron-right"class="w-3.5 h-3.5"></i></button>
        <div class="w-px h-3 bg-gray-300 dark:bg-gray-700 mx-1"></div>
        <span class="text-[10px] px-1.5 py-0.5 rounded \${isLast?'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30':'text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30'}">\${isLast?'Latest':'Older'}</span>
      </div>\`:'';
    const vdata=encodeURIComponent(JSON.stringify(vars));
    const idata=encodeURIComponent(JSON.stringify(ids));
    wrap.innerHTML=\`
      <div class="flex w-full md:max-w-[85%] max-w-[95%] space-x-3 md:space-x-4">
        <div class="w-8 h-8 rounded-full bg-gray-100 dark:bg-[#111] border border-gray-200 dark:border-gray-800 flex items-center justify-center flex-shrink-0 mt-1 overflow-hidden">\${avatarHtml}</div>
        <div class="flex flex-1 min-w-0 items-start space-x-2">
          <div class="\${!isGreeting && isLatest ? 'swipeable' : ''} min-w-0" id="bb-\${msg.id}" data-group="\${esc(msg.group_id||'')}" data-vars="\${vdata}" data-ids="\${idata}" data-ai="\${ai}">
            <div class="msg-content text-sm leading-relaxed bg-white dark:bg-[#111] border border-gray-100 dark:border-gray-800 rounded-2xl rounded-tl-sm p-4 shadow-sm w-fit max-w-full break-words">\${formatContent(content)}</div>
            \${pill}
          </div>
          <div class="flex-shrink-0 pt-2"><button onclick="toggleDropdown(event,'\${msg.id}',true)" class="p-1 text-gray-400 hover:text-black dark:hover:text-white rounded opacity-0 group-hover:opacity-100 transition-opacity"><i data-lucide="more-vertical"class="w-4 h-4"></i></button></div>
        </div>
      </div>\`;
  }else{
    wrap.innerHTML=\`
      <div class="flex w-full md:max-w-[80%] max-w-[95%] items-start justify-end space-x-2 ml-auto">
        <div class="flex-shrink-0 pt-2"><button onclick="toggleDropdown(event,'\${msg.id}',false)" class="p-1 text-gray-400 hover:text-black dark:hover:text-white rounded opacity-0 group-hover:opacity-100 transition-opacity"><i data-lucide="more-vertical"class="w-4 h-4"></i></button></div>
        <div class="msg-content bg-black dark:bg-white text-white dark:text-black text-sm rounded-2xl rounded-tr-sm px-4 py-2.5 shadow-sm break-words w-fit max-w-full">\${formatContent(msg.content||'')}</div>
      </div>\`;
  }
  return wrap;
}

function getVars(el){return JSON.parse(decodeURIComponent(el.dataset.vars||'%5B%5D'));}
function getIds(el){return JSON.parse(decodeURIComponent(el.dataset.ids||'%5B%5D'));}

function renderAllMessages(){
    const cc=$('chat-container');cc.innerHTML='';
    S.msgs.forEach(m=>cc.appendChild(buildMsgEl(m)));
    lucide.createIcons();attachSwipeListeners();
}
function prependMessages(msgs){
    const cc=$('chat-container'),frag=document.createDocumentFragment();
    msgs.forEach(m=>frag.appendChild(buildMsgEl(m)));
    cc.insertBefore(frag,cc.firstChild);
    lucide.createIcons();attachSwipeListeners();
}
function appendMsgEl(msg){
    const cc=$('chat-container');
    const old=cc.querySelector(\`[data-msg-id="\${msg.id}"]\`);
    const el=buildMsgEl(msg);
    if(old)old.replaceWith(el);else cc.appendChild(el);
    lucide.createIcons();attachSwipeListeners();
}
function refreshMsgEl(id){
    const m=S.msgs.find(m=>m.id==id);if(!m)return;
    const cc=$('chat-container');
    const old=cc.querySelector(\`[data-msg-id="\${id}"]\`);
    if(old)old.replaceWith(buildMsgEl(m));
    lucide.createIcons();attachSwipeListeners();
}
function scrollToBottom(smooth=false){
    const cc=$('chat-container');
    cc.scrollTo({top:cc.scrollHeight,behavior:smooth?'smooth':'instant'});
}

async function handleSend(){
    if(S.generating)return;
    const ta=$('chat-input');const txt=ta.value.trim();if(!txt)return;
    ta.value='';ta.style.height='auto';
    S.generating=true;$('send-btn').disabled=true;

    const tuid='tu'+Date.now();
    S.msgs.push({id:tuid,role:'user',content:txt});
    appendMsgEl({id:tuid,role:'user',content:txt});

    const tbid='tb'+Date.now();
    S.msgs.push({id:tbid,role:'bot',variants:[''],variant_ids:[tbid],active_index:0,group_id:''});
    appendMsgEl(S.msgs[S.msgs.length-1]);
    const typing=document.querySelector(\`[data-msg-id="\${tbid}"] .msg-content\`);
    if(typing)typing.innerHTML='<span class="flex items-center space-x-2"><svg class="animate-spin w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-9-9"/></svg><span class="text-xs text-gray-400">Generating...</span></span>';
    if(!S.userScrolled)scrollToBottom();

    try {
        const resp = await fetch('?action=sendMessage', {
            method: 'POST',
            headers: {'Content-Type':'application/json','X-CSRF-Token':S.csrf,'X-Session-Id':S.session},
            body: JSON.stringify({content:txt, thinking_effort:S.thinkingEffort})
        });

        if (!resp.ok) {
            const errJson = await resp.json();
            throw new Error(errJson.error || 'Server error');
        }

        let fullText = "", fullReasoning = "";
        let display = "";

        for await (const data of parseStream(resp)) {
            if (data.error) throw new Error(data.error);
            if (data.reasoning) fullReasoning += data.reasoning;
            if (data.chunk) fullText += data.chunk;
            display = fullText;
            if (fullReasoning) display = \`<think>\\n\${fullReasoning}\\n</think>\\n\\n\${fullText}\`;
            typing.innerHTML = formatContent(display);

            if (data.done) {
                const bi = S.msgs.findIndex(m=>m.id==tbid);
                if (bi !== -1) {
                    S.msgs[bi].id = data.bot_id;
                    S.msgs[bi].group_id = data.group_id;
                    S.msgs[bi].variant_ids = [data.bot_id];
                    S.msgs[bi].variants = [display];
                    S.msgs[bi].content = display;
                }
                const bub = document.querySelector(\`[data-msg-id="\${tbid}"]\`);
                if (bub) {
                    bub.dataset.msgId = data.bot_id;
                    const bbel = document.getElementById(\`bb-\${tbid}\`);
                    if(bbel) bbel.id = \`bb-\${data.bot_id}\`;
                }
                refreshMsgEl(data.bot_id);
                if(!S.userScrolled)scrollToBottom();
                if(data.should_summarize) triggerSummarizeSilent();
            }
        }
    } catch (err) {
        [tuid,tbid].forEach(id=>{S.msgs=S.msgs.filter(m=>m.id!=id);document.querySelector(\`[data-msg-id="\${id}"]\`)?.remove();});
        toast('Error: ' + err.message, 5000);
    } finally {
        S.generating=false;$('send-btn').disabled=false;
    }
}

async function changeVariation(msgId,dir){
    const isGreeting = (!S.hasMore && S.msgs[0] && S.msgs[0].id == msgId);
    if(isGreeting) return;
    const el=document.getElementById(\`bb-\${msgId}\`);if(!el)return;
    const vars=getVars(el),ids=getIds(el);
    const ai=parseInt(el.dataset.ai||'0');
    const ni=ai+dir;
    if(ni>=0&&ni<vars.length){
        await api('setMainVariant',{id:ids[ni]});
        el.dataset.ai=ni;
        const ci=el.querySelector('.msg-content');if(ci)ci.innerHTML=formatContent(vars[ni]);
        updatePill(el,ni,vars.length,msgId,ids);
        const m=S.msgs.find(m=>m.id==msgId);if(m)m.active_index=ni;
    }else if(ni>=vars.length){
        regenVariant(msgId,el.dataset.group);
    }
}

function updatePill(el,ai,total,msgId,ids){
    const isLast=ai===total-1;
    let pill=el.querySelector('.variant-pill');
    if(total<=1){pill?.remove();return;}
    const html=\`<div class="variant-pill flex items-center space-x-1.5 mt-2.5 text-xs text-gray-500 bg-gray-50 dark:bg-[#1a1a1a] w-max px-2 py-1.5 rounded-md border border-gray-200 dark:border-gray-800">
        <button onclick="changeVariation('\${msgId}',-1)"\${ai===0?' disabled':''}class="hover:text-black dark:hover:text-white disabled:opacity-30 p-0.5"><i data-lucide="chevron-left"class="w-3.5 h-3.5"></i></button>
        <span class="min-w-[2.5rem] text-center">\${ai+1}/\${total}</span>
        <button onclick="changeVariation('\${msgId}',1)"\${isLast?' disabled':''}class="hover:text-black dark:hover:text-white disabled:opacity-30 p-0.5"><i data-lucide="chevron-right"class="w-3.5 h-3.5"></i></button>
        <div class="w-px h-3 bg-gray-300 dark:bg-gray-700 mx-1"></div>
        <span class="text-[10px] px-1.5 py-0.5 rounded \${isLast?'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/30':'text-amber-600 dark:text-amber-400 bg-amber-100 dark:bg-amber-900/30'}">\${isLast?'Latest':'Older'}</span>
    </div>\`;
    if(pill)pill.outerHTML=html;else el.insertAdjacentHTML('beforeend',html);
    lucide.createIcons();
}

async function regenVariant(msgId,groupId){
    const isGreeting = (!S.hasMore && S.msgs[0] && S.msgs[0].id == msgId);
    if(isGreeting) return;
    if(S.generating)return;
    S.generating=true;$('send-btn').disabled=true;
    const el=document.getElementById(\`bb-\${msgId}\`);
    const ci=el?.querySelector('.msg-content');
    if(ci)ci.innerHTML='<span class="text-gray-400 text-xs flex items-center space-x-2"><svg class="animate-spin w-3 h-3"viewBox="0 0 24 24"fill="none"stroke="currentColor"stroke-width="2"><path d="M21 12a9 9 0 11-9-9"/></svg><span>Generating…</span></span>';
    
    try {
        const resp = await fetch('?action=regenerate', {
            method: 'POST',
            headers: {'Content-Type':'application/json','X-CSRF-Token':S.csrf,'X-Session-Id':S.session},
            body: JSON.stringify({group_id:groupId})
        });

        if (!resp.ok) {
            const errJson = await resp.json();
            throw new Error(errJson.error || 'Server error');
        }

        let fullText = "", fullReasoning = "", display = "";
        for await (const data of parseStream(resp)) {
            if (data.error) throw new Error(data.error);
            if (data.reasoning) fullReasoning += data.reasoning;
            if (data.chunk) fullText += data.chunk;
            display = fullText;
            if (fullReasoning) display = \`<think>\\n\${fullReasoning}\\n</think>\\n\\n\${fullText}\`;
            if(ci) ci.innerHTML = formatContent(display);

            if (data.done) {
                const m=S.msgs.find(m=>m.id==msgId);
                if(m&&el){
                    const newVars=[...(m.variants||[]), display];
                    const newIds=[...(m.variant_ids||[]), data.bot_id];
                    const newAi=newVars.length-1;
                    m.variants=newVars;m.variant_ids=newIds;m.active_index=newAi;
                    el.dataset.vars=encodeURIComponent(JSON.stringify(newVars));
                    el.dataset.ids=encodeURIComponent(JSON.stringify(newIds));
                    el.dataset.ai=newAi;
                    updatePill(el,newAi,newVars.length,msgId,newIds);
                }
            }
        }
    } catch(err) {
        toast('Regeneration failed: ' + err.message);
        if(ci)ci.innerHTML='<span class="text-red-400 text-xs">Regeneration failed.</span>';
    } finally {
        S.generating=false;$('send-btn').disabled=false;
    }
}

function attachSwipeListeners(){
  S.msgs.filter(m=>m.role==='bot').forEach(msg=>{
    const isGreeting = (!S.hasMore && S.msgs[0] && S.msgs[0].id === msg.id);
    if(isGreeting) return;
    
    // Escaped backticks and dollar signs for Worker compatibility
    const el=document.getElementById(\`bb-\${msg.id}\`);
    if(!el||el._swipe)return;
    el._swipe=true;
    
    let sx=0, sy=0, drag=false, axisLocked=null;
    
    const start=e=>{
      const latestBotMsg = S.msgs.slice().reverse().find(m => m.role === 'bot');
      if (!latestBotMsg || latestBotMsg.id !== msg.id) return;
      
      sx = e.touches ? e.touches[0].clientX : e.clientX;
      sy = e.touches ? e.touches[0].clientY : e.clientY;
      drag = true;
      axisLocked = null; // Reset the axis lock on every new touch
    };
    
    const mv=e=>{
      if(!drag) return;
      const x = e.touches ? e.touches[0].clientX : e.clientX;
      const y = e.touches ? e.touches[0].clientY : e.clientY;
      const dx = x - sx;
      const dy = y - sy;
      
      // Phase 1: Determine the primary axis of movement once we pass a 10px threshold
      if (!axisLocked) {
          if (Math.abs(dx) > 10 || Math.abs(dy) > 10) {
              axisLocked = Math.abs(dx) > Math.abs(dy) ? 'x' : 'y';
          }
      }
      
      // Phase 2: If we haven't determined the axis yet, or if locked to vertical (scrolling), do NOTHING
      if (!axisLocked || axisLocked === 'y') {
          return; 
      }
      
      // Phase 3: We are locked to horizontal (swiping). Prevent the screen from scrolling up/down.
      if(e.cancelable) e.preventDefault();
      
      el.classList.add('swiping'); 
      // Escaped backticks and dollar signs here
      el.style.transform = \`translateX(\${dx*.25}px)\`;
      
      if (dx < -150) { 
          drag=false; el.style.transform=''; el.classList.remove('swiping'); changeVariation(msg.id, 1); 
      }
      else if (dx > 150) { 
          drag=false; el.style.transform=''; el.classList.remove('swiping'); changeVariation(msg.id, -1); 
      }
    };
    
    const end=()=>{ drag=false; axisLocked=null; el.style.transform=''; el.classList.remove('swiping'); };
    
    // Note: touchmove is set to passive: false so preventDefault() can freeze the screen during horizontal swipes
    el.addEventListener('mousedown',start); window.addEventListener('mousemove',mv, {passive: false}); window.addEventListener('mouseup',end);
    el.addEventListener('touchstart',start,{passive:true}); window.addEventListener('touchmove',mv,{passive:false}); window.addEventListener('touchend',end);
  });
}

function toggleDropdown(e,id,isBot){
    e.stopPropagation();
    const drop=$('global-dropdown'),btn=e.currentTarget,rect=btn.getBoundingClientRect();
    const el=isBot?document.getElementById(\`bb-\${id}\`):null;
    const vars=el?getVars(el):[];const ids=el?getIds(el):[];
    const ai=el?parseInt(el.dataset.ai||'0'):0;
    const isGreeting = (!S.hasMore && S.msgs[0] && S.msgs[0].id == id && isBot);
    drop.innerHTML=\`
        <button onclick="copyMsg('\${id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left"><i data-lucide="copy"class="w-4 h-4 mr-2"></i>Copy</button>
        <button onclick="startEdit('\${id}',\${isBot})" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left"><i data-lucide="edit-2"class="w-4 h-4 mr-2"></i>Edit</button>
        \${isBot?\`<button onclick="pinMsg('\${id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left"><i data-lucide="pin"class="w-4 h-4 mr-2"></i>Pin to Sketchboard</button>\`:''}
        \${isBot&&vars.length>1&&!isGreeting?\`<button onclick="setMainDrop('\${id}','\${ids[ai]}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left text-blue-600 dark:text-blue-400"><i data-lucide="check-circle"class="w-4 h-4 mr-2"></i>Keep this version only</button>\`:''}
        \${isBot&&!isGreeting?\`<button onclick="regenDrop('\${id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left"><i data-lucide="refresh-cw"class="w-4 h-4 mr-2"></i>Regenerate</button>\`:''}
        <div class="h-px bg-gray-200 dark:bg-gray-800 my-1"></div>
        <button onclick="rewindHere('\${id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left text-red-500"><i data-lucide="rotate-ccw"class="w-4 h-4 mr-2"></i>Rewind Here</button>
        <button onclick="deleteMsg('\${id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left text-red-500"><i data-lucide="trash-2"class="w-4 h-4 mr-2"></i>Delete</button>\`;
    lucide.createIcons();
    drop.classList.remove('hf');
    drop.style.top=\`\${rect.bottom+4}px\`;
    
    if(isBot){
        drop.style.left=\`\${rect.left}px\`;drop.style.right='auto';
        if (rect.left + 208 > window.innerWidth) { drop.style.left = 'auto'; drop.style.right = '10px'; }
    } else {
        drop.style.right=\`\${window.innerWidth-rect.right}px\`;drop.style.left='auto';
        if (window.innerWidth - rect.right + 208 > window.innerWidth) { drop.style.right = 'auto'; drop.style.left = '10px'; }
    }
}

function togglePersonaDropdown(e) {
    e.stopPropagation();
    const drop = $('global-dropdown');
    const rect = e.currentTarget.getBoundingClientRect();
    
    drop.innerHTML = \`
        <div class="px-3 py-2 text-[10px] font-bold text-gray-400 uppercase tracking-wider border-b border-gray-200 dark:border-gray-800">Switch Persona for Session</div>
        <div class="max-h-64 overflow-y-auto">
        \${S.personas.map(p => \`
            <button onclick="changeSessionPersona('\${p.id}')" class="flex items-center px-4 py-2 text-sm hover:bg-gray-50 dark:hover:bg-gray-800 w-full text-left \${p.id == S.currentPersonaId ? 'text-blue-600 dark:text-blue-400 font-medium bg-gray-50 dark:bg-gray-800' : ''}">
                <span class="w-5 h-5 rounded overflow-hidden mr-2 bg-gray-200 dark:bg-gray-700 flex items-center justify-center text-[10px] flex-shrink-0">\${p.avatar.startsWith('http') ? \`<img src="\${esc(p.avatar)}" class="w-full h-full object-cover">\` : esc(p.avatar.substring(0,2))}</span>
                <span class="truncate">\${esc(p.name)}</span>
                \${p.id == S.currentPersonaId ? '<i data-lucide="check" class="w-3.5 h-3.5 ml-auto"></i>' : ''}
            </button>
        \`).join('')}
        </div>
    \`;
    lucide.createIcons();
    drop.classList.remove('hf');
    drop.style.top = \`\${rect.bottom + 4}px\`;
    drop.style.left = \`\${rect.left}px\`;
    drop.style.right = 'auto';
}

function closeAllDropdowns(){$('global-dropdown').classList.add('hf');}
function copyMsg(id){const m=S.msgs.find(m=>m.id==id);if(!m)return;navigator.clipboard.writeText(m.role==='bot'?(m.variants?.[m.active_index||0]||''):(m.content||''));toast('Copied!');closeAllDropdowns();}
function pinMsg(id){const m=S.msgs.find(m=>m.id==id);if(!m)return;const t=(m.variants?.[m.active_index||0]||m.content||'').substring(0,120);addPinText(t);closeAllDropdowns();}
async function setMainDrop(msgId,varId){
    await api('keepVersionOnly',{id:varId});
    const m=S.msgs.find(m=>m.id==msgId);const el=document.getElementById(\`bb-\${msgId}\`);
    if(m&&el){
        const idx=getIds(el).indexOf(varId);const content=getVars(el)[idx]||'';
        m.variants=[content];m.variant_ids=[varId];m.active_index=0;
        el.dataset.vars=encodeURIComponent(JSON.stringify([content]));
        el.dataset.ids=encodeURIComponent(JSON.stringify([varId]));
        el.dataset.ai='0';
        el.querySelector('.variant-pill')?.remove();
    }
    closeAllDropdowns();toast('Other versions deleted.');
}
function regenDrop(id){const el=document.getElementById(\`bb-\${id}\`);if(!el)return;closeAllDropdowns();regenVariant(id,el.dataset.group);}
async function rewindHere(id){
    if(!confirm('Delete all messages after this one?'))return;
    await api('rewindChat',{id});
    const idx=S.msgs.findIndex(m=>m.id==id);if(idx!==-1)S.msgs=S.msgs.slice(0,idx+1);
    const cc=$('chat-container');let found=false;
    Array.from(cc.children).forEach(el=>{if(found)el.remove();if(el.dataset.msgId==id)found=true;});
    closeAllDropdowns();
}
async function deleteMsg(id){
    await api('deleteMessage',{id});S.msgs=S.msgs.filter(m=>m.id!=id);
    document.querySelector(\`[data-msg-id="\${id}"]\`)?.remove();closeAllDropdowns();
}
function startEdit(id,isBot){
    const m=S.msgs.find(m=>m.id==id);if(!m)return;closeAllDropdowns();
    const wrap=document.querySelector(\`[data-msg-id="\${id}"]\`);if(!wrap)return;
    const txt=isBot?(m.variants?.[m.active_index||0]||''):(m.content||'');
    wrap.innerHTML=\`<div class="w-full max-w-2xl \${isBot?'':'ml-auto'} bg-white dark:bg-[#111] border border-gray-200 dark:border-gray-800 rounded-xl p-3">
        <textarea id="edit-ta-\${id}"class="w-full bg-transparent resize-none outline-none text-base md:text-sm min-h-[80px] p-2 dark:text-white"autofocus></textarea>
        <div class="flex justify-end space-x-2 mt-2">
            <button onclick="cancelEdit('\${id}')"class="text-xs px-3 py-1.5 rounded text-gray-500 hover:bg-gray-100 dark:hover:bg-gray-800">Cancel</button>
            <button onclick="saveEdit('\${id}',\${isBot})"class="text-xs px-3 py-1.5 rounded bg-black dark:bg-white text-white dark:text-black">Save</button>
        </div></div>\`;
    const ta=document.getElementById(\`edit-ta-\${id}\`);ta.value=txt;ta.focus();
}
function cancelEdit(id){refreshMsgEl(id);}
async function saveEdit(id,isBot){
    const ta=document.getElementById(\`edit-ta-\${id}\`);if(!ta)return;
    const val=ta.value.trim();if(!val)return;
    await api('editMessage',{id,content:val});
    const m=S.msgs.find(m=>m.id==id);
    if(m){if(isBot&&m.variants){m.variants[m.active_index||0]=val;}else m.content=val;}
    refreshMsgEl(id);
}

async function triggerSummarize(){
    $('summarize-banner').classList.remove('hf');lucide.createIcons();
    const res=await api('triggerSummarize');
    $('summarize-banner').classList.add('hf');
    if(res.summary){$('memory-summary-ta').value=res.summary;S.memory.current_summary=res.summary;}
    toast(res.error?'Summarize failed: '+res.error:'Summary updated!');
}
async function triggerSummarizeSilent(){
    $('summarize-banner').classList.remove('hf');lucide.createIcons();
    await api('triggerSummarize');
    $('summarize-banner').classList.add('hf');
}
async function saveSummaryEdit(){
    const val=$('memory-summary-ta').value;
    const res=await api('updateSummary',{summary:val});
    if(res.success){S.memory.current_summary=val;$('sum-save-hint').classList.remove('hf');setTimeout(()=>$('sum-save-hint').classList.add('hf'),2000);toast('Summary saved!');}
}

async function loadSketchboard(){
    const res=await api('manageSketchboard',{op:'list'});
    S.pins=Array.isArray(res.pins)?res.pins:(Array.isArray(res)?res:[]);
    S.sketchGlobal=res.global_active!==undefined?(res.global_active==1):true;
    renderSketchboard();
}
function renderSketchboard(){
    const list=$('pins-list'),cnt=$('sketch-count'),led=$('sketch-led');
    const activeCnt=S.pins.filter(p=>parseInt(p.is_active)===1).length;
    cnt.textContent=S.pins.length;
    led.className='w-2 h-2 rounded-full flex-shrink-0 transition-colors '+(S.sketchGlobal?'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.6)]':'bg-gray-400');
    const gt = $('global-sketch-toggle');
    if(gt) {
        gt.innerHTML = \`<i data-lucide="\${S.sketchGlobal ? 'toggle-right' : 'toggle-left'}" class="w-5 h-5"></i>\`;
        gt.className = S.sketchGlobal ? 'text-green-500 hover:text-gray-500 transition-colors' : 'text-gray-400 hover:text-green-500 transition-colors';
    }
    list.innerHTML='';
    S.pins.forEach(pin=>{
        const isActive = parseInt(pin.is_active) === 1;
        const li=document.createElement('li');
        li.className=\`p-3 rounded-lg border border-gray-200 dark:border-gray-800 bg-white dark:bg-[#111] text-sm relative group \${isActive?'':'opacity-50'}\`;
        li.innerHTML=\`<div class="pr-20 text-sm text-gray-700 dark:text-gray-300 break-words \${isActive?'':'line-through'}">\${esc(pin.content)}</div>
            <div class="absolute right-2 top-2 flex space-x-1 opacity-100 sm:opacity-0 group-hover:opacity-100 transition-opacity bg-white/80 dark:bg-[#111]/80 backdrop-blur-sm pl-1 rounded">
                <button onclick="togglePin('\${pin.id}')" class="p-1.5 sm:p-1 \${isActive?'text-green-500 hover:text-gray-500':'text-gray-400 hover:text-green-500'}" title="Toggle Active"><i data-lucide="\${isActive?'toggle-right':'toggle-left'}"class="w-4 h-4 sm:w-3.5 sm:h-3.5"></i></button>
                <button onclick="editPin('\${pin.id}')" class="p-1.5 sm:p-1 text-gray-400 hover:text-blue-500" title="Edit"><i data-lucide="edit-2"class="w-4 h-4 sm:w-3.5 sm:h-3.5"></i></button>
                <button onclick="deletePin('\${pin.id}')" class="p-1.5 sm:p-1 text-gray-400 hover:text-red-500" title="Delete"><i data-lucide="trash-2"class="w-4 h-4 sm:w-3.5 sm:h-3.5"></i></button>
            </div>\`;
        list.appendChild(li);
    });
    lucide.createIcons();
}
async function addPin(){const inp=$('new-pin-input'),val=inp.value.trim();if(!val)return;await api('manageSketchboard',{op:'add',content:val});inp.value='';await loadSketchboard();toast('Pinned!');}
async function addPinText(t){await api('manageSketchboard',{op:'add',content:t});await loadSketchboard();toast('Pinned!');}
async function deletePin(id){await api('manageSketchboard',{op:'delete',id});await loadSketchboard();}
function editPin(id){
    const p=S.pins.find(p=>p.id===id);if(!p)return;
    $('edit-pin-id').value = id;
    $('edit-pin-ta').value = p.content;
    openModal('edit-pin-modal');
}
async function savePinEdit(){
    const id=$('edit-pin-id').value;
    const v=$('edit-pin-ta').value.trim();
    if(!id||!v)return;
    await api('manageSketchboard',{op:'edit',id,content:v});
    closeModals();
    await loadSketchboard();
    toast('Pin saved!');
}
async function togglePin(id){
    await api('manageSketchboard',{op:'togglePin',id});
    await loadSketchboard();
}
async function toggleGlobalSketchboard(){
    S.sketchGlobal = !S.sketchGlobal;
    renderSketchboard();
    await api('manageSketchboard',{op:'toggleGlobal',active:S.sketchGlobal});
}

function renderSessionsList(){
    const cont=$('sessions-list');if(!cont)return;
    cont.innerHTML='';
    S.sessions.forEach(sess=>{
        const cur=sess.id===S.session;
        const div=document.createElement('div');
        div.className=\`border \${cur?'border-2 border-black dark:border-white bg-gray-50 dark:bg-[#111]':'border-gray-200 dark:border-gray-700 opacity-70 hover:opacity-100'} rounded-lg p-3 sm:p-4 relative cursor-pointer group hover:border-gray-400 dark:hover:border-gray-500 transition-all\`;
        div.innerHTML=\`\${cur?'<span class="absolute top-2 right-2 bg-black dark:bg-white text-white dark:text-black text-[10px] px-1.5 py-0.5 rounded">Current</span>':''}
            <h5 class="font-medium text-xs sm:text-sm mb-1 pr-12">\${esc(sess.label||sess.id)}</h5>
            \${!cur?\`<div class="absolute top-2 right-2 flex space-x-1 sm:space-x-2">
                <button onclick="event.stopPropagation();renameSession('\${sess.id}')"class="p-1 text-gray-400 hover:text-blue-500"><i data-lucide="edit-2"class="w-3.5 h-3.5"></i></button>
                <button onclick="event.stopPropagation();deleteSession('\${sess.id}')"class="p-1 text-gray-400 hover:text-red-500"><i data-lucide="trash-2"class="w-3.5 h-3.5"></i></button>
            </div>\`:\`\`}\`;
        if(!cur)div.onclick=()=>switchSession(sess.id);
        cont.appendChild(div);
    });
    lucide.createIcons();
}
async function switchSession(id){
    const res=await api('manageSessions',{op:'switch',session_id:id});
    if(res.error){toast('Error: '+res.error);return;}
    S.session=id;
    const s=S.sessions.find(s=>s.id===id);
    S.sessionLabel=s?.label||id;
    const d=await api('getInitData',{},'GET');
    if(d&&!d.error){
        S.memory=d.memory||{}; S.csrf=d.csrf_token;
        S.currentPersonaId=d.current_persona_id || (S.personas[0]?S.personas[0].id:null);
        populateMemoryForm();
    }
    S.msgs=[];S.hasMore=false;
    $('chat-container').innerHTML='';
    await loadChatHistory();
    S.pins=[];
    renderSketchboard();
    await loadSketchboard();
    updateHeader();
    closeModals();
}
async function newSession(){
    const label=prompt('Session name:','New Session '+new Date().toLocaleTimeString());if(!label)return;
    const res=await api('manageSessions',{op:'new',label,persona_id:S.currentPersonaId});
    if(res.success){
        S.sessions.push({id:res.session_id,label:res.label});
        S.session=res.session_id;S.sessionLabel=res.label;
        S.msgs=[];S.hasMore=false;S.memory={};S.pins=[];
        $('chat-container').innerHTML='';
        renderSketchboard();
        await loadSketchboard();
        updateHeader();
        renderSessionsList();
        toast('New session created!');
        closeModals();
    }
}
async function renameSession(id){
    const s=S.sessions.find(s=>s.id===id);
    const label=prompt('New name:',s?.label||id);if(!label)return;
    await api('manageSessions',{op:'rename',session_id:id,label});
    const idx=S.sessions.findIndex(s=>s.id===id);if(idx!==-1)S.sessions[idx].label=label;
    if(id===S.session){S.sessionLabel=label;updateHeader();}
    renderSessionsList();
}
async function deleteSession(id){
    if(!confirm('Delete this session and all its messages?'))return;
    await api('manageSessions',{op:'delete',session_id:id});
    S.sessions=S.sessions.filter(s=>s.id!==id);
    if(S.session===id){
        S.session='default';S.sessionLabel='Default Session';
        S.msgs=[];S.hasMore=false;
        await loadChatHistory();
    }
    renderSessionsList();
}

async function loadPersonas(){
    const res = await api('managePersonas', {op: 'list'});
    S.personas = Array.isArray(res) ? res : [];
    
    if(!S.currentPersonaId && S.personas.length > 0) S.currentPersonaId = S.personas[0].id;
    updateHeader();
    
    const cont = $('personas-list-container'); cont.innerHTML = '';
    S.personas.forEach(p => {
        const isCurrent = p.id == S.currentPersonaId;
        const div = document.createElement('div');
        div.className = \`flex items-center justify-between border \${isCurrent?'border-blue-500':'border-gray-200 dark:border-gray-700'} rounded-lg p-3 bg-white dark:bg-[#0a0a0a]\`;
        
        const avHtml = p.avatar.startsWith('http') ? \`<img src="\${esc(p.avatar)}" class="w-full h-full object-cover">\` : \`<span class="text-xs font-bold text-gray-500">\${esc(p.avatar.substring(0,2))}</span>\`;
        div.innerHTML = \`
            <div class="flex items-center space-x-3 min-w-0">
                <div class="w-10 h-10 rounded-lg bg-gray-100 dark:bg-gray-800 flex items-center justify-center overflow-hidden flex-shrink-0">\${avHtml}</div>
                <div class="min-w-0">
                    <p class="text-sm font-semibold truncate">\${esc(p.name)}\${isCurrent?'<span class="ml-2 text-[10px] bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400 px-1.5 py-0.5 rounded">Active in Session</span>':''}</p>
                    <p class="text-xs text-gray-500 truncate">\${esc(p.description || 'No description')}</p>
                </div>
            </div>
            <div class="flex items-center space-x-2 pl-3">
                \${!isCurrent ? \`<button onclick="changeSessionPersona('\${p.id}')" class="text-[10px] px-2 py-1 rounded border border-gray-200 dark:border-gray-700 hover:border-blue-500 hover:text-blue-500 transition-colors whitespace-nowrap">Use Here</button>\` : ''}
                <button onclick="showPersonaForm('\${p.id}')" class="p-1.5 text-gray-400 hover:text-blue-500"><i data-lucide="edit-2" class="w-4 h-4"></i></button>
                <button onclick="deletePersona('\${p.id}')" class="p-1.5 text-gray-400 hover:text-red-500"><i data-lucide="trash-2" class="w-4 h-4"></i></button>
            </div>
        \`;
        cont.appendChild(div);
    });
    lucide.createIcons();
}

function showPersonaForm(editId){
    S.editingPersonaId = editId;
    $('persona-edit-id').value = editId || '';
    $('personas-title').textContent = editId ? 'Edit Persona' : 'Create Persona';
    $('personas-list-view').classList.add('hf');
    $('personas-form-view').classList.remove('hf');
    
    if(editId) {
        const p = S.personas.find(x => x.id == editId);
        if(p) {
            $('persona-name').value = p.name; $('persona-avatar').value = p.avatar;
            $('persona-desc').value = p.description; $('persona-prompt').value = p.system_prompt;
            $('persona-user').value = p.user_persona; $('persona-first-msg').value = p.greeting_message;
        }
    } else {
        $('persona-name').value = ''; $('persona-avatar').value = 'AI';
        $('persona-desc').value = ''; $('persona-prompt').value = '';
        $('persona-user').value = ''; $('persona-first-msg').value = '';
    }
    updateAvatarPreview();
}

function hidePersonaForm(){
    $('personas-form-view').classList.add('hf');
    $('personas-list-view').classList.remove('hf');
    $('personas-title').textContent = 'Personas & Prompts';
}

async function savePersona(){
    const p = {
        op: S.editingPersonaId ? 'edit' : 'add',
        id: S.editingPersonaId,
        name: $('persona-name').value.trim(),
        avatar: $('persona-avatar').value.trim() || 'AI',
        description: $('persona-desc').value.trim(),
        system_prompt: $('persona-prompt').value.trim(),
        user_persona: $('persona-user').value.trim(),
        greeting_message: $('persona-first-msg').value.trim()
    };
    
    if(!p.name) { toast("Name is required"); return; }
    
    const res = await api('managePersonas', p);
    if(res.error) { toast(res.error); return; }
    
    hidePersonaForm();
    await loadPersonas();
    toast('Persona saved!');
}

async function deletePersona(id){
    if(!confirm("Delete this persona?")) return;
    const res = await api('managePersonas', {op: 'delete', id});
    if(res.error) { toast(res.error); return; }
    if(S.currentPersonaId == id) S.currentPersonaId = null;
    await loadPersonas();
    toast('Persona deleted.');
}

async function changeSessionPersona(pid) {
    closeAllDropdowns();
    const res = await api('setSessionPersona', { session_id: S.session, persona_id: pid });
    if(res.error) { toast(res.error); return; }
    S.currentPersonaId = pid;
    updateHeader();
    if(!$('persona-modal').classList.contains('hf')) loadPersonas();
    toast('Persona switched for this session.');
}

function updateHeader(){
    const persona = S.personas.find(p => p.id == S.currentPersonaId) || S.personas[0] || {name: 'System Assistant', avatar: 'AI'};
    $('header-name').textContent=persona.name;
    const label=S.sessions.find(s=>s.id===S.session)?.label||S.session;
    $('header-sess').textContent=label;
    const av=persona.avatar;
    $('header-avatar').innerHTML=av.startsWith('http')?\`<img src="\${esc(av)}"class="w-full h-full object-cover">\`:\`<span class="text-xs font-bold text-gray-600 dark:text-gray-300">\${esc(av.substring(0,2))}</span>\`;
}

function updateAvatarPreview(){
    const val=$('persona-avatar').value.trim();
    $('persona-avatar-preview').innerHTML=val.startsWith('http')?\`<img src="\${esc(val)}"class="w-full h-full object-cover">\`:\`<span class="text-xl font-bold text-gray-400">\${esc(val.substring(0,2)||'AI')}</span>\`;
}

function populateMemoryForm(){
    const m=S.memory;
    $('mem-threshold').value=m.summarize_threshold||50;$('mem-count').value=m.summarize_count||30;
    $('mem-context').value=m.context_count||20;$('mem-fetch').value=m.history_fetch_count||50;
    $('mem-include-old').checked=!!m.include_old_summary;
    $('memory-summary-ta').value=m.current_summary||'';
    const label=S.sessions.find(s=>s.id===S.session)?.label||S.session;
    $('mem-session-label').textContent='Session: '+label;
}

async function saveMemorySettings(){
    const res=await api('updateMemoryConfig',{memory:{summarize_threshold:$('mem-threshold').value,summarize_count:$('mem-count').value,context_count:$('mem-context').value,history_fetch_count:$('mem-fetch').value,include_old_summary:$('mem-include-old').checked?1:0}});
    if(res.success){toast('Memory settings saved!');closeModals();}
}

async function loadApiKeys(){
    const keys=await api('manageKeys',{op:'list'});
    const cont=$('keys-list-container');cont.innerHTML='';
    (Array.isArray(keys)?keys:[]).forEach(k=>{
        const div=document.createElement('div');
        div.className='flex flex-col sm:flex-row items-start sm:items-center justify-between border border-gray-200 dark:border-gray-700 rounded-lg p-3 sm:space-x-3 gap-2 sm:gap-0';
        div.innerHTML=\`<div class="flex items-center space-x-3 w-full sm:w-auto"><i data-lucide="key"class="w-4 h-4 text-gray-400"></i><div class="flex-1">
            <p class="text-sm font-medium">\${esc(k.provider)}<span class="text-[10px] \${k.is_primary?'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-100':'bg-gray-200 text-gray-800 dark:bg-gray-700 dark:text-gray-200'} px-1.5 py-0.5 rounded ml-1">\${k.is_primary?'Primary ':''}\${esc(k.key_mode)}</span></p>
            <p class="text-xs text-gray-500 font-mono">\${esc(k.masked_key||(k.provider==='custom'?'No key needed':'sk-...'))} • \${esc(k.model)}\${k.name?' • '+esc(k.name):''}</p></div></div>
            <div class="flex items-center space-x-2 self-end sm:self-auto">
                <button onclick="testKey('\${k.id}',this)" class="text-[10px] px-2 py-1 rounded border border-gray-200 dark:border-gray-700 text-gray-500 hover:border-green-500 hover:text-green-600 transition-colors" title="Test this endpoint">Test</button>
                <button onclick="showKeyForm('\${k.id}')"class="p-1 sm:p-0 text-gray-400 hover:text-blue-500"><i data-lucide="edit-2"class="w-4 h-4"></i></button>
                <button onclick="deleteKey('\${k.id}')"class="p-1 sm:p-0 text-gray-400 hover:text-red-500"><i data-lucide="trash-2"class="w-4 h-4"></i></button>
            </div>\`;
        cont.appendChild(div);
    });
    lucide.createIcons();
}

async function showKeyForm(editId){
    S.editingKeyId=editId;$('key-edit-id').value=editId||'';$('key-form-error').classList.add('hf');
    $('keys-title').textContent=editId?'Edit API Endpoint':'Add API Endpoint';
    $('keys-list-view').classList.add('hf');$('keys-form-view').classList.remove('hf');
    
    if(editId){
        const keys=await api('manageKeys',{op:'list'});
        const k=(Array.isArray(keys)?keys:[]).find(k=>k.id==editId);
        if(k){
            $('key-provider').value=k.provider; $('key-model').value=k.model; 
            $('key-custom-url').value=k.custom_url||'';
            $('key-mode').value=k.key_mode; $('key-value').value='';
            $('key-name').value=k.name||''; $('key-primary').checked=!!k.is_primary;
            $('custom-url-container').classList.toggle('hf', k.provider !== 'custom' && k.provider !== 'cloudflare');
            if(k.provider === 'custom') $('custom-url-label').textContent = 'Custom API URL';
            if(k.provider === 'cloudflare') $('custom-url-label').textContent = 'Cloudflare Account ID';
        }
    } else {
        $('key-provider').value='groq'; $('key-model').value=''; 
        $('key-custom-url').value='';
        $('key-mode').value='chat'; $('key-value').value=''; 
        $('key-name').value=''; $('key-primary').checked=false;
        $('custom-url-container').classList.add('hf');
    }
}

function hideKeyForm(){$('keys-form-view').classList.add('hf');$('keys-list-view').classList.remove('hf');$('keys-title').textContent='API Endpoints';}

async function saveKey(){
    const errEl=$('key-form-error'),editId=$('key-edit-id').value,kv=$('key-value').value.trim();
    if(!$('key-model').value.trim()){errEl.textContent='Model ID required';errEl.classList.remove('hf');return;}
    
    const isCustom = $('key-provider').value === 'custom';
    if(!editId && !kv && !isCustom){errEl.textContent='API key required';errEl.classList.remove('hf');return;}
    
    const p={op:editId?'edit':'add',provider:$('key-provider').value, custom_url:$('key-custom-url').value.trim(), model:$('key-model').value.trim(),key_mode:$('key-mode').value,name:$('key-name').value.trim(),is_primary:$('key-primary').checked?1:0};
    if(editId){p.id=editId;if(kv)p.api_key=kv;}else p.api_key=kv;
    
    const res=await api('manageKeys',p);
    if(res.error){errEl.textContent=res.error;errEl.classList.remove('hf');return;}
    hideKeyForm();await loadApiKeys();toast('Key saved!');
}

async function testKey(id,btn){
    const orig=btn.textContent;btn.textContent='…';btn.disabled=true;
    const res=await api('testKey',{id});
    btn.disabled=false;
    if(res.ok){btn.textContent='✓ OK';btn.className=btn.className.replace('text-gray-500','text-green-600');setTimeout(()=>{btn.textContent=orig;btn.className=btn.className.replace('text-green-600','text-gray-500');},3000);}
    else{btn.textContent='✗ Fail';btn.className=btn.className.replace('text-gray-500','text-red-500');toast('Test failed: '+(res.error||'unknown'),5000);setTimeout(()=>{btn.textContent=orig;btn.className=btn.className.replace('text-red-500','text-gray-500');},4000);}
}

async function deleteKey(id){if(!confirm('Delete this key/endpoint?'))return;await api('manageKeys',{op:'delete',id});await loadApiKeys();}

async function saveAccount(){
    const errEl=$('acct-error'),succEl=$('acct-success');errEl.classList.add('hf');succEl.classList.add('hf');
    const res=await api('updateAccount',{username:$('acct-username').value.trim(),password:$('acct-newpass').value,current_password:$('acct-curpass').value});
    if(res.error){errEl.textContent=res.error;errEl.classList.remove('hf');return;}
    S.username=$('acct-username').value.trim();$('sidebar-uname').textContent=S.username;
    succEl.textContent='Account updated!';succEl.classList.remove('hf');
    $('acct-curpass').value='';$('acct-newpass').value='';
}

function exportData(){window.location.href='?action=exportData';}

async function importData(e){
    const file=e.target.files[0];if(!file)return;
    const text=await file.text();
    const res=await api('importData',{data:text});
    if(res.success){toast(\`Imported \${res.imported} messages!\`);await loadChatHistory();closeModals();}
    else toast(res.error||'Import failed');
}

async function nukeServer(){
    const errEl=$('nuke-error');errEl.classList.add('hf');
    const pass=$('nuke-pass').value;if(!pass){errEl.textContent='Enter your password.';errEl.classList.remove('hf');return;}
    const res=await api('nukeServer',{password:pass});
    if(res.error){errEl.textContent=res.error;errEl.classList.remove('hf');return;}
    document.body.innerHTML='<div class="h-screen w-full bg-black flex flex-col items-center justify-center text-white space-y-4"><h1 class="text-2xl font-mono">DATABASE WIPED</h1><button onclick="location.reload()"class="mt-4 px-4 py-2 border border-white hover:bg-white hover:text-black font-mono">REBOOT</button></div>';
}

function openModal(id){
    if(id==='keys-modal')loadApiKeys();
    if(id==='persona-modal')loadPersonas();
    if(id==='sessions-modal')renderSessionsList();
    if(id==='memory-modal'){
        api('getInitData',{},'GET').then(d=>{if(d&&!d.error&&d.memory){S.memory=d.memory;populateMemoryForm();}});
    }
    if(id==='account-modal'){$('acct-username').value=S.username;$('acct-error').classList.add('hf');$('acct-success').classList.add('hf');}
    const bd=$('modal-backdrop');bd.classList.remove('hf');
    document.querySelectorAll('.modal-content').forEach(m=>m.classList.add('hf'));
    $(id).classList.remove('hf');
    setTimeout(()=>bd.classList.remove('opacity-0'),10);
}

function closeModals(){
    const bd=$('modal-backdrop');bd.classList.add('opacity-0');
    setTimeout(()=>{bd.classList.add('hf');document.querySelectorAll('.modal-content').forEach(m=>m.classList.add('hf'));},200);
    hideKeyForm(); hidePersonaForm();
}

function closeModalsOnBackdrop(e){if(e.target.id==='modal-backdrop')closeModals();}

document.addEventListener('keydown',e=>{if(e.key==='Escape'){closeModals();closeAllDropdowns();$('sketchboard-sidebar').classList.add('translate-x-full');$('sketchboard-overlay').classList.add('opacity-0');setTimeout(()=>$('sketchboard-overlay').classList.add('hf'),300);}});

function applyTheme(dark){document.documentElement.classList.toggle('dark',dark);$('theme-icon')?.setAttribute('data-lucide',dark?'sun':'moon');lucide.createIcons();}
function toggleTheme(){const d=document.documentElement.classList.toggle('dark');$('theme-icon')?.setAttribute('data-lucide',d?'sun':'moon');lucide.createIcons();document.cookie=\`aiphp_theme=\${d?'dark':'light'}; path=/; max-age=31536000\`;}
</script>
</body>
</html>`;
}

// ── DEDICATED SETUP PAGE ────────────────────────────────────────────
function getSetupHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>RSROLEPLAY Engine — Setup</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>tailwind.config={darkMode:'class'}</script>
</head>
<body class="bg-gray-50 dark:bg-[#0a0a0a] text-black dark:text-white min-h-screen flex items-center justify-center font-sans">
<div class="w-[calc(100%-2rem)] max-w-sm mx-auto">
  <div class="bg-white dark:bg-[#111] border border-gray-200 dark:border-gray-800 rounded-2xl shadow-2xl p-8">
    <div class="flex items-center space-x-3 mb-2">
      <div class="w-8 h-8 bg-black dark:bg-white rounded-md flex items-center justify-center">
        <span class="text-white dark:text-black text-xs font-bold">AI</span>
      </div>
      <h1 class="text-xl font-bold tracking-tight">RSROLEPLAY Engine</h1>
    </div>
    <p class="text-xs text-gray-500 mb-8">First time setup — create your admin account.</p>

    <div id="error-box" class="hidden mb-4 text-sm text-red-500 bg-red-50 dark:bg-red-900/20 px-3 py-2 rounded-lg"></div>

    <div class="space-y-4">
      <div>
        <label class="block text-xs font-medium text-gray-500 mb-1">Username</label>
        <input id="username" type="text" placeholder="admin" autofocus class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-sm outline-none focus:border-black dark:focus:border-white transition-colors">
      </div>
      <div>
        <label class="block text-xs font-medium text-gray-500 mb-1">Password</label>
        <input id="password" type="password" placeholder="••••••" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-sm outline-none focus:border-black dark:focus:border-white transition-colors">
      </div>
      <div>
        <label class="block text-xs font-medium text-gray-500 mb-1">Confirm Password</label>
        <input id="confirm" type="password" placeholder="••••••" class="w-full border border-gray-200 dark:border-gray-700 bg-transparent rounded-lg p-3 text-sm outline-none focus:border-black dark:focus:border-white transition-colors">
      </div>
      <button id="btn" onclick="doSetup()" class="w-full bg-black dark:bg-white text-white dark:text-black py-3 rounded-lg text-sm font-medium hover:opacity-80 transition-opacity flex items-center justify-center">
        <span>Create Account</span>
      </button>
    </div>
    <p class="text-[11px] text-gray-400 text-center mt-6">This page disappears after setup. Keep your credentials safe.</p>
  </div>
</div>
<script>
  if (window.matchMedia('(prefers-color-scheme: dark)').matches) document.documentElement.classList.add('dark');
  document.getElementById('username').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('password').focus(); });
  document.getElementById('password').addEventListener('keydown', e => { if (e.key === 'Enter') document.getElementById('confirm').focus(); });
  document.getElementById('confirm').addEventListener('keydown',  e => { if (e.key === 'Enter') doSetup(); });

  async function doSetup() {
    const btn      = document.getElementById('btn');
    const errBox   = document.getElementById('error-box');
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const confirm  = document.getElementById('confirm').value;

    errBox.classList.add('hidden');

    if (!username)          return showErr('Username is required.');
    if (!password)          return showErr('Password is required.');
    if (password.length<6)  return showErr('Password must be at least 6 characters.');
    if (password !== confirm) return showErr('Passwords do not match.');

    btn.disabled = true;
    btn.innerHTML = '<svg class="animate-spin w-4 h-4 mr-2" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 11-9-9"/></svg>Setting up...';

    try {
      const res  = await fetch('?action=setup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username, password, confirm }) });
      const data = await res.json();
      if (data.error) { showErr(data.error); resetBtn(); return; }
      window.location.href = '/';
    } catch { showErr('Connection error.'); resetBtn(); }
  }
  function showErr(msg) { document.getElementById('error-box').textContent = msg; document.getElementById('error-box').classList.remove('hidden'); }
  function resetBtn() { const btn = document.getElementById('btn'); btn.disabled = false; btn.innerHTML = '<span>Create Account</span>'; }
</script>
</body>
</html>`;
}
