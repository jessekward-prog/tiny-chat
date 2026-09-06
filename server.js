/* tiny-chat — a deliberately minimal chat UI over an OpenAI-compatible endpoint.
 *
 * There is no configuration in this app. No settings screen, no config file,
 * no .env, no defaults. The model endpoint comes entirely from environment
 * variables the host platform injects. If they are absent the server still
 * boots and reports itself unconfigured. */

const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 8080);

// Persisted state lives under dataDir so it survives the container being
// recreated on redeploy. Falls back to cwd when run outside the platform.
const DATA_DIR = process.env.DATA_DIR || '/app/data';
const PIN_FILE = path.join(fs.existsSync(DATA_DIR) ? DATA_DIR : __dirname, 'pin.json');

const SETTINGS_FILE = path.join(fs.existsSync(DATA_DIR) ? DATA_DIR : __dirname, 'settings.json');
const DEFAULT_SETTINGS = { systemPrompt: '', temperature: 0.7, topP: 1, maxTokens: 0, webSearch: false };
// Fleet-wide name, the same one llm-cmd uses. Not auto-detected by Hostess, so
// it must be declared in app.yaml's env: list.
const SEARX = (process.env.SEARXNG_URL || '').trim().replace(/\/+$/, '');

function readSettings() {
  try { return { ...DEFAULT_SETTINGS, ...JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')) }; }
  catch { return { ...DEFAULT_SETTINGS }; }
}
function writeSettings(next) {
  const clean = {
    systemPrompt: typeof next.systemPrompt === 'string' ? next.systemPrompt.slice(0, 4000) : '',
    temperature: Math.min(2, Math.max(0, Number(next.temperature) || 0)),
    topP: Math.min(1, Math.max(0.01, Number(next.topP) || 1)),
    maxTokens: Math.max(0, Math.floor(Number(next.maxTokens) || 0)),   // 0 = let the model decide
    webSearch: !!next.webSearch,
  };
  fs.mkdirSync(path.dirname(SETTINGS_FILE), { recursive: true });
  const tmp = `${SETTINGS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(clean));
  fs.renameSync(tmp, SETTINGS_FILE);
  return clean;
}

const CHATS_FILE = path.join(fs.existsSync(DATA_DIR) ? DATA_DIR : __dirname, 'chats.json');

function readChats() {
  try { return JSON.parse(fs.readFileSync(CHATS_FILE, 'utf8')); } catch { return []; }
}
// tmp + rename, so a crash mid-write can't leave a truncated file behind —
// same approach Hostess uses for its own registry.
function writeChats(chats) {
  fs.mkdirSync(path.dirname(CHATS_FILE), { recursive: true });
  const tmp = `${CHATS_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(chats));
  fs.renameSync(tmp, CHATS_FILE);
}
const titleFrom = (text) => (text || 'New chat').replace(/\s+/g, ' ').trim().slice(0, 48) || 'New chat';

function readPin() {
  try { return JSON.parse(fs.readFileSync(PIN_FILE, 'utf8')); } catch { return null; }
}
function writePin(pin) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(pin, salt, 32).toString('hex');
  const secret = crypto.randomBytes(32).toString('hex');
  fs.mkdirSync(path.dirname(PIN_FILE), { recursive: true });
  fs.writeFileSync(PIN_FILE, JSON.stringify({ salt, hash, secret }));
  cached = { salt, hash, secret };
  return cached;
}
function verifyPin(rec, pin) {
  const h = crypto.scryptSync(pin, rec.salt, 32);
  const known = Buffer.from(rec.hash, 'hex');
  return h.length === known.length && crypto.timingSafeEqual(h, known);
}
// Cookie is an HMAC of the stored secret, so a container restart doesn't
// log everyone out and no session table is needed.
const tokenFor = (rec) => crypto.createHmac('sha256', rec.secret).update('unlocked').digest('hex');
function unlocked(req) {
  const rec = current();
  if (!rec) return false;
  const cookie = /(?:^|;\s*)tc=([a-f0-9]{64})/.exec(req.headers.cookie || '');
  if (!cookie) return false;
  const a = Buffer.from(cookie[1], 'hex'), b = Buffer.from(tokenFor(rec), 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
// APP_PIN is the operator's channel: it preseeds on first boot, and it also
// OVERRIDES a PIN that was set interactively — that's the documented contract.
// Reconciled once at startup rather than per request, because verifying costs a
// deliberate scrypt and the env can't change under a running container anyway.
let cached = null;
function current() { return cached; }

(function reconcileEnvPin() {
  let rec = readPin();
  const envPin = process.env.APP_PIN ? String(process.env.APP_PIN) : null;
  if (envPin && /^[0-9]{4,12}$/.test(envPin) && (!rec || !verifyPin(rec, envPin))) {
    rec = writePin(envPin);   // new secret invalidates existing cookies, which is correct for a PIN change
    console.log('APP_PIN from the environment applied — any previously set PIN is replaced.');
  }
  cached = rec;
})();

// The only three knobs, and none of them have a fallback value on purpose.
const lm = () => ({
  url: (process.env.LM_STUDIO_URL || '').trim().replace(/\/+$/, ''),
  key: process.env.LM_STUDIO_API_KEY || '',
  model: process.env.LM_STUDIO_MODEL || '',
});

const cookie = (v) => `tc=${v}; HttpOnly; SameSite=Strict; Path=/; Max-Age=31536000`;

async function readBody(req) {
  let raw = '';
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 100_000) { req.destroy(); return null; }
  }
  try { return JSON.parse(raw); } catch { return null; }
}

const json = (res, code, body) => {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
};

// LM_STUDIO_MODEL is the operator's default, not a cage. The app holds the
// endpoint and key, so it can enumerate what's available and let the user pick.
async function listModels() {
  const { url, key } = lm();
  if (!url) return [];
  const res = await fetch(`${url}/api/v0/models`, {
    headers: { ...(key && { authorization: `Bearer ${key}` }) },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`model list returned HTTP ${res.status}`);
  const data = await res.json();
  return (data.data || [])
    .filter((m) => m.type === 'llm' || m.type === 'vlm')
    .map((m) => ({ id: m.id, loaded: m.state === 'loaded', quant: m.quantization || null }));
}

// Retrieval happens here and is injected as context. We deliberately do NOT
// hand the model a tool and hope: a model claiming to have searched without
// searching is a documented failure mode, and pre-fetched results can't be faked.
async function webSearch(query) {
  if (!SEARX) throw new Error('No search backend configured on this deployment.');
  const url = `${SEARX}/search?q=${encodeURIComponent(query)}&format=json&safesearch=0`;
  const res = await fetch(url, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(9000) });
  if (!res.ok) throw new Error(`search backend returned HTTP ${res.status}`);
  const data = await res.json();
  return (data.results || []).slice(0, 5).map((r) => ({
    title: (r.title || '').trim(),
    url: r.url,
    snippet: (r.content || '').trim().slice(0, 400),
  }));
}

function searchContext(query, results) {
  const body = results.map((r, i) => `[${i + 1}] ${r.title}\n${r.url}\n${r.snippet}`).join('\n\n');
  return `Web search results for "${query}". Use them if relevant and cite by number; say so if they do not answer the question.\n\n${body}`;
}

async function chat(messages, override) {
  const cfg = readSettings();
  const { url, key, model: def } = lm();
  const prepared = cfg.systemPrompt ? [{ role: 'system', content: cfg.systemPrompt }, ...messages] : [...messages];
  const model = override || def;
  if (!url) throw new Error('No model endpoint configured on this deployment.');
  const res = await fetch(`${url}/v1/chat/completions`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(key && { authorization: `Bearer ${key}` }) },
    body: JSON.stringify({
      model: model || undefined,
      messages: prepared,
      temperature: cfg.temperature,
      top_p: cfg.topP,
      ...(cfg.maxTokens > 0 && { max_tokens: cfg.maxTokens }),
    }),
    signal: AbortSignal.timeout(120000),
  });
  if (!res.ok) {
    // Pass the endpoint's own message through. Flattening this to the status
    // code hides the useful part — "Failed to load model" (usually VRAM) looks
    // identical to a bad model id or a bad key until you read the body.
    const detail = await res.text().catch(() => '');
    let msg = '';
    try { msg = JSON.parse(detail)?.error?.message || ''; } catch { msg = detail.slice(0, 200); }
    throw new Error(`model endpoint returned HTTP ${res.status}${msg ? ` — ${msg}` : ''}`);
  }
  const data = await res.json();
  const choice = data.choices?.[0];
  const reply = choice?.message?.content;
  if (!reply) {
    // A too-low max_tokens burns the whole budget before any text is emitted,
    // which otherwise surfaces as a baffling empty response.
    if (choice?.finish_reason === 'length') {
      throw new Error('Max tokens is too low — the reply was cut off before any text was produced. Raise it in settings, or set it to 0.');
    }
    throw new Error('model endpoint returned no message');
  }
  return reply;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  if (url.pathname === '/api/state') {
    return json(res, 200, { needsSetup: !current(), locked: !unlocked(req) });
  }

  if (url.pathname === '/api/setup' && req.method === 'POST') {
    if (current()) return json(res, 409, { error: 'A PIN is already set.' });
    const body = await readBody(req);
    const pin = String(body?.pin || '');
    if (!/^[0-9]{4,12}$/.test(pin)) return json(res, 400, { error: 'PIN must be 4-12 digits.' });
    const rec = writePin(pin);
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': cookie(tokenFor(rec)) });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (url.pathname === '/api/unlock' && req.method === 'POST') {
    const rec = current();
    if (!rec) return json(res, 409, { error: 'No PIN set yet.' });
    const body = await readBody(req);
    if (!verifyPin(rec, String(body?.pin || ''))) return json(res, 401, { error: 'Wrong PIN.' });
    res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': cookie(tokenFor(rec)) });
    return res.end(JSON.stringify({ ok: true }));
  }

  // Everything past here requires an unlocked session.
  if (url.pathname.startsWith('/api/') && !unlocked(req)) {
    return json(res, 401, { error: 'locked' });
  }

  const chatMatch = /^\/api\/chats\/([a-z0-9]{6,32})$/.exec(url.pathname);

  if (url.pathname === '/api/chats' && req.method === 'GET') {
    // List view never needs the message bodies.
    return json(res, 200, { chats: readChats().map(({ messages, ...c }) => c) });
  }

  if (url.pathname === '/api/chats' && req.method === 'POST') {
    const chats = readChats();
    const chat = { id: crypto.randomBytes(8).toString('hex'), title: 'New chat', model: null, updatedAt: Date.now(), messages: [] };
    chats.unshift(chat);
    writeChats(chats);
    return json(res, 200, { chat });
  }

  if (chatMatch && req.method === 'GET') {
    const chat = readChats().find((c) => c.id === chatMatch[1]);
    return chat ? json(res, 200, { chat }) : json(res, 404, { error: 'no such chat' });
  }

  if (chatMatch && req.method === 'PUT') {
    const body = await readBody(req);
    if (!Array.isArray(body?.messages)) return json(res, 400, { error: 'messages required' });
    const chats = readChats();
    const i = chats.findIndex((c) => c.id === chatMatch[1]);
    if (i < 0) return json(res, 404, { error: 'no such chat' });
    const first = body.messages.find((m) => m.role === 'user');
    chats[i] = { ...chats[i], messages: body.messages, model: body.model || chats[i].model,
                 title: chats[i].title === 'New chat' && first ? titleFrom(first.content) : chats[i].title,
                 updatedAt: Date.now() };
    const [moved] = chats.splice(i, 1);
    chats.unshift(moved);
    writeChats(chats);
    return json(res, 200, { chat: { ...moved, messages: undefined } });
  }

  if (chatMatch && req.method === 'DELETE') {
    writeChats(readChats().filter((c) => c.id !== chatMatch[1]));
    return json(res, 200, { ok: true });
  }

  if (url.pathname === '/api/settings' && req.method === 'GET') {
    return json(res, 200, { settings: readSettings(), searchAvailable: !!SEARX });
  }
  if (url.pathname === '/api/settings' && req.method === 'PUT') {
    const body = await readBody(req);
    if (!body) return json(res, 400, { error: 'bad JSON' });
    return json(res, 200, { settings: writeSettings(body) });
  }

  if (url.pathname === '/api/models') {
    try { return json(res, 200, { models: await listModels(), current: lm().model || null }); }
    catch (err) { return json(res, 502, { error: err.message }); }
  }

  if (url.pathname === '/api/status') {
    const { url: u, key, model } = lm();
    // Never report the key itself — only whether one arrived.
    return json(res, 200, { configured: !!u, host: u ? new URL(u).host : null, model: model || null, keySet: !!key });
  }

  if (url.pathname === '/api/chat' && req.method === 'POST') {
    const body = await readBody(req);
    const messages = body?.messages;
    if (!Array.isArray(messages) || !messages.length) return json(res, 400, { error: 'messages required' });
    try {
      const cfg = readSettings();
      let sources = null;
      let augmented = messages;
      if (cfg.webSearch && SEARX) {
        const q = [...messages].reverse().find((m) => m.role === 'user')?.content || '';
        try {
          const results = await webSearch(q);
          if (results.length) {
            sources = results;
            augmented = [...messages.slice(0, -1), { role: 'system', content: searchContext(q, results) }, messages[messages.length - 1]];
          }
        } catch (err) {
          sources = { error: err.message };   // a dead backend must not take the reply down
        }
      }
      return json(res, 200, { reply: await chat(augmented, body?.model), sources });
    } catch (err) {
      return json(res, 502, { error: err.message });
    }
  }

  if (url.pathname === '/') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(PAGE);
  }

  json(res, 404, { error: 'not found' });
});

// Node running as PID 1 gets no default signal disposition from the kernel, so
// without these handlers SIGTERM is simply dropped: the platform waits out its
// full grace period and then SIGKILLs us mid-write. Close cleanly instead.
for (const sig of ['SIGTERM', 'SIGINT']) {
  process.on(sig, () => {
    server.close(() => process.exit(0));
    // Don't let a hung keep-alive connection outlast the grace period.
    setTimeout(() => process.exit(0), 4000).unref();
  });
}

server.listen(PORT, '0.0.0.0', () => {
  const { url } = lm();
  console.log(`tiny-chat listening on 0.0.0.0:${PORT} — model endpoint ${url ? 'configured' : 'NOT configured'}`);
});

const PAGE = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Tiny Chat</title>
<script>
// Applied before first paint so a stored theme (or the OS preference, first
// visit) never flashes the light default first.
(function(){try{
  var t=localStorage.getItem('tc-theme');
  if(!t) t=matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
  if(t!=='light') document.documentElement.classList.add('theme-'+t);
}catch(e){}})();
</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:#f7f7f8; --surface:#fff; --border:#e4e4e7; --text:#18181b; --text-2:#71717a;
    --me:#18181b; --me-text:#fff; --them:#f1f1f3; --ok:#16a34a; --off:#a1a1aa; --err:#dc2626;
    --radius:14px; --scanline:0;
    --sans:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    --mono:'JetBrains Mono',ui-monospace,Menlo,Consolas,monospace;
    --ibm:'IBM Plex Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    --font-ui:var(--sans); --font-body:var(--sans);
  }
  /* Explicit theme picked in settings always wins. With none stored yet, the
     inline head script above falls back to the OS preference on first paint. */
  html.theme-dark {
    --bg:#09090b; --surface:#131316; --border:#27272a; --text:#fafafa; --text-2:#a1a1aa;
    --me:#fafafa; --me-text:#09090b; --them:#1f1f23; --off:#52525b; --ok:#22c55e; --err:#f87171;
  }
  /* Burnt-amber CRT — same phosphor palette as this fleet's other terminal-styled
     apps (llm-cmd). Monospace throughout and a scanline overlay is what sells it,
     not just the color swap. */
  html.theme-amber {
    --bg:#0e0a00; --surface:#1a1200; --border:#3d2e00; --text:#e8a040; --text-2:#a57d00;
    --me:#e8840a; --me-text:#0e0a00; --them:#241a00; --ok:#4ade80; --off:#826200; --err:#f87171;
    --font-ui:var(--mono); --font-body:var(--mono); --scanline:1;
  }
  /* Matches hostess.cmdward.xyz/rules.html: black/white mono chrome, IBM Plex
     Sans for reading text, the same ok/err accents as its compliance tags. */
  html.theme-hostess {
    --bg:#000000; --surface:#111111; --border:#2c2c2c; --text:#ffffff; --text-2:#767676;
    --me:#ffffff; --me-text:#000000; --them:#1e1e1e; --ok:#3fb37f; --off:#474747; --err:#e0564f;
    --font-ui:var(--mono); --font-body:var(--ibm);
  }
  *{box-sizing:border-box}
  body{margin:0;height:100dvh;display:flex;background:var(--bg);color:var(--text);font:15px/1.55 var(--font-body);-webkit-font-smoothing:antialiased;transition:background .2s,color .2s}
  h1,h2,.pill,.card h2,#gt,label b,select#pick,button{font-family:var(--font-ui)}
  /* CRT scanlines — only the amber theme sets --scanline to 1. */
  body::after{content:'';position:fixed;inset:0;pointer-events:none;z-index:999;opacity:calc(var(--scanline) * .4);
    background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,.08) 2px,rgba(0,0,0,.08) 4px)}
  #side{position:relative;width:250px;flex:none;background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;transition:margin-left .2s cubic-bezier(.2,.7,.3,1)}
  #side h2{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--text-2);margin:0;padding:0 14px 8px}
  #newBtn{margin:14px 12px 12px;padding:9px;font:inherit;font-size:13.5px;font-weight:600;border:1px solid var(--border);background:var(--bg);color:var(--text);border-radius:10px;cursor:pointer;transition:border-color .14s,background .14s}
  #newBtn:hover{border-color:var(--text-2);background:var(--them)}
  #list{flex:1;overflow-y:auto;padding:0 8px calc(12px + env(safe-area-inset-bottom));display:flex;flex-direction:column;gap:2px}
  .drawerX{display:none;position:absolute;top:10px;right:10px;width:30px;height:30px;border:1px solid var(--border);background:var(--bg);color:var(--text-2);border-radius:8px;cursor:pointer;font-size:18px;line-height:1;align-items:center;justify-content:center}
  #scrim{display:none;position:fixed;inset:0;background:rgba(0,0,0,.5);z-index:19}
  .item{display:flex;align-items:center;gap:6px;padding:8px 10px;border-radius:9px;cursor:pointer;font-size:13.5px;color:var(--text-2);transition:background .12s,color .12s}
  .item:hover{background:var(--them);color:var(--text)}
  .item.on{background:var(--them);color:var(--text);font-weight:500}
  .item .t{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .item .x{opacity:0;border:0;background:none;color:var(--text-2);cursor:pointer;font-size:15px;line-height:1;padding:2px 4px;border-radius:5px;flex:none}
  .item:hover .x{opacity:.65}
  .item .x:hover{opacity:1;color:var(--err);background:var(--bg)}
  .item.empty{color:var(--text-2);cursor:default;font-size:12.5px;padding:10px}
  .item.empty:hover{background:none}
  #col{flex:1;min-width:0;display:flex;flex-direction:column}
  #cfg{position:relative;width:290px;flex:none;background:var(--surface);border-left:1px solid var(--border);overflow-y:auto;padding:18px 16px calc(18px + env(safe-area-inset-bottom));transition:margin-right .2s cubic-bezier(.2,.7,.3,1)}
  body:not(.cfg) #cfg{margin-right:-290px}
  #cfg h2{font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--text-2);margin:0 0 14px}
  .fld{margin-bottom:16px}
  .fld label{display:flex;justify-content:space-between;align-items:baseline;font-size:12.5px;color:var(--text-2);margin-bottom:5px}
  .fld label b{color:var(--text);font-weight:600}
  .fld .v{font-variant-numeric:tabular-nums;color:var(--text)}
  .fld input[type=range]{width:100%;accent-color:var(--me)}
  .fld input[type=checkbox]{accent-color:var(--me);width:16px;height:16px;cursor:pointer}
  .fld.off{opacity:.5}
  .fld.off input{pointer-events:none}
  .src{margin-top:7px;font-size:12px;color:var(--text-2);display:flex;flex-direction:column;gap:3px}
  .src a{color:var(--text-2);text-decoration:none}
  .src a:hover{color:var(--text);text-decoration:underline}
  .fld input[type=number],.fld textarea{width:100%;font:inherit;font-size:13px;color:inherit;background:var(--bg);border:1px solid var(--border);border-radius:9px;padding:8px 10px;outline:none;transition:border-color .14s}
  .fld textarea{resize:vertical;min-height:84px;line-height:1.5}
  .fld input:focus,.fld textarea:focus{border-color:var(--text-2)}
  .fld .hint{font-size:11.5px;color:var(--text-2);margin-top:5px;line-height:1.45}
  #saved{font-size:11.5px;color:var(--ok);opacity:0;transition:opacity .2s}
  #saved.on{opacity:1}
  .swatches{display:flex;gap:9px}
  .swatches button{width:30px;height:30px;border-radius:50%;border:2px solid var(--border);cursor:pointer;padding:0;background:var(--sw,var(--surface))}
  .swatches button.on{border-color:var(--text)}
  #themeSw button[data-theme=light]{--sw:linear-gradient(135deg,#fff 50%,#e4e4e7 50%)}
  #themeSw button[data-theme=dark]{--sw:linear-gradient(135deg,#131316 50%,#09090b 50%)}
  #themeSw button[data-theme=amber]{--sw:linear-gradient(135deg,#1a1200 50%,#e8840a 50%)}
  #themeSw button[data-theme=hostess]{--sw:linear-gradient(135deg,#111 50%,#3fb37f 50%)}
  #themeSw button{background:var(--sw)}
  @media(max-width:980px){
    #cfg{position:fixed;inset:0 0 0 auto;z-index:20;box-shadow:0 0 40px rgba(0,0,0,.4)}
    body.cfg #scrim{display:block}
    .drawerX.cfgX{display:flex}
    #gear{width:40px;height:40px;font-size:17px}
  }
  #burger,#gear{display:none;align-items:center;justify-content:center;border:1px solid var(--border);background:var(--bg);color:var(--text);border-radius:8px;width:30px;height:30px;cursor:pointer;font-size:15px;line-height:1;flex:none}
  #gear{display:flex}
  body.cfg #gear{border-color:var(--text-2)}
  @media(max-width:760px){
    #side{position:fixed;inset:0 auto 0 0;z-index:20;margin-left:-250px;box-shadow:0 0 40px rgba(0,0,0,.4)}
    body.nav #side{margin-left:0}
    body.nav #scrim{display:block}
    #burger{display:flex;width:40px;height:40px;font-size:17px}
    .drawerX.sideX{display:flex}
    #t{font-size:16px}
    #b{min-height:44px}
  }
  header{display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid var(--border);background:var(--surface)}
  header h1{font-size:15px;font-weight:600;margin:0;flex:1;letter-spacing:-.01em;white-space:nowrap}
  @media(max-width:1150px){ .pill{display:none} }
  select#pick{font:inherit;font-size:12px;color:var(--text);background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:5px 8px;max-width:230px;outline:none;cursor:pointer}
  select#pick:focus{border-color:var(--text-2)}
  .pill{display:inline-flex;align-items:center;gap:6px;font-size:11.5px;color:var(--text-2);background:var(--bg);border:1px solid var(--border);padding:4px 10px;border-radius:999px}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--off);flex:none}
  .dot.on{background:var(--ok)}
  main{flex:1;overflow-y:auto;padding:22px 18px;display:flex;flex-direction:column;gap:12px}
  .wrap{max-width:680px;margin:0 auto;width:100%;display:flex;flex-direction:column;gap:12px}
  .msg{display:flex;animation:rise .22s cubic-bezier(.2,.7,.3,1)}
  .msg.me{justify-content:flex-end}
  .bub{max-width:78%;padding:10px 14px;border-radius:var(--radius);white-space:pre-wrap;word-wrap:break-word}
  .me .bub{background:var(--me);color:var(--me-text);border-bottom-right-radius:5px}
  .them .bub{background:var(--them);border-bottom-left-radius:5px}
  @keyframes rise{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .empty{margin:auto;text-align:center;color:var(--text-2);font-size:13.5px;max-width:34ch}
  .banner{border:1px solid var(--border);border-left:3px solid var(--err);background:var(--surface);padding:11px 14px;border-radius:0 10px 10px 0;font-size:13px;color:var(--text-2)}
  .banner b{color:var(--text)}
  .typing{display:flex;gap:4px;padding:13px 15px;background:var(--them);border-radius:var(--radius);border-bottom-left-radius:5px;width:fit-content}
  .typing i{width:6px;height:6px;border-radius:50%;background:var(--text-2);animation:blink 1.3s infinite}
  .typing i:nth-child(2){animation-delay:.18s} .typing i:nth-child(3){animation-delay:.36s}
  @keyframes blink{0%,60%,100%{opacity:.25}30%{opacity:1}}
  footer{border-top:1px solid var(--border);background:var(--surface);padding:12px 18px calc(12px + env(safe-area-inset-bottom))}
  form{max-width:680px;margin:0 auto;display:flex;gap:9px;align-items:flex-end}
  textarea{flex:1;resize:none;font:inherit;color:inherit;background:var(--bg);border:1px solid var(--border);border-radius:11px;padding:10px 13px;max-height:140px;outline:none;transition:border-color .14s}
  textarea:focus{border-color:var(--text-2)}
  button{font:inherit;font-weight:600;font-size:14px;background:var(--me);color:var(--me-text);border:0;border-radius:11px;padding:10px 18px;cursor:pointer;transition:opacity .14s,transform .08s}
  button:disabled{opacity:.4;cursor:default}
  button:not(:disabled):active{transform:scale(.97)}
  @media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
  #gate{position:fixed;inset:0;background:var(--bg);display:none;align-items:center;justify-content:center;padding:calc(24px + env(safe-area-inset-top)) 24px calc(24px + env(safe-area-inset-bottom));z-index:10}
  #gate.show{display:flex}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:28px 26px;width:100%;max-width:330px;text-align:center}
  .card h2{margin:0 0 6px;font-size:16px;font-weight:600;letter-spacing:-.01em}
  .card p{margin:0 0 18px;font-size:13px;color:var(--text-2)}
  .card input{width:100%;font:inherit;font-size:20px;letter-spacing:.4em;text-align:center;color:inherit;background:var(--bg);border:1px solid var(--border);border-radius:11px;padding:11px;margin-bottom:9px;outline:none;transition:border-color .14s}
  .card input:focus{border-color:var(--text-2)}
  .card button{width:100%;margin-top:6px}
  .card .err{color:var(--err);font-size:12.5px;min-height:17px;margin:4px 0 0}
</style></head><body>
<div id="gate"><div class="card">
  <h2 id="gt">Set a PIN</h2>
  <p id="gp">Choose a 4-12 digit PIN. You'll need it each time.</p>
  <input id="p1" type="password" inputmode="numeric" autocomplete="off" placeholder="••••">
  <input id="p2" type="password" inputmode="numeric" autocomplete="off" placeholder="confirm">
  <div class="err" id="ge"></div>
  <button id="gb" type="button">Continue</button>
</div></div>
<div id="scrim"></div>
<aside id="side">
  <button class="drawerX sideX" id="sideClose" type="button" aria-label="Close">&times;</button>
  <button id="newBtn" type="button">+ New chat</button>
  <h2>History</h2>
  <div id="list"></div>
</aside>
<div id="col">
<header>
  <button id="burger" type="button" aria-label="Conversations">&#9776;</button>
  <h1>Tiny Chat</h1>
  <select id="pick" title="Model — the operator's default is preselected"></select>
  <span class="pill"><span class="dot" id="dot"></span><span id="stat">checking…</span></span>
  <button id="gear" type="button" aria-label="Settings" title="Model settings">&#9881;</button>
</header>
<main><div class="wrap" id="log"><div class="empty" id="empty">No configuration lives in this app. Whatever model answers below was supplied entirely by the host platform.</div></div></main>
<footer><form id="f">
  <textarea id="t" rows="1" placeholder="Message…" autocomplete="off"></textarea>
  <button id="b" type="submit">Send</button>
</form></footer>
</div>
<aside id="cfg">
  <button class="drawerX cfgX" id="cfgClose" type="button" aria-label="Close">&times;</button>
  <div class="fld">
    <label><b>Theme</b></label>
    <div class="swatches" id="themeSw">
      <button data-theme="light" type="button" title="Light" aria-label="Light theme"></button>
      <button data-theme="dark" type="button" title="Dark" aria-label="Dark theme"></button>
      <button data-theme="amber" type="button" title="Amber CRT" aria-label="Amber CRT theme"></button>
      <button data-theme="hostess" type="button" title="Hostess" aria-label="Hostess theme"></button>
    </div>
  </div>
  <h2>Model settings</h2>
  <div class="fld" id="fWeb">
    <label><b>Web search</b><input id="sWeb" type="checkbox"></label>
    <div class="hint" id="hWeb">Searches before answering and passes the results in as context — the model is never asked to fetch anything itself.</div>
  </div>
  <div class="fld">
    <label><b>System prompt</b></label>
    <textarea id="sSys" placeholder="Optional. Prepended to every message in every conversation."></textarea>
  </div>
  <div class="fld">
    <label><b>Temperature</b><span class="v" id="vTemp">0.70</span></label>
    <input id="sTemp" type="range" min="0" max="2" step="0.05">
    <div class="hint">Lower is more deterministic, higher more varied.</div>
  </div>
  <div class="fld">
    <label><b>Top P</b><span class="v" id="vTop">1.00</span></label>
    <input id="sTop" type="range" min="0.05" max="1" step="0.05">
    <div class="hint">Nucleus sampling. Leave at 1 unless you know you want it lower.</div>
  </div>
  <div class="fld">
    <label><b>Max tokens</b></label>
    <input id="sMax" type="number" min="0" step="64" placeholder="0">
    <div class="hint">0 lets the model decide. Raise it if long replies are being cut off.</div>
  </div>
  <div id="saved">Saved</div>
</aside>
<script>
  const log=document.getElementById('log'), empty=document.getElementById('empty');
  const f=document.getElementById('f'), t=document.getElementById('t'), b=document.getElementById('b');
  const dot=document.getElementById('dot'), stat=document.getElementById('stat');
  let history=[]; let busy=false; let currentId=null;
  const side=document.getElementById('side'), list=document.getElementById('list');
  const newBtn=document.getElementById('newBtn'), burger=document.getElementById('burger');
  burger.addEventListener('click',()=>document.body.classList.toggle('nav'));

  const scrim=document.getElementById('scrim');
  const closeDrawers=()=>document.body.classList.remove('nav','cfg');
  scrim.addEventListener('click',closeDrawers);
  document.getElementById('sideClose').addEventListener('click',closeDrawers);
  document.getElementById('cfgClose').addEventListener('click',closeDrawers);

  const themeSw=document.getElementById('themeSw');
  function applyTheme(t){
    document.documentElement.className=t==='light'?'':'theme-'+t;
    themeSw.querySelectorAll('button').forEach(el=>el.classList.toggle('on',el.dataset.theme===t));
    try{localStorage.setItem('tc-theme',t);}catch(e){}
  }
  themeSw.querySelectorAll('button').forEach(el=>el.addEventListener('click',()=>applyTheme(el.dataset.theme)));
  applyTheme((()=>{ try{return localStorage.getItem('tc-theme');}catch(e){return null;} })()
    || (matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'));

  function when(ts){
    const m=Math.floor((Date.now()-ts)/60000);
    if(m<1) return 'just now'; if(m<60) return m+'m ago';
    const h=Math.floor(m/60); if(h<24) return h+'h ago';
    return Math.floor(h/24)+'d ago';
  }

  function renderList(chats){
    list.innerHTML='';
    if(!chats.length){ const e=document.createElement('div'); e.className='item empty'; e.textContent='No conversations yet.'; list.append(e); return; }
    for(const c of chats){
      const row=document.createElement('div'); row.className='item'+(c.id===currentId?' on':'');
      row.title=c.title+' — '+when(c.updatedAt);
      const t=document.createElement('span'); t.className='t'; t.textContent=c.title;
      const x=document.createElement('button'); x.className='x'; x.type='button'; x.textContent='\u00d7'; x.title='Delete';
      t.addEventListener('click',()=>openChat(c.id));
      row.addEventListener('click',e=>{ if(e.target!==x) openChat(c.id); });
      x.addEventListener('click',async e=>{ e.stopPropagation();
        await fetch('/api/chats/'+c.id,{method:'DELETE'});
        if(c.id===currentId){ currentId=null; history=[]; }
        await refresh(true);
      });
      row.append(t,x); list.append(row);
    }
  }

  async function refresh(autoOpen){
    const d=await fetch('/api/chats').then(r=>r.json()).catch(()=>({chats:[]}));
    renderList(d.chats||[]);
    if(autoOpen){
      if(d.chats&&d.chats.length) await openChat(d.chats[0].id);
      else await newChat();
    }
  }

  function paint(){
    log.innerHTML='';
    if(!history.length){
      const e=document.createElement('div'); e.className='empty';
      e.textContent='No configuration lives in this app. Whatever model answers below was supplied entirely by the host platform.';
      log.append(e); return;
    }
    for(const m of history) bubble(m.role==='user'?'me':'them', m.content);
  }

  async function openChat(id){
    const d=await fetch('/api/chats/'+id).then(r=>r.json()).catch(()=>null);
    if(!d||!d.chat) return;
    currentId=d.chat.id; history=d.chat.messages||[];
    paint(); document.body.classList.remove('nav');
    await refresh(false);
  }

  async function newChat(){
    const d=await fetch('/api/chats',{method:'POST'}).then(r=>r.json());
    currentId=d.chat.id; history=[]; paint();
    document.body.classList.remove('nav');
    await refresh(false);
  }
  newBtn.addEventListener('click',newChat);

  async function save(){
    if(!currentId) return;
    await fetch('/api/chats/'+currentId,{method:'PUT',headers:{'content-type':'application/json'},
      body:JSON.stringify({messages:history,model:pick.value||null})}).catch(()=>{});
    await refresh(false);
  }

  const gate=document.getElementById('gate'), gt=document.getElementById('gt'), gp=document.getElementById('gp');
  const p1=document.getElementById('p1'), p2=document.getElementById('p2'), ge=document.getElementById('ge'), gb=document.getElementById('gb');
  let setupMode=true;

  // Accept the keyboard's number row AND the numpad. e.key normalizes numpad
  // digits (Num Lock on) to the same characters, so one test covers both.
  // Accepts the number row and the numpad alike. Deliberately does NOT block
  // non-digit keydowns: with Num Lock off a numpad key arrives as 'Home'/'End'
  // rather than a digit, and swallowing those makes the field look broken.
  // Validation happens on submit instead, where it can actually explain itself.
  for(const el of [p1,p2]) el.addEventListener('keydown',e=>{
    if(e.key==='Enter'){ e.preventDefault(); gb.click(); }
  });

  function showGate(needsSetup){
    setupMode=needsSetup;
    gt.textContent=needsSetup?'Set a PIN':'Enter your PIN';
    gp.textContent=needsSetup?"Choose a 4-12 digit PIN. You'll need it each time.":'This app is PIN protected.';
    p2.style.display=needsSetup?'':'none';
    gate.classList.add('show'); p1.focus();
  }

  gb.addEventListener('click',async()=>{
    ge.textContent=''; const pin=p1.value.trim();
    if(!/^[0-9]{4,12}$/.test(pin)){ ge.textContent='4-12 digits.'; return; }
    if(setupMode && pin!==p2.value.trim()){ ge.textContent="PINs don't match."; return; }
    gb.disabled=true;
    try{
      const r=await fetch(setupMode?'/api/setup':'/api/unlock',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({pin})});
      const d=await r.json();
      if(!r.ok) throw new Error(d.error||'Failed');
      gate.classList.remove('show'); p1.value=p2.value=''; loadStatus(); loadModels(); refresh(true); loadCfg(); t.focus();
    }catch(err){ ge.textContent=err.message; }
    gb.disabled=false;
  });

  const pick=document.getElementById('pick');
  function loadModels(){
    fetch('/api/models').then(r=>r.json()).then(d=>{
      if(!d.models||!d.models.length){ pick.style.display='none'; return; }
      pick.innerHTML='';
      for(const m of d.models){
        const o=document.createElement('option');
        o.value=m.id;
        o.textContent=(m.loaded?'● ':'○ ')+m.id+(m.quant?'  ('+m.quant+')':'');
        if(m.id===d.current) o.selected=true;
        pick.append(o);
      }
      syncPill();
    }).catch(()=>{pick.style.display='none'});
  }

  // The pill showed the operator's default even after switching models, so the
  // two disagreed. It now reflects whatever is actually about to be used.
  let lmHost='';
  function syncPill(){
    if(!lmHost) return;
    stat.textContent=(pick.value||'linked')+' @ '+lmHost;
  }
  pick.addEventListener('change',syncPill);

  function loadStatus(){
    fetch('/api/status').then(r=>r.json()).then(s=>{
      if(s.configured){ dot.classList.add('on'); lmHost=s.host; stat.textContent=(s.model||'linked')+' @ '+s.host; syncPill(); }
      else { stat.textContent='not linked'; banner('<b>No model endpoint.</b> This app has no settings of its own — the host platform has not supplied one.'); }
    }).catch(()=>{stat.textContent='status unavailable'});
  }

  const gear=document.getElementById('gear');
  const sSys=document.getElementById('sSys'), sTemp=document.getElementById('sTemp');
  const sTop=document.getElementById('sTop'), sMax=document.getElementById('sMax');
  const vTemp=document.getElementById('vTemp'), vTop=document.getElementById('vTop');
  const savedTag=document.getElementById('saved');
  const sWeb=document.getElementById('sWeb'), fWeb=document.getElementById('fWeb'), hWeb=document.getElementById('hWeb');
  gear.addEventListener('click',()=>document.body.classList.toggle('cfg'));

  function showCfg(c){
    sSys.value=c.systemPrompt||''; sTemp.value=c.temperature; sTop.value=c.topP; sMax.value=c.maxTokens||0;
    sWeb.checked=!!c.webSearch;
    vTemp.textContent=Number(c.temperature).toFixed(2); vTop.textContent=Number(c.topP).toFixed(2);
  }
  function loadCfg(){ fetch('/api/settings').then(r=>r.json()).then(d=>{
    showCfg(d.settings);
    if(!d.searchAvailable){
      fWeb.classList.add('off'); sWeb.checked=false; sWeb.disabled=true;
      hWeb.textContent='Unavailable — this deployment has no SEARXNG_URL set, so there is no search backend to reach.';
    }
  }).catch(()=>{}); }

  let cfgTimer=null;
  function saveCfg(){
    vTemp.textContent=Number(sTemp.value).toFixed(2); vTop.textContent=Number(sTop.value).toFixed(2);
    clearTimeout(cfgTimer);
    cfgTimer=setTimeout(async()=>{
      const d=await fetch('/api/settings',{method:'PUT',headers:{'content-type':'application/json'},
        body:JSON.stringify({systemPrompt:sSys.value,temperature:sTemp.value,topP:sTop.value,maxTokens:sMax.value,webSearch:sWeb.checked})
      }).then(r=>r.json()).catch(()=>null);
      if(d&&d.settings){ showCfg(d.settings); savedTag.classList.add('on'); setTimeout(()=>savedTag.classList.remove('on'),1200); }
    },400);
  }
  for(const el of [sSys,sTemp,sTop,sMax,sWeb]) el.addEventListener('input',saveCfg);

  fetch('/api/state').then(r=>r.json()).then(st=>{
    if(st.needsSetup||st.locked) showGate(st.needsSetup); else { loadStatus(); loadModels(); refresh(true); loadCfg(); }
  }).catch(()=>{stat.textContent='status unavailable'});

  function banner(html){ const d=document.createElement('div'); d.className='banner'; d.innerHTML=html; log.append(d); scroll(); }
  function bubble(who,text){ const e=document.getElementById('empty')||log.querySelector('.empty'); if(e) e.remove(); const m=document.createElement('div'); m.className='msg '+who;
    const x=document.createElement('div'); x.className='bub'; x.textContent=text; m.append(x); log.append(m); scroll(); return x; }
  function scroll(){ requestAnimationFrame(()=>document.querySelector('main').scrollTo({top:1e9,behavior:'smooth'})); }

  t.addEventListener('input',()=>{ t.style.height='auto'; t.style.height=Math.min(t.scrollHeight,140)+'px'; });
  t.addEventListener('keydown',e=>{ if(e.key==='Enter'&&!e.shiftKey){ e.preventDefault(); f.requestSubmit(); }});

  f.addEventListener('submit',async e=>{
    e.preventDefault();
    const text=t.value.trim(); if(!text||busy) return;
    busy=true; b.disabled=true; t.value=''; t.style.height='auto';
    bubble('me',text); history.push({role:'user',content:text});
    const wait=document.createElement('div'); wait.className='msg them';
    wait.innerHTML='<div class="typing"><i></i><i></i><i></i></div>'; log.append(wait); scroll();
    if(sWeb.checked&&!sWeb.disabled){ const n=document.createElement('div'); n.className='src'; n.style.margin='0 0 0 4px'; n.textContent='Searching the web…'; wait.append(n); }
    try{
      const r=await fetch('/api/chat',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({messages:history, model:pick.value||undefined})});
      const d=await r.json(); wait.remove();
      if(!r.ok) throw new Error(d.error||('HTTP '+r.status));
      const bub=bubble('them',d.reply); history.push({role:'assistant',content:d.reply});
      if(d.sources){
        const box=document.createElement('div'); box.className='src';
        if(d.sources.error){ box.textContent='Search unavailable: '+d.sources.error; }
        else d.sources.forEach((r,i)=>{ const a=document.createElement('a');
          a.href=r.url; a.target='_blank'; a.rel='noopener noreferrer';
          a.textContent='['+(i+1)+'] '+(r.title||r.url); box.append(a); });
        bub.append(box);
      }
      await save();
    }catch(err){ wait.remove(); banner('<b>Failed.</b> '+err.message); }
    busy=false; b.disabled=false; t.focus();
  });
</script></body></html>`;
