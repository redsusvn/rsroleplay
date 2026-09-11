/* RSROLEPLAY — trình cài đặt Cloudflare
 *
 * Chạy:  node setup/server.mjs
 *
 * Một file, không phụ thuộc gói nào, chỉ dùng node:http. Nó không tự deploy
 * code - việc đó người dùng tự làm bằng `npx wrangler deploy` - mà lo phần
 * phiền phức phía trước: chọn tài khoản, tạo D1, và sinh ra wrangler.toml đã
 * điền sẵn mọi id.
 *
 * VỀ TOKEN, VÀ TẠI SAO KHÔNG PHẢI NÚT "ĐĂNG NHẬP BẰNG CLOUDFLARE"
 * Cloudflare có luồng OAuth, nhưng client id của nó thuộc về Wrangler. Một ứng
 * dụng khác dùng client id đó là đang mạo danh Wrangler, nên ở đây không làm
 * thế. Thay vào đó trang tạo sẵn một đường dẫn tới đúng chỗ tạo API token kèm
 * danh sách quyền cần tick - vẫn là một cú bấm, nhưng token là của họ và họ
 * thấy rõ nó được cấp quyền gì.
 *
 * Token KHÔNG bao giờ chạm đĩa. Trang giữ nó trong biến JavaScript và gửi kèm
 * từng yêu cầu; server này chỉ chuyển tiếp sang API Cloudflare rồi quên đi.
 */
import http from 'node:http';
import { randomBytes } from 'node:crypto';

const PORT = Number(process.env.PORT || 8788);
const CF = 'https://api.cloudflare.com/client/v4';

/* Một server nghe trên localhost vẫn có thể bị trang web khác gọi tới từ trình
   duyệt của chính người dùng. Khoá phiên này chỉ trang do server phát ra mới
   biết, nên một trang lạ không gọi thay được. */
const SESSION_KEY = randomBytes(24).toString('hex');

const json = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
};

const readBody = req => new Promise((resolve, reject) => {
  let n = 0; const parts = [];
  req.on('data', c => {
    n += c.length;
    if (n > 64 * 1024) { reject(new Error('Yêu cầu quá lớn')); req.destroy(); return; }
    parts.push(c);
  });
  req.on('end', () => {
    try { resolve(parts.length ? JSON.parse(Buffer.concat(parts).toString('utf8')) : {}); }
    catch { reject(new Error('JSON không hợp lệ')); }
  });
  req.on('error', reject);
});

/* Gọi API Cloudflare. Lỗi của Cloudflare được đưa nguyên văn ra trang thay vì
   nuốt đi - "token thiếu quyền D1" hữu ích hơn nhiều so với "không thành công". */
async function cf(token, path, init = {}) {
  const r = await fetch(CF + path, {
    ...init,
    headers: {
      Authorization: 'Bearer ' + token,
      'Content-Type': 'application/json',
      ...(init.headers || {}),
    },
  });
  let data = null;
  try { data = await r.json(); } catch { /* Cloudflare trả về gì đó không phải JSON */ }
  if (!data) return { ok: false, status: r.status, errors: [{ message: 'Cloudflare trả lời ' + r.status }] };
  return {
    ok: r.ok && data.success !== false,
    status: r.status,
    result: data.result,
    errors: data.errors || [],
  };
}

const fail = (res, out) => json(res, 200, {
  ok: false,
  status: out.status,
  message: (out.errors || []).map(e => (e.code ? e.code + ': ' : '') + e.message).join(' · ')
           || 'Cloudflare từ chối yêu cầu (' + out.status + ')',
});

const ROUTES = {
  /* Ai đang cầm token này, và nó còn sống không */
  async verify(token) {
    const v = await cf(token, '/user/tokens/verify');
    if (!v.ok) return v;
    return { ok: true, result: { status: v.result?.status || 'active' } };
  },
  /* Danh sách tài khoản. Cần quyền Account Settings:Read; thiếu thì trang cho
     nhập Account ID bằng tay. */
  accounts: token => cf(token, '/accounts?per_page=50'),
  /* Worker đang có, để chọn ghi đè hay đặt tên mới */
  workers: (token, b) =>
    cf(token, '/accounts/' + encodeURIComponent(b.account) + '/workers/scripts'),
  d1list: (token, b) =>
    cf(token, '/accounts/' + encodeURIComponent(b.account) + '/d1/database?per_page=50'),
  d1create: (token, b) =>
    cf(token, '/accounts/' + encodeURIComponent(b.account) + '/d1/database', {
      method: 'POST',
      body: JSON.stringify({ name: String(b.name || '').slice(0, 60) }),
    }),
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');

  if (url.pathname === '/' && req.method === 'GET') {
    const html = page(SESSION_KEY);
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy':
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    res.end(html);
    return;
  }

  if (url.pathname.startsWith('/api/') && req.method === 'POST') {
    if (req.headers['x-setup-key'] !== SESSION_KEY) {
      return json(res, 403, { ok: false, message: 'Sai khoá phiên. Tải lại trang.' });
    }
    const name = url.pathname.slice(5);
    const fn = ROUTES[name];
    if (!fn) return json(res, 404, { ok: false, message: 'Không có endpoint này' });

    let body;
    try { body = await readBody(req); }
    catch (e) { return json(res, 400, { ok: false, message: e.message }); }

    const token = String(req.headers['x-cf-token'] || '').trim();
    if (!token) return json(res, 400, { ok: false, message: 'Chưa có token' });

    try {
      const out = await fn(token, body);
      if (!out.ok) return fail(res, out);
      return json(res, 200, { ok: true, result: out.result });
    } catch (e) {
      return json(res, 200, { ok: false, message: 'Không gọi được Cloudflare: ' + e.message });
    }
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not found');
});

server.listen(PORT, '127.0.0.1', () => {
  console.log('');
  console.log('  Trình cài đặt RSROLEPLAY');
  console.log('  → http://127.0.0.1:' + PORT + '/');
  console.log('');
  console.log('  Chỉ nghe trên 127.0.0.1. Token không được ghi ra đĩa.');
  console.log('  Ctrl+C để dừng.');
  console.log('');
});

function page(key) {
  return `<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cài đặt RSROLEPLAY</title>
<style>
:root{
  --bg:#0d1017; --panel:#141924; --panel2:#1b2130; --line:#252d3d;
  --text:#e8ecf4; --dim:#93a0b8; --accent:#5b8cff; --ok:#3ecf8e; --warn:#ffb23f; --bad:#ff6b6b;
  color-scheme:dark;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.65 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif}
.wrap{max-width:760px;margin:0 auto;padding:40px 20px 80px}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:15px;margin:0 0 10px;letter-spacing:.02em}
.sub{color:var(--dim);margin:0 0 28px}
.step{background:var(--panel);border:1px solid var(--line);border-radius:14px;
  padding:20px 22px;margin-bottom:14px}
.step[data-done="1"]{border-color:rgba(62,207,142,.45)}
.num{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;
  border-radius:50%;background:var(--panel2);color:var(--dim);font-size:12px;font-weight:700;
  margin-right:9px;flex:none}
.step[data-done="1"] .num{background:rgba(62,207,142,.16);color:var(--ok)}
.head{display:flex;align-items:center;margin-bottom:12px}
p{margin:0 0 12px}
.dim{color:var(--dim)}
.small{font-size:13px}
label{display:block;font-size:13px;color:var(--dim);margin:14px 0 6px}
input,select,textarea{width:100%;background:#0b0e15;color:var(--text);
  border:1px solid var(--line);border-radius:9px;padding:10px 12px;font:inherit;outline:none}
input:focus,select:focus,textarea:focus{border-color:var(--accent)}
textarea{font:13px/1.6 ui-monospace,'SFMono-Regular',Consolas,monospace;resize:vertical}
button{background:var(--accent);color:#08111f;border:0;border-radius:9px;
  padding:10px 16px;font:inherit;font-weight:650;cursor:pointer}
button:disabled{opacity:.45;cursor:default}
button.ghost{background:transparent;color:var(--text);border:1px solid var(--line);font-weight:500}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
.msg{margin-top:12px;padding:10px 12px;border-radius:9px;font-size:13.5px;display:none}
.msg.show{display:block}
.msg.ok{background:rgba(62,207,142,.12);color:var(--ok)}
.msg.bad{background:rgba(255,107,107,.12);color:var(--bad)}
.msg.warn{background:rgba(255,178,63,.12);color:var(--warn)}
ul{margin:0 0 12px;padding-left:20px}
li{margin-bottom:5px}
code{background:var(--panel2);padding:2px 6px;border-radius:5px;
  font:13px ui-monospace,Consolas,monospace}
.perm{background:var(--panel2);border-radius:9px;padding:12px 14px;margin:10px 0}
.perm b{color:var(--accent);font-weight:650}
.copy{position:relative}
.copy button{position:absolute;top:8px;right:8px;padding:5px 11px;font-size:12px}
a{color:var(--accent)}
.hide{display:none}
.pill{display:inline-block;background:var(--panel2);border-radius:20px;
  padding:3px 11px;font-size:12px;color:var(--dim);margin-left:8px}
</style></head><body><div class="wrap">

<h1>Cài đặt RSROLEPLAY lên Cloudflare</h1>
<p class="sub">Trang này lo phần chuẩn bị: chọn tài khoản, tạo cơ sở dữ liệu, và
sinh file cấu hình đã điền sẵn mọi id. <b>Việc đẩy code lên vẫn do bạn tự chạy</b>
— hướng dẫn ở bước cuối.</p>

<!-- 1 -->
<div class="step" id="s1">
  <div class="head"><span class="num">1</span><h2>Lấy API token của Cloudflare</h2></div>
  <p>Bấm nút dưới để mở trang tạo token trên Cloudflare (mở tab mới, bạn sẽ đăng
  nhập ở đó). Chọn <b>Create Custom Token</b>, rồi cấp đúng ba quyền sau:</p>
  <div class="perm">
    <p style="margin:0 0 6px"><b>Account</b> · Workers Scripts · <b>Edit</b></p>
    <p style="margin:0 0 6px"><b>Account</b> · D1 · <b>Edit</b></p>
    <p style="margin:0"><b>Account</b> · Account Settings · <b>Read</b></p>
  </div>
  <p class="small dim">Quyền thứ ba chỉ để liệt kê tài khoản cho bạn chọn. Nếu
  không muốn cấp, bỏ qua cũng được — bước 2 có ô nhập Account ID bằng tay.</p>
  <div class="row">
    <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener">
      <button>Mở trang tạo token ↗</button></a>
  </div>
  <label for="tok">Dán token vào đây</label>
  <input id="tok" type="password" placeholder="ví dụ: A1b2C3d4..." autocomplete="off" spellcheck="false">
  <div class="row"><button id="btn-verify">Kiểm tra token</button></div>
  <div class="msg" id="m1"></div>
  <p class="small dim" style="margin-top:12px">Token nằm trong bộ nhớ trình duyệt
  và bộ nhớ tiến trình Node đang chạy trên máy bạn. Nó không được ghi ra đĩa,
  không ghi log, và server này chỉ nghe trên 127.0.0.1.</p>
</div>

<!-- 2 -->
<div class="step hide" id="s2">
  <div class="head"><span class="num">2</span><h2>Chọn tài khoản</h2></div>
  <label for="acc">Tài khoản Cloudflare</label>
  <select id="acc"><option>Đang tải…</option></select>
  <label for="accman">…hoặc dán Account ID bằng tay</label>
  <input id="accman" placeholder="32 ký tự, lấy ở thanh bên phải trang Cloudflare"
         autocomplete="off" spellcheck="false">
  <div class="row"><button id="btn-acc">Dùng tài khoản này</button></div>
  <div class="msg" id="m2"></div>
</div>

<!-- 3 -->
<div class="step hide" id="s3">
  <div class="head"><span class="num">3</span><h2>Đặt tên Worker</h2></div>
  <p class="small dim">Chọn một Worker đã có để ghi đè, hoặc gõ tên mới — Wrangler
  sẽ tự tạo khi bạn deploy.</p>
  <label for="wk">Worker đang có</label>
  <select id="wk"><option value="">— tạo mới —</option></select>
  <label for="wkname">Tên Worker sẽ dùng</label>
  <input id="wkname" value="roleplay" autocomplete="off" spellcheck="false">
  <div class="row"><button id="btn-wk">Tiếp tục</button></div>
  <div class="msg" id="m3"></div>
</div>

<!-- 4 -->
<div class="step hide" id="s4">
  <div class="head"><span class="num">4</span><h2>Cơ sở dữ liệu D1</h2></div>
  <p class="small dim">Toàn bộ hội thoại, persona và API key nằm ở đây. Chọn cái
  đã có, hoặc tạo mới ngay tại đây.</p>
  <label for="db">D1 đang có</label>
  <select id="db"><option value="">— tạo mới —</option></select>
  <label for="dbname">Tên cơ sở dữ liệu mới</label>
  <input id="dbname" value="roleplay-db" autocomplete="off" spellcheck="false">
  <div class="row">
    <button id="btn-dbnew">Tạo mới</button>
    <button id="btn-dbuse" class="ghost">Dùng cái đã chọn</button>
  </div>
  <div class="msg" id="m4"></div>
</div>

<!-- 5 -->
<div class="step hide" id="s5">
  <div class="head"><span class="num">5</span><h2>Chép file cấu hình</h2></div>
  <p>Tạo file tên <code>wrangler.toml</code> đặt cạnh <code>worker.js</code>, rồi
  dán toàn bộ nội dung dưới đây vào. Mọi id đã được điền sẵn.</p>
  <div class="copy">
    <textarea id="toml" rows="26" spellcheck="false" readonly></textarea>
    <button class="ghost" id="btn-copy1">Chép</button>
  </div>
  <div class="msg" id="m5"></div>
</div>

<!-- 6 -->
<div class="step hide" id="s6">
  <div class="head"><span class="num">6</span><h2>Đẩy code lên — bạn tự chạy</h2></div>
  <p>Mở terminal ở thư mục chứa <code>worker.js</code> và <code>wrangler.toml</code>,
  chạy lần lượt:</p>
  <div class="copy">
    <textarea id="cmds" rows="7" spellcheck="false" readonly></textarea>
    <button class="ghost" id="btn-copy2">Chép</button>
  </div>
  <p class="small dim">Lệnh đầu đăng nhập Wrangler bằng trình duyệt — đây là luồng
  OAuth chính thức của Cloudflare, tách biệt với token ở bước 1. Token bước 1 chỉ
  dùng cho trang này; nếu muốn bạn có thể xoá nó trên Cloudflare sau khi deploy xong.</p>

  <h2 style="margin-top:26px">Sau khi deploy</h2>
  <ul class="small">
    <li>Mở địa chỉ Wrangler in ra, dạng <code>https://&lt;tên-worker&gt;.&lt;tài-khoản&gt;.workers.dev</code></li>
    <li>Lần đầu vào sẽ có màn hình tạo tài khoản quản trị. Bảng trong D1 được tạo tự động.</li>
    <li>Vào <b>API Endpoints</b> thêm khoá của nhà cung cấp AI thì mới chat được.</li>
  </ul>

  <h2 style="margin-top:26px">Nếu gặp lỗi</h2>
  <ul class="small">
    <li><b>“Worker exceeded CPU time limit”</b> — thiếu phần Durable Object trong
    cấu hình. Kiểm tra khối <code>[[durable_objects.bindings]]</code> và
    <code>[[migrations]]</code> còn nguyên trong <code>wrangler.toml</code> không.</li>
    <li><b>“binding DB … not found”</b> — sai <code>database_id</code>. Quay lại bước 4.</li>
    <li><b>“workers.api.error.script_too_large”</b> — bản miễn phí giới hạn 1 MB sau
    nén; <code>worker.js</code> khoảng 1 MB thô nhưng nén xuống thấp hơn nhiều nên
    thường không sao.</li>
  </ul>
</div>

<script>
const KEY = ${JSON.stringify(key)};
let TOKEN = '';
const S = { account:'', worker:'roleplay', dbName:'', dbId:'' };
const $ = id => document.getElementById(id);

function say(el, text, kind){
  const m = $(el);
  m.textContent = text;
  m.className = 'msg show ' + (kind || '');
}
function done(step){ $(step).dataset.done = '1'; }
function show(step){ $(step).classList.remove('hide'); $(step).scrollIntoView({behavior:'smooth',block:'center'}); }

async function api(name, body){
  const r = await fetch('/api/' + name, {
    method:'POST',
    headers:{ 'Content-Type':'application/json', 'X-Setup-Key':KEY, 'X-CF-Token':TOKEN },
    body: JSON.stringify(body || {})
  });
  return r.json();
}

/* 1 — token */
$('btn-verify').onclick = async () => {
  TOKEN = $('tok').value.trim();
  if(!TOKEN){ say('m1','Chưa dán token.','bad'); return; }
  say('m1','Đang kiểm tra…');
  const v = await api('verify');
  if(!v.ok){ say('m1', v.message || 'Token không dùng được.', 'bad'); return; }
  say('m1','Token hợp lệ.','ok'); done('s1'); show('s2');

  const a = await api('accounts');
  const sel = $('acc');
  if(!a.ok || !Array.isArray(a.result) || !a.result.length){
    sel.innerHTML = '<option value="">(không liệt kê được — nhập tay bên dưới)</option>';
    say('m2', (a.message || 'Token không có quyền Account Settings:Read.') +
        ' Bạn vẫn tiếp tục được bằng cách dán Account ID.', 'warn');
    return;
  }
  sel.innerHTML = a.result.map(x =>
    '<option value="' + x.id + '">' + esc(x.name) + '</option>').join('');
};

const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

/* 2 — tài khoản */
$('btn-acc').onclick = async () => {
  S.account = ($('accman').value.trim() || $('acc').value || '').trim();
  if(!/^[0-9a-f]{32}$/i.test(S.account)){
    say('m2','Account ID phải là 32 ký tự hex. Lấy ở thanh bên phải trang tổng quan Cloudflare.','bad');
    return;
  }
  say('m2','Đã chọn.','ok'); done('s2'); show('s3');

  const w = await api('workers', {account:S.account});
  const sel = $('wk');
  if(w.ok && Array.isArray(w.result) && w.result.length){
    sel.innerHTML = '<option value="">— tạo mới —</option>' + w.result.map(x =>
      '<option value="' + esc(x.id) + '">' + esc(x.id) + '</option>').join('');
  } else {
    sel.innerHTML = '<option value="">— tạo mới —</option>';
    if(!w.ok) say('m3', w.message || 'Không liệt kê được Worker.', 'warn');
  }
  const d = await api('d1list', {account:S.account});
  const dsel = $('db');
  const list = (d.ok && d.result) ? d.result : [];
  dsel.innerHTML = '<option value="">— tạo mới —</option>' + list.map(x =>
    '<option value="' + esc(x.uuid || x.id) + '">' + esc(x.name) + '</option>').join('');
  if(!d.ok) say('m4', d.message || 'Không liệt kê được D1.', 'warn');
};

$('wk').onchange = () => { if($('wk').value) $('wkname').value = $('wk').value; };

/* 3 — worker */
$('btn-wk').onclick = () => {
  const n = $('wkname').value.trim();
  if(!/^[a-z0-9][a-z0-9-]{0,62}$/.test(n)){
    say('m3','Tên chỉ gồm chữ thường, số và dấu gạch ngang.','bad'); return;
  }
  S.worker = n;
  say('m3','Đã đặt tên: ' + n, 'ok'); done('s3'); show('s4');
};

/* 4 — D1 */
$('btn-dbuse').onclick = () => {
  const sel = $('db');
  if(!sel.value){ say('m4','Chưa chọn cái nào. Bấm “Tạo mới” nếu chưa có.','bad'); return; }
  S.dbId = sel.value;
  S.dbName = sel.options[sel.selectedIndex].textContent;
  finish();
};
$('btn-dbnew').onclick = async () => {
  const n = $('dbname').value.trim();
  if(!n){ say('m4','Chưa đặt tên.','bad'); return; }
  say('m4','Đang tạo…');
  const r = await api('d1create', {account:S.account, name:n});
  if(!r.ok){ say('m4', r.message || 'Không tạo được.', 'bad'); return; }
  S.dbId = r.result?.uuid || r.result?.id || '';
  S.dbName = r.result?.name || n;
  if(!S.dbId){ say('m4','Cloudflare không trả về id. Kiểm tra lại trên dashboard.','bad'); return; }
  finish();
};

function finish(){
  say('m4','Xong: ' + S.dbName + ' · ' + S.dbId, 'ok');
  done('s4');
  $('toml').value = toml();
  $('cmds').value = cmds();
  show('s5'); $('s6').classList.remove('hide');
}

function toml(){
  return [
'name = "' + S.worker + '"',
'main = "worker.js"',
'compatibility_date = "2026-09-01"',
'',
'# Chạy Worker gần D1 và nhà cung cấp AI thay vì gần điện thoại: mỗi tin nhắn là',
'# vài lượt đi-về tới cả hai.',
'[placement]',
'mode = "smart"',
'',
'[[d1_databases]]',
'binding = "DB"                 # worker.js đọc env.DB',
'database_name = "' + S.dbName + '"',
'database_id = "' + S.dbId + '"',
'',
'# Phần quan trọng nhất. Worker chỉ có 10ms CPU mỗi request, một câu trả lời dài',
'# vượt qua đó và bị giết ("Worker exceeded CPU time limit"). Durable Object nền',
'# SQLite được 30 giây, nên việc sinh chữ chạy trong đó còn Worker chỉ bơm byte.',
'# Thiếu khối này app vẫn chạy, nhưng câu dài có thể bị cắt ngang.',
'[[durable_objects.bindings]]',
'name = "STREAMER"              # worker.js đọc env.STREAMER',
'class_name = "ChatStreamer"    # export class ChatStreamer trong worker.js',
'',
'[[migrations]]',
'tag = "v1"',
'new_sqlite_classes = ["ChatStreamer"]   # nền SQLite = loại bản miễn phí cho phép',
'',
'# Dọn dẹp hằng ngày: phiên đăng nhập hết hạn, cờ sinh chữ đã xong, chặn IP cũ.',
'[triggers]',
'crons = ["0 4 * * *"]',
'',
'[observability]',
'enabled = true',
''].join('\\n');
}

function cmds(){
  return [
'npx wrangler login',
'npx wrangler deploy',
'',
'# Xem log trực tiếp nếu cần dò lỗi:',
'# npx wrangler tail',
''].join('\\n');
}

function copyFrom(id, btn){
  const t = $(id);
  t.select(); t.setSelectionRange(0, 99999);
  navigator.clipboard.writeText(t.value).then(() => {
    const old = btn.textContent; btn.textContent = 'Đã chép';
    setTimeout(() => btn.textContent = old, 1400);
  });
}
$('btn-copy1').onclick = e => copyFrom('toml', e.currentTarget);
$('btn-copy2').onclick = e => copyFrom('cmds', e.currentTarget);
</script>
</div></body></html>`;
}
