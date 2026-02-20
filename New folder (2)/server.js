/**
 * ULTIMATE CTF SERVER v6.0
 * npm install express sqlite3 ws cors helmet compression
 * node server.js
 * Site:  http://localhost:3000
 * Admin: http://localhost:3000/admin  password: danik2026
 */

'use strict';

const express   = require('express');
const sqlite3   = require('sqlite3').verbose();
const http      = require('http');
const WebSocket = require('ws');
const os        = require('os');

const app        = express();
const server     = http.createServer(app);
const wss        = new WebSocket.Server({ server });
const PORT       = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'danik2026';

app.use(require('cors')());
app.use(require('helmet')({ contentSecurityPolicy: false }));
app.use(require('compression')());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set('trust proxy', true);

// ── Database ──────────────────────────────────────────────────────────────────
const db = new sqlite3.Database('ctf.db', err => {
    if (err) { console.error('DB error:', err); process.exit(1); }
    console.log('DB ready');
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
        id    INTEGER PRIMARY KEY AUTOINCREMENT,
        name  TEXT, score INTEGER, rank TEXT, crack TEXT,
        ip TEXT, geo TEXT, risk TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS banned_ips (
        ip TEXT PRIMARY KEY, reason TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS req_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT, method TEXT, path TEXT, ua TEXT,
        ts DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

const dbRun = (s,p=[]) => new Promise((res,rej)=>db.run(s,p,function(e){e?rej(e):res(this);}));
const dbAll = (s,p=[]) => new Promise((res,rej)=>db.all(s,p,(e,r)=>e?rej(e):res(r)));
const dbGet = (s,p=[]) => new Promise((res,rej)=>db.get(s,p,(e,r)=>e?rej(e):res(r)));

function getIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim()
        || req.headers['x-real-ip']
        || req.socket?.remoteAddress || '0.0.0.0';
}

function classifyIP(ip) {
    const rules = [
        {p:'185.220.',label:'TOR',risk:'CRITICAL'},{p:'199.249.',label:'TOR',risk:'CRITICAL'},
        {p:'104.244.',label:'VPN',risk:'HIGH'},{p:'13.',label:'AWS',risk:'MEDIUM'},
        {p:'18.',label:'AWS',risk:'MEDIUM'},{p:'52.',label:'AWS',risk:'MEDIUM'},
        {p:'34.',label:'GCP',risk:'MEDIUM'},{p:'35.',label:'GCP',risk:'MEDIUM'},
        {p:'138.197.',label:'DO',risk:'MEDIUM'},{p:'127.',label:'Local',risk:'CLEAN'},
        {p:'10.',label:'LAN',risk:'CLEAN'},{p:'192.168.',label:'LAN',risk:'CLEAN'},
        {p:'::1',label:'Local',risk:'CLEAN'},
    ];
    for (const r of rules) if (ip.startsWith(r.p)) return {label:r.label,risk:r.risk};
    return {label:'Unknown',risk:'LOW'};
}

const rateMap = new Map();
function limited(ip) {
    const now = Date.now();
    const h = (rateMap.get(ip)||[]).filter(t=>now-t<60000);
    h.push(now); rateMap.set(ip,h);
    return h.length > 120;
}

const HONEYPOTS = new Set(['/wp-admin','/phpmyadmin','/.env','/admin.php','/config.php','/.git/config']);

function broadcast(d) {
    const m = JSON.stringify(d);
    wss.clients.forEach(c=>{if(c.readyState===WebSocket.OPEN)c.send(m);});
}

// ── Global middleware ─────────────────────────────────────────────────────────
app.use(async (req,res,next)=>{
    const ip  = getIP(req);
    const geo = classifyIP(ip);
    req._ip  = ip;
    req._geo = geo;
    db.run('INSERT INTO req_log(ip,method,path,ua)VALUES(?,?,?,?)',
        [ip,req.method,req.path,(req.headers['user-agent']||'').slice(0,200)]);
    try {
        const b = await dbGet('SELECT ip FROM banned_ips WHERE ip=?',[ip]);
        if (b) return res.status(403).send(`<html><body style="background:#000;color:#f44;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;text-align:center"><div><h1>🚫 BANNED</h1><p>${ip}</p></div></body></html>`);
    } catch(e){}
    if (limited(ip)) return res.status(429).json({ok:false,error:'Rate limited'});
    if (HONEYPOTS.has(req.path)) { broadcast({type:'alert',msg:'Honeypot: '+req.path,ip,ts:new Date().toISOString()}); return res.status(403).json({ok:false,error:'Forbidden'}); }
    next();
});

// ── Password scoring ──────────────────────────────────────────────────────────
const COMMON = new Set(['password','123456','12345678','qwerty','abc123','monkey','letmein',
    'trustno1','dragon','baseball','iloveyou','master','sunshine','passw0rd','shadow',
    '123123','654321','superman','qazwsx','football','password1','password123','admin',
    'welcome','login','hello','111111','000000','root','admin123','qwerty123','princess']);

function score(pw) {
    if (!pw||!pw.length) return {score:0,rank:'💀 EMPTY',color:'#444',crack:'Instant',flags:[],details:{}};
    let s=0; const flags=[],det={};
    const l=pw.length;
    s+=l>=25?180:l>=20?140:l>=16?100:l>=12?70:l>=8?40:l>=6?20:l*3;
    det.length=l;
    const lo=/[a-z]/.test(pw),up=/[A-Z]/.test(pw),di=/\d/.test(pw),
          sy=/[!@#$%^&*()\-_=+\[\]{};':"\\|,.<>/?`~]/.test(pw),un=/[^\x00-\x7F]/.test(pw);
    if(lo)s+=10; if(up)s+=20; if(di)s+=20; if(sy)s+=40; if(un)s+=30;
    const t=[lo,up,di,sy,un].filter(Boolean).length;
    s+=t*15; det.charTypes=t;
    if(COMMON.has(pw.toLowerCase())){s-=350;flags.push('COMMON_PASSWORD');}
    let n=pw.toLowerCase();
    for(const[k,v]of Object.entries({'0':'o','1':'i','3':'e','4':'a','5':'s','@':'a','$':'s','7':'t'}))n=n.split(k).join(v);
    if(n!==pw.toLowerCase()&&COMMON.has(n)){s-=200;flags.push('LEET_COMMON');}
    for(const{re,pts,f}of[
        {re:/password/i,pts:-180,f:'CONTAINS_PASSWORD'},
        {re:/^(admin|root)$/i,pts:-200,f:'IS_ADMIN_ROOT'},
        {re:/^[0-9]+$/,pts:-80,f:'DIGITS_ONLY'},
        {re:/^[a-zA-Z]+$/,pts:-50,f:'LETTERS_ONLY'},
        {re:/(.)\1{3,}/,pts:-100,f:'REPEATED_CHARS'},
        {re:/12345/,pts:-60,f:'SEQ_DIGITS'},
        {re:/qwerty/i,pts:-80,f:'KEYBOARD_WALK'},
        {re:/iloveyou/i,pts:-100,f:'ILOVEYOU'},
    ]){if(re.test(pw)){s+=pts;flags.push(f);}}
    let wk=0,pl=pw.toLowerCase();
    for(const row of['qwertyuiop','asdfghjkl','zxcvbnm','1234567890'])
        for(let i=0;i<pl.length-3;i++)if(row.includes(pl.slice(i,i+4)))wk+=20;
    if(wk>0){s-=wk;flags.push('KEYBOARD_PATTERN');}
    const uq=new Set(pw).size,en=pw.length*Math.log2(Math.max(uq,2));
    s+=Math.floor(en*1.5); det.entropy=Math.round(en*10)/10;
    const ws=pw.split(/[\s_\-]+/).filter(w=>w.length>1);
    if(ws.length>=4){s+=ws.length*25;flags.push('PASSPHRASE');det.words=ws.length;}
    s=Math.max(0,Math.min(1000,s));
    let rank='🪦 DEAD',color='#555';
    if(s>=850){rank='🦄 GODMODE';color='#ff00ff';}
    else if(s>=700){rank='🔥 ELITE';color='#ff4444';}
    else if(s>=550){rank='💎 DIAMOND';color='#00cfff';}
    else if(s>=400){rank='👑 PLATINUM';color='#e5e4e2';}
    else if(s>=250){rank='⭐ GOLD';color='#ffd700';}
    else if(s>=120){rank='⚪ SILVER';color='#c0c0c0';}
    else if(s>=50){rank='🕐 BRONZE';color='#cd7f32';}
    let pool=0;
    if(lo)pool+=26;if(up)pool+=26;if(di)pool+=10;if(sy)pool+=32;
    pool=Math.max(pool,2);
    const sec=Math.pow(pool,pw.length)/1e10;
    const crack=sec<1?'Instant':sec<60?Math.round(sec)+'s':sec<3600?Math.round(sec/60)+'m'
        :sec<86400?Math.round(sec/3600)+'h':sec<2592000?Math.round(sec/86400)+'d'
        :sec<3.15e7?Math.round(sec/2592000)+'mo':sec<3.15e9?Math.round(sec/3.15e7)+'yr':'1000+ yrs';
    return {score:s,rank,color,crack,flags,details:det};
}

function adminOnly(req,res,next){
    if((req.headers['x-admin-token']||req.query.token)!==ADMIN_PASS)
        return res.status(401).json({ok:false,error:'Unauthorized'});
    next();
}

// =============================================================================
// ROUTES
// =============================================================================

app.get('/', (req,res) => {
    res.setHeader('Content-Type','text/html;charset=utf-8');
    res.send(MAIN_PAGE);
});

app.get('/admin', (req,res) => {
    res.setHeader('Content-Type','text/html;charset=utf-8');
    res.send(ADMIN_PAGE);
});

app.post('/submit', async (req,res) => {
    try {
        const {name,password} = req.body;
        if (!name||!String(name).trim()) return res.json({ok:false,error:'Name required'});
        if (!password||!String(password).length) return res.json({ok:false,error:'Password required'});
        const n = String(name).trim().replace(/[^\w\s\-]/g,'').slice(0,30)||'Anonymous';
        const r = score(String(password));
        await dbRun('INSERT INTO submissions(name,score,rank,crack,ip,geo,risk)VALUES(?,?,?,?,?,?,?)',
            [n,r.score,r.rank,r.crack,req._ip,req._geo.label,req._geo.risk]);
        broadcast({type:'submission',name:n,score:r.score,rank:r.rank,
                   ip:req._ip,geo:req._geo.label,risk:req._geo.risk,ts:new Date().toISOString()});
        res.json({ok:true,...r});
    } catch(e) { res.json({ok:false,error:e.message}); }
});

app.get('/api/leaderboard', async (req,res) => {
    try {
        const rows = await dbAll('SELECT name,score,rank,crack,geo,risk,ts FROM submissions ORDER BY score DESC LIMIT 100');
        res.json({ok:true,rows});
    } catch(e) { res.json({ok:false,rows:[]}); }
});

app.get('/api/admin/data', adminOnly, async (req,res) => {
    try {
        const [subs,banned,logs,stats] = await Promise.all([
            dbAll('SELECT * FROM submissions ORDER BY id DESC LIMIT 200'),
            dbAll('SELECT * FROM banned_ips ORDER BY ts DESC'),
            dbAll('SELECT * FROM req_log ORDER BY id DESC LIMIT 300'),
            dbGet('SELECT COUNT(*) as total,ROUND(AVG(score)) as avg,MAX(score) as top FROM submissions'),
        ]);
        res.json({ok:true,subs,banned,logs,stats});
    } catch(e) { res.json({ok:false,error:e.message}); }
});

app.post('/api/admin/ban', adminOnly, async (req,res) => {
    try {
        const {ip,reason} = req.body;
        if (!ip) return res.json({ok:false,error:'IP required'});
        await dbRun('INSERT OR REPLACE INTO banned_ips(ip,reason)VALUES(?,?)',[ip,reason||'Banned by admin']);
        broadcast({type:'ban',ip,reason:reason||'Banned by admin',ts:new Date().toISOString()});
        console.log('Banned:',ip);
        res.json({ok:true});
    } catch(e) { res.json({ok:false,error:e.message}); }
});

app.post('/api/admin/unban', adminOnly, async (req,res) => {
    try {
        const {ip} = req.body;
        if (!ip) return res.json({ok:false,error:'IP required'});
        await dbRun('DELETE FROM banned_ips WHERE ip=?',[ip]);
        res.json({ok:true});
    } catch(e) { res.json({ok:false,error:e.message}); }
});

app.post('/api/admin/delete', adminOnly, async (req,res) => {
    try {
        await dbRun('DELETE FROM submissions WHERE id=?',[req.body.id]);
        res.json({ok:true});
    } catch(e) { res.json({ok:false,error:e.message}); }
});

app.get('/flag1',(req,res)=>{ broadcast({type:'alert',msg:'Flag 1 found!',ip:req._ip,ts:new Date().toISOString()}); res.json({flag:'FLAG{hidden_endpoint_1}'}); });
app.get('/flag2',(req,res)=>{ broadcast({type:'alert',msg:'Flag 2 found!',ip:req._ip,ts:new Date().toISOString()}); res.json({flag:'FLAG{multi_endpoint_hunter}'}); });

// 404 — always last
app.use((req,res) => res.status(404).json({error:'Not found'}));

wss.on('connection', ws => ws.send(JSON.stringify({type:'welcome'})));

// =============================================================================
// HTML — after all routes so JS in HTML can't conflict with route definitions
// =============================================================================

const MAIN_PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ULTIMATE CTF v6</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
:root{--g:#00ff41;--r:#ff4444;--gold:#ffd700}
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:var(--g);font-family:'Share Tech Mono',monospace;min-height:100vh;overflow-x:hidden}
canvas{position:fixed;top:0;left:0;z-index:0;pointer-events:none}
.pg{position:relative;z-index:1;max-width:860px;margin:0 auto;padding:20px}
h1{font-family:'Orbitron',sans-serif;font-size:clamp(1.4em,5vw,2.7em);text-shadow:0 0 30px var(--g);animation:fl 4s infinite}
@keyframes fl{0%,100%{opacity:1}93%{opacity:.55}95%{opacity:1}98%{opacity:.65}99%{opacity:1}}
.card{background:rgba(0,255,65,.04);border:1px solid rgba(0,255,65,.17);border-radius:12px;padding:22px;margin:13px 0}
input[type=text],input[type=password]{width:100%;padding:13px 15px;margin:6px 0;background:rgba(0,0,0,.95);border:1.5px solid rgba(0,255,65,.28);border-radius:9px;color:var(--g);font-family:inherit;font-size:15px;outline:none;transition:.25s}
input[type=text]:focus,input[type=password]:focus{border-color:var(--g);box-shadow:0 0 12px rgba(0,255,65,.22)}
.btn{width:100%;padding:14px;margin-top:9px;background:var(--g);border:none;border-radius:9px;color:#000;font-family:'Orbitron',sans-serif;font-size:13px;font-weight:900;letter-spacing:2px;cursor:pointer;transition:.2s}
.btn:hover{background:#00cc33;transform:translateY(-2px);box-shadow:0 5px 18px rgba(0,255,65,.3)}
.btn:disabled{opacity:.4;cursor:not-allowed;transform:none}
#res{min-height:76px;padding:18px;border:2px solid rgba(0,255,65,.1);border-radius:11px;text-align:center;font-size:16px;transition:.3s;color:#222}
.bw{height:9px;background:#0a0a0a;border-radius:5px;margin:11px 0;overflow:hidden}
.bf{height:100%;width:0;background:linear-gradient(90deg,#f44,var(--gold),var(--g));border-radius:5px;transition:width 1s ease}
table{width:100%;border-collapse:collapse;font-size:13px}
th{padding:8px 7px;text-align:left;border-bottom:1px solid rgba(0,255,65,.18);font-size:10px;text-transform:uppercase;letter-spacing:1px;opacity:.5}
td{padding:8px 7px;border-bottom:1px solid rgba(0,255,65,.06)}
tr:hover td{background:rgba(0,255,65,.03)}
.ck{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold}
.CLEAN,.LOW{color:var(--g);border:1px solid var(--g)}
.MEDIUM{color:#fa0;border:1px solid #fa0}
.HIGH{color:#f60;border:1px solid #f60}
.CRITICAL{color:var(--r);border:1px solid var(--r)}
.fc{display:inline-block;margin:2px;padding:2px 7px;background:rgba(255,68,68,.1);color:#f99;border:1px solid rgba(255,68,68,.22);border-radius:4px;font-size:11px}
.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--g);margin-right:5px;animation:bk 1s infinite}
@keyframes bk{0%,100%{opacity:1}50%{opacity:.1}}
.sc{max-height:330px;overflow-y:auto}
</style>
</head>
<body>
<canvas id="c"></canvas>
<div class="pg">
  <div style="text-align:center;padding:34px 0 16px">
    <h1>⚡ ULTIMATE CTF v6.0</h1>
    <p style="opacity:.3;font-size:12px;margin-top:7px">Threat Intel · Password Scoring · Live Leaderboard</p>
  </div>

  <div class="card">
    <input id="nm" type="text"     placeholder="👤 Hacker Alias" maxlength="30" autocomplete="off">
    <input id="pw" type="password" placeholder="🔑 Password to Analyze" autocomplete="new-password">
    <button class="btn" id="sb">🚀 ANALYZE PASSWORD</button>
  </div>

  <div class="card">
    <div id="res">Submit a password above to see your score...</div>
    <div class="bw"><div class="bf" id="bf"></div></div>
    <div id="fl" style="margin-top:5px;font-size:12px"></div>
  </div>

  <div class="card">
    <h3 style="margin-bottom:13px;font-size:12px;text-transform:uppercase;letter-spacing:1px">
      <span class="dot"></span>Live Leaderboard
    </h3>
    <div class="sc">
      <table>
        <thead><tr><th>#</th><th>Name</th><th>Score</th><th>Rank</th><th>Crack</th><th>Geo</th><th>Risk</th></tr></thead>
        <tbody id="lb"><tr><td colspan="7" style="text-align:center;opacity:.3;padding:16px">Loading...</td></tr></tbody>
      </table>
    </div>
  </div>

  <p style="text-align:center;opacity:.15;font-size:11px;padding:12px 0">
    <a href="/admin" style="color:var(--g);text-decoration:none">Admin</a>
  </p>
</div>

<script>
(function(){
  // Matrix
  var cv=document.getElementById('c'),cx=cv.getContext('2d');
  function rs(){cv.width=innerWidth;cv.height=innerHeight;}rs();window.onresize=rs;
  var CH='01アイウカキクケコサシスタチ',dr=[];
  function id(){dr=Array(Math.floor(innerWidth/13)).fill(1);}id();window.addEventListener('resize',id);
  setInterval(function(){
    cx.fillStyle='rgba(0,0,0,.05)';cx.fillRect(0,0,cv.width,cv.height);
    cx.fillStyle='#00ff41';cx.font='13px monospace';
    dr.forEach(function(y,i){
      cx.fillText(CH[Math.floor(Math.random()*CH.length)],i*13,y*13);
      if(y*13>cv.height&&Math.random()>.975)dr[i]=0;
      dr[i]++;
    });
  },50);

  function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function setRes(h,col){
    var el=document.getElementById('res');
    el.innerHTML=h; el.style.borderColor=col; el.style.color=col;
  }

  function go(){
    var name=document.getElementById('nm').value.trim();
    var pw=document.getElementById('pw').value;
    if(!name){setRes('⚠️ Enter a hacker alias','#f44');return;}
    if(!pw){setRes('⚠️ Enter a password','#f44');return;}
    var btn=document.getElementById('sb');
    btn.disabled=true; btn.textContent='⏳ ANALYZING...';
    fetch('/submit',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name,password:pw})})
      .then(function(r){return r.json();})
      .then(function(d){
        if(!d.ok){setRes('❌ '+(d.error||'Error'),'#f44');}
        else{
          document.getElementById('bf').style.width=Math.round(d.score/10)+'%';
          var el=document.getElementById('res');
          el.style.borderColor=d.color; el.style.color='var(--g)';
          el.innerHTML='<div style="font-size:1.8em;margin-bottom:5px">'+esc(d.rank)+'</div>'
            +'<div>Score: <strong style="color:'+d.color+';font-size:1.4em">'+d.score+'</strong> / 1000</div>'
            +'<div style="opacity:.55;font-size:.8em;margin-top:5px">Crack: '+esc(d.crack)
            +(d.details&&d.details.entropy?' · Entropy: '+d.details.entropy+' bits':'')
            +(d.details&&d.details.words?' · Passphrase: '+d.details.words+' words':'')+'</div>';
          var fl=document.getElementById('fl');
          if(d.flags&&d.flags.length)
            fl.innerHTML='⚠️ '+d.flags.map(function(f){return'<span class="fc">'+esc(f)+'</span>';}).join('');
          else
            fl.innerHTML='<span style="color:var(--g)">✅ No weak patterns</span>';
          loadLB();
        }
        btn.disabled=false; btn.textContent='🚀 ANALYZE PASSWORD';
      })
      .catch(function(e){
        setRes('❌ Network error','#f44');
        btn.disabled=false; btn.textContent='🚀 ANALYZE PASSWORD';
      });
  }

  function loadLB(){
    fetch('/api/leaderboard').then(function(r){return r.json();}).then(function(d){
      if(!d.ok||!d.rows)return;
      var g=['#ffd700','#c0c0c0','#cd7f32'];
      document.getElementById('lb').innerHTML=d.rows.length
        ?d.rows.map(function(r,i){return'<tr>'
            +'<td style="color:'+(g[i]||'#444')+'">'+(i+1)+'</td>'
            +'<td><strong>'+esc(r.name)+'</strong></td>'
            +'<td style="color:#00ff41;font-weight:bold">'+r.score+'</td>'
            +'<td style="font-size:11px">'+esc(r.rank)+'</td>'
            +'<td style="opacity:.6">'+esc(r.crack)+'</td>'
            +'<td style="opacity:.45">'+esc(r.geo)+'</td>'
            +'<td><span class="ck '+(r.risk||'LOW')+'">'+esc(r.risk||'?')+'</span></td>'
            +'</tr>';}).join('')
        :'<tr><td colspan="7" style="text-align:center;opacity:.3;padding:16px">No submissions yet</td></tr>';
    }).catch(function(){});
  }

  // Button click
  document.getElementById('sb').addEventListener('click', go);

  // Enter key on BOTH inputs
  document.getElementById('nm').addEventListener('keydown',function(e){if(e.key==='Enter')go();});
  document.getElementById('pw').addEventListener('keydown',function(e){if(e.key==='Enter')go();});

  // WebSocket
  function wsc(){
    try{
      var ws=new WebSocket('ws://'+location.host);
      ws.onmessage=function(e){try{var d=JSON.parse(e.data);if(d.type==='submission')loadLB();}catch(x){}};
      ws.onclose=function(){setTimeout(wsc,3000);};
    }catch(x){}
  }

  loadLB();
  setInterval(loadLB,5000);
  wsc();
})();
</script>
</body>
</html>`;

const ADMIN_PAGE = String.raw`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — CTF v6</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@700;900&display=swap');
:root{--g:#00ff41;--r:#ff4444;--gold:#ffd700}
*{margin:0;padding:0;box-sizing:border-box}
body{background:#050505;color:var(--g);font-family:'Share Tech Mono',monospace;min-height:100vh}
#LS{display:flex;align-items:center;justify-content:center;flex-direction:column;gap:14px;min-height:100vh}
#LS h2{font-family:'Orbitron',sans-serif;font-size:2em;text-shadow:0 0 20px var(--g)}
#AP{display:none}
.wp{max-width:1100px;margin:0 auto;padding:20px}
.tp{display:flex;align-items:center;justify-content:space-between;padding:13px 0 20px;border-bottom:1px solid rgba(0,255,65,.1);margin-bottom:20px;flex-wrap:wrap;gap:9px}
.tp h1{font-family:'Orbitron',sans-serif;font-size:1.4em;text-shadow:0 0 14px var(--g)}
.st{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:11px;margin-bottom:18px}
.sc{background:rgba(0,255,65,.04);border:1px solid rgba(0,255,65,.12);border-radius:10px;padding:13px;text-align:center}
.sv{font-family:'Orbitron',sans-serif;font-size:1.7em;color:var(--g)}
.sl{font-size:10px;opacity:.35;text-transform:uppercase;letter-spacing:1px;margin-top:3px}
.card{background:rgba(0,255,65,.03);border:1px solid rgba(0,255,65,.1);border-radius:11px;padding:17px;margin-bottom:17px}
.card h3{font-size:11px;text-transform:uppercase;letter-spacing:1px;opacity:.45;margin-bottom:11px}
input[type=text],input[type=password]{padding:9px 12px;background:rgba(0,0,0,.9);border:1.5px solid rgba(0,255,65,.2);border-radius:7px;color:var(--g);font-family:inherit;font-size:13px;outline:none;transition:.2s}
input[type=text]:focus,input[type=password]:focus{border-color:var(--g)}
.btn{padding:9px 15px;border:none;border-radius:7px;font-family:inherit;font-size:12px;font-weight:bold;cursor:pointer;transition:.2s}
.red{background:var(--r);color:#fff}.red:hover{background:#c00}
.grn{background:var(--g);color:#000}.grn:hover{background:#0c3}
.gh{background:transparent;border:1px solid rgba(0,255,65,.2);color:var(--g)}.gh:hover{background:rgba(0,255,65,.07)}
.sm{padding:4px 9px;font-size:11px;border-radius:5px}
.tabs{display:flex;gap:6px;margin-bottom:15px;flex-wrap:wrap}
.tab{padding:7px 13px;border:1px solid rgba(0,255,65,.16);border-radius:7px;cursor:pointer;font-size:12px;transition:.2s;user-select:none}
.tab.on,.tab:hover{background:var(--g);color:#000;font-weight:bold}
.pn{display:none}.pn.on{display:block}
table{width:100%;border-collapse:collapse;font-size:12px}
th{padding:7px 7px;text-align:left;border-bottom:1px solid rgba(0,255,65,.14);font-size:10px;text-transform:uppercase;letter-spacing:1px;opacity:.4}
td{padding:7px 7px;border-bottom:1px solid rgba(0,255,65,.05);vertical-align:middle}
tr:hover td{background:rgba(0,255,65,.02)}
.scr{max-height:350px;overflow-y:auto}
.ck{display:inline-block;padding:2px 6px;border-radius:4px;font-size:10px;font-weight:bold}
.CLEAN,.LOW{color:var(--g);border:1px solid var(--g)}
.MEDIUM{color:#fa0;border:1px solid #fa0}
.HIGH{color:#f60;border:1px solid #f60}
.CRITICAL{color:var(--r);border:1px solid var(--r)}
.fd{max-height:210px;overflow-y:auto;background:#000;border:1px solid rgba(0,255,65,.08);border-radius:8px;padding:10px;font-size:11px;line-height:1.7}
.fs{color:var(--g)}.fb{color:var(--r)}.fa{color:var(--gold)}
#toast{position:fixed;top:16px;right:16px;padding:10px 16px;border-radius:8px;font-size:13px;display:none;z-index:9999;font-weight:bold}
</style>
</head>
<body>

<div id="LS">
  <h2>🛡️ ADMIN ACCESS</h2>
  <input id="LPW" type="password" placeholder="Enter admin password" style="width:260px;padding:13px 15px;font-size:15px">
  <button class="btn grn" id="LBT" style="width:260px;padding:13px;font-size:14px">🔓 LOGIN</button>
  <div id="LER" style="color:var(--r);font-size:13px;min-height:18px"></div>
</div>

<div id="AP">
<div class="wp">
  <div class="tp">
    <h1>🛡️ ADMIN PANEL</h1>
    <div style="display:flex;gap:7px;flex-wrap:wrap">
      <a href="/" style="text-decoration:none"><button class="btn gh">← CTF</button></a>
      <button class="btn red sm" id="LOUT">Logout</button>
    </div>
  </div>

  <div class="st">
    <div class="sc"><div class="sv" id="sTot">-</div><div class="sl">Submissions</div></div>
    <div class="sc"><div class="sv" id="sAvg">-</div><div class="sl">Avg Score</div></div>
    <div class="sc"><div class="sv" id="sTop">-</div><div class="sl">Top Score</div></div>
    <div class="sc"><div class="sv" id="sBan">-</div><div class="sl">Banned IPs</div></div>
  </div>

  <div class="card">
    <h3>🚫 Ban IP Address</h3>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input type="text" id="bIP"  placeholder="IP Address"        style="flex:1;min-width:140px">
      <input type="text" id="bRS"  placeholder="Reason (optional)" style="flex:2;min-width:170px">
      <button class="btn red" id="bBT">🚫 BAN</button>
    </div>
  </div>

  <div class="tabs">
    <div class="tab on"  id="T0">📋 Submissions</div>
    <div class="tab"     id="T1">🚫 Banned IPs</div>
    <div class="tab"     id="T2">📡 Request Log</div>
    <div class="tab"     id="T3">🔴 Live Feed</div>
  </div>

  <div id="P0" class="pn on">
    <div class="card"><h3>All Submissions</h3>
      <div class="scr"><table>
        <thead><tr><th>ID</th><th>Name</th><th>Score</th><th>Rank</th><th>Crack</th><th>IP</th><th>Geo</th><th>Risk</th><th>Time</th><th>Actions</th></tr></thead>
        <tbody id="tS"><tr><td colspan="10" style="text-align:center;opacity:.3;padding:16px">Loading...</td></tr></tbody>
      </table></div>
    </div>
  </div>

  <div id="P1" class="pn">
    <div class="card"><h3>Banned IPs</h3>
      <div class="scr"><table>
        <thead><tr><th>IP</th><th>Reason</th><th>Time</th><th>Action</th></tr></thead>
        <tbody id="tB"><tr><td colspan="4" style="text-align:center;opacity:.3;padding:16px">No bans</td></tr></tbody>
      </table></div>
    </div>
  </div>

  <div id="P2" class="pn">
    <div class="card"><h3>Request Log</h3>
      <div class="scr"><table>
        <thead><tr><th>ID</th><th>IP</th><th>Method</th><th>Path</th><th>Time</th></tr></thead>
        <tbody id="tL"><tr><td colspan="5" style="text-align:center;opacity:.3;padding:16px">Loading...</td></tr></tbody>
      </table></div>
    </div>
  </div>

  <div id="P3" class="pn">
    <div class="card"><h3>Live Feed</h3>
      <div class="fd" id="FD">Connecting...</div>
    </div>
  </div>
</div>
</div>

<div id="toast"></div>

<script>
(function(){
  var TOKEN='';

  function e(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function ft(ts){try{return new Date(ts).toLocaleString();}catch(x){return String(ts||'?');}}

  function toast(msg,color){
    var el=document.getElementById('toast');
    el.textContent=msg; el.style.background=color;
    el.style.color=color==='#00ff41'?'#000':'#fff';
    el.style.display='block';
    setTimeout(function(){el.style.display='none';},3000);
  }

  // ── Login ──────────────────────────────────────────────────────────────────
  function doLogin(){
    TOKEN=document.getElementById('LPW').value;
    if(!TOKEN){document.getElementById('LER').textContent='Enter password';return;}
    loadData().then(function(ok){
      if(ok){
        document.getElementById('LS').style.display='none';
        document.getElementById('AP').style.display='block';
        wsConnect();
      } else {
        document.getElementById('LER').textContent='❌ Wrong password';
        TOKEN='';
      }
    });
  }

  document.getElementById('LBT').addEventListener('click', doLogin);
  document.getElementById('LPW').addEventListener('keydown', function(ev){if(ev.key==='Enter')doLogin();});
  document.getElementById('LOUT').addEventListener('click', function(){TOKEN='';location.reload();});

  // ── Load data ──────────────────────────────────────────────────────────────
  function loadData(){
    return fetch('/api/admin/data',{headers:{'x-admin-token':TOKEN}})
      .then(function(r){return r.json();})
      .then(function(d){
        if(!d.ok)return false;
        var s=d.stats||{};
        document.getElementById('sTot').textContent=s.total||0;
        document.getElementById('sAvg').textContent=s.avg||0;
        document.getElementById('sTop').textContent=s.top||0;
        document.getElementById('sBan').textContent=(d.banned||[]).length;
        renderSubs(d.subs||[]);
        renderBans(d.banned||[]);
        renderLogs(d.logs||[]);
        return true;
      }).catch(function(){return false;});
  }

  function renderSubs(rows){
    document.getElementById('tS').innerHTML=rows.length
      ?rows.map(function(r){return'<tr>'
          +'<td style="opacity:.3">'+r.id+'</td>'
          +'<td><strong>'+e(r.name)+'</strong></td>'
          +'<td style="color:#0f4;font-weight:bold">'+r.score+'</td>'
          +'<td style="font-size:11px">'+e(r.rank||'')+'</td>'
          +'<td style="opacity:.55">'+e(r.crack||'?')+'</td>'
          +'<td style="font-size:11px">'+e(r.ip||'')+'</td>'
          +'<td style="opacity:.45">'+e(r.geo||'?')+'</td>'
          +'<td><span class="ck '+(r.risk||'LOW')+'">'+e(r.risk||'?')+'</span></td>'
          +'<td style="opacity:.3;font-size:10px">'+ft(r.ts)+'</td>'
          +'<td style="white-space:nowrap">'
          +'<button class="btn red sm" data-ban-ip="'+e(r.ip)+'" data-ban-name="'+e(r.name)+'">🚫</button> '
          +'<button class="btn gh sm" data-del="'+r.id+'">🗑️</button>'
          +'</td>'
          +'</tr>';}).join('')
      :'<tr><td colspan="10" style="text-align:center;opacity:.3;padding:16px">No submissions</td></tr>';

    document.querySelectorAll('[data-ban-ip]').forEach(function(btn){
      btn.addEventListener('click',function(){
        var ip=this.getAttribute('data-ban-ip'),name=this.getAttribute('data-ban-name');
        if(!confirm('Ban IP '+ip+' ('+name+')?'))return;
        apiPost('/api/admin/ban',{ip:ip,reason:'Banned from submission: '+name},function(d){
          toast(d.ok?'🚫 Banned '+ip:'Error: '+(d.error||'?'),d.ok?'#f44':'#f80');
          if(d.ok)loadData();
        });
      });
    });

    document.querySelectorAll('[data-del]').forEach(function(btn){
      btn.addEventListener('click',function(){
        var id=this.getAttribute('data-del');
        if(!confirm('Delete submission #'+id+'?'))return;
        apiPost('/api/admin/delete',{id:id},function(d){
          toast(d.ok?'🗑️ Deleted':'Error: '+(d.error||'?'),d.ok?'#fa0':'#f44');
          if(d.ok)loadData();
        });
      });
    });
  }

  function renderBans(rows){
    document.getElementById('tB').innerHTML=rows.length
      ?rows.map(function(r){return'<tr>'
          +'<td style="color:var(--r);font-weight:bold">'+e(r.ip)+'</td>'
          +'<td style="opacity:.5">'+e(r.reason||'—')+'</td>'
          +'<td style="opacity:.3;font-size:10px">'+ft(r.ts)+'</td>'
          +'<td><button class="btn grn sm" data-unban="'+e(r.ip)+'">✅ Unban</button></td>'
          +'</tr>';}).join('')
      :'<tr><td colspan="4" style="text-align:center;opacity:.3;padding:16px">No bans</td></tr>';

    document.querySelectorAll('[data-unban]').forEach(function(btn){
      btn.addEventListener('click',function(){
        var ip=this.getAttribute('data-unban');
        if(!confirm('Unban '+ip+'?'))return;
        apiPost('/api/admin/unban',{ip:ip},function(d){
          toast(d.ok?'✅ Unbanned '+ip:'Error: '+(d.error||'?'),d.ok?'#0f4':'#f80');
          if(d.ok)loadData();
        });
      });
    });
  }

  function renderLogs(rows){
    document.getElementById('tL').innerHTML=rows.length
      ?rows.map(function(r){return'<tr>'
          +'<td style="opacity:.3">'+r.id+'</td>'
          +'<td style="font-size:11px">'+e(r.ip||'')+'</td>'
          +'<td style="opacity:.4">'+e(r.method||'')+'</td>'
          +'<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.55">'+e(r.path||'')+'</td>'
          +'<td style="opacity:.3;font-size:10px">'+ft(r.ts)+'</td>'
          +'</tr>';}).join('')
      :'<tr><td colspan="5" style="text-align:center;opacity:.3;padding:16px">No logs</td></tr>';
  }

  // ── Ban form ───────────────────────────────────────────────────────────────
  document.getElementById('bBT').addEventListener('click', function(){
    var ip=document.getElementById('bIP').value.trim();
    var reason=document.getElementById('bRS').value.trim();
    if(!ip){toast('Enter an IP','#f44');return;}
    apiPost('/api/admin/ban',{ip:ip,reason:reason},function(d){
      toast(d.ok?'🚫 Banned '+ip:'Error: '+(d.error||'?'),d.ok?'#f44':'#f80');
      if(d.ok){document.getElementById('bIP').value='';document.getElementById('bRS').value='';loadData();}
    });
  });

  // ── Tabs ───────────────────────────────────────────────────────────────────
  [0,1,2,3].forEach(function(i){
    document.getElementById('T'+i).addEventListener('click',function(){
      [0,1,2,3].forEach(function(j){
        document.getElementById('T'+j).classList.toggle('on',j===i);
        var p=document.getElementById('P'+j);
        p.classList.toggle('on',j===i);
        p.style.display=j===i?'block':'none';
      });
    });
  });

  // ── WebSocket ──────────────────────────────────────────────────────────────
  function wsConnect(){
    try{
      var ws=new WebSocket('ws://'+location.host);
      var fd=document.getElementById('FD');
      ws.onopen=function(){fd.innerHTML='<span style="opacity:.4">Live — waiting for events...</span>';};
      ws.onmessage=function(ev){
        try{
          var d=JSON.parse(ev.data),line='';
          if(d.type==='submission'){line='<div class="fs">[NEW] '+ft(d.ts)+' — '+e(d.name)+' scored '+d.score+' from '+e(d.ip)+'</div>';loadData();}
          else if(d.type==='ban'){line='<div class="fb">[BAN] '+ft(d.ts)+' — '+e(d.ip)+': '+e(d.reason)+'</div>';loadData();}
          else if(d.type==='alert'){line='<div class="fa">[ALERT] '+ft(d.ts)+' — '+e(d.ip)+': '+e(d.msg)+'</div>';}
          if(line){fd.innerHTML+=line;fd.scrollTop=fd.scrollHeight;}
        }catch(x){}
      };
      ws.onclose=function(){setTimeout(wsConnect,3000);};
    }catch(x){}
  }

  // ── API helper ─────────────────────────────────────────────────────────────
  function apiPost(url,body,cb){
    fetch(url,{method:'POST',headers:{'Content-Type':'application/json','x-admin-token':TOKEN},body:JSON.stringify(body)})
      .then(function(r){return r.json();})
      .then(cb)
      .catch(function(){cb({ok:false,error:'Network error'});});
  }

  // Init panel visibility
  [0,1,2,3].forEach(function(i){
    document.getElementById('P'+i).style.display=i===0?'block':'none';
  });

  setInterval(loadData,15000);
})();
</script>
</body>
</html>`;

// ── Start ─────────────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
    const lan = Object.values(os.networkInterfaces()).flat()
        .find(n => n.family==='IPv4' && !n.internal)?.address || 'localhost';
    console.log('\n'+'═'.repeat(52));
    console.log('  🔥 ULTIMATE CTF v6.0');
    console.log('═'.repeat(52));
    console.log('  Site:  http://localhost:'+PORT);
    console.log('  LAN:   http://'+lan+':'+PORT);
    console.log('  Admin: http://localhost:'+PORT+'/admin');
    console.log('  Pass:  '+ADMIN_PASS);
    console.log('═'.repeat(52)+'\n');
});

process.on('SIGINT', () => { db.close(() => process.exit(0)); });