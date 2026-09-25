const express    = require('express');
const cors       = require('cors');
const bodyParser = require('body-parser');
const bcrypt     = require('bcryptjs');
const qrcode     = require('qrcode');
const fs         = require('fs');
const path       = require('path');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

// ===================== FILE PATHS =====================
const DATA_DIR    = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const USERS_FILE    = path.join(DATA_DIR, 'users.json');
const BAL_CODES     = path.join(DATA_DIR, 'balance_codes.json');
const PASS_FILE     = path.join(DATA_DIR, 'sender_passwords.json');
const GLOBAL_SENDER = path.join(DATA_DIR, 'global_senders.json');

// ===================== CONSTANTS =====================
const OWNER_EMAIL = 'evanziggy1013@gmail.com';
const OWNER_KEY   = 'EVAN13_OWNER_2024';

const FEATURE_PRICES = {
    'otp':              4000,
    'ai_dark':          4000,
    'email':            4000,
    'bugwa':            5000,
    'report':           6000,
    'global_sender':   20000,
    'upgrade_premium_v1': 2000,
    'upgrade_premium_v2': 4000,
    'upgrade_premium_v3': 6000,
    'upgrade_max':        30000,
    'upgrade_admin':      40000,
    'call':     0, 'custom': 0, 'info': 0,
    'ai_normal': 0, 'ai_tsundere': 0, 'game': 0,
};

const TYPE_ORDER = ['free','premium_v1','premium_v2','premium_v3','max','admin','owner'];

function tokenLimit(type) {
    switch(type) {
        case 'owner': case 'admin': return -1;
        case 'max':        return 30;
        case 'premium_v3': return 10;
        case 'premium_v2': return 5;
        case 'premium_v1': return 2;
        default:           return 1;
    }
}
function defaultFeatures(type) {
    var base = ['info','game','ai_normal','call','custom'];
    if (type === 'owner' || type === 'admin')
        return ['info','game','ai_normal','ai_dark','ai_tsundere','call','custom','otp','report','email','bugwa','global_sender'];
    return base;
}
function determineType(email) {
    return email === OWNER_EMAIL ? 'owner' : 'free';
}

// ===================== HELPERS =====================
function loadJson(file, def) {
    try { if (fs.existsSync(file)) return JSON.parse(fs.readFileSync(file,'utf8')); } catch(e) {}
    return def;
}
function saveJson(file, data) { fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf8'); }
function hashPass(p) { return crypto.createHash('sha256').update(p).digest('hex'); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function sanitize(user) {
    return { username:user.username, email:user.email, accountType:user.accountType,
        unlockedFeatures:user.unlockedFeatures, tokenUsed:user.tokenUsed, balance:user.balance||0 };
}

// ===================== BAILEYS =====================
const sessions = {}, sessionStates = {}, qrCodes = {};
const senderPasswords = loadJson(PASS_FILE, {});

let makeWASocket, useMultiFileAuthState, DisconnectReason, makeCacheableSignalKeyStore, pinoLogger;
try {
    const b = require('@whiskeysockets/baileys');
    makeWASocket             = b.makeWASocket;
    useMultiFileAuthState    = b.useMultiFileAuthState;
    DisconnectReason         = b.DisconnectReason;
    makeCacheableSignalKeyStore = b.makeCacheableSignalKeyStore;
    pinoLogger = require('pino')({ level: 'silent' });
    console.log('Baileys loaded OK');
} catch(e) { console.log('Baileys error:', e.message); }

async function createSession(num, isGlobal) {
    if (!makeWASocket) return;
    var dir = path.join(__dirname, 'sessions', num);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    var { state, saveCreds } = await useMultiFileAuthState(dir);
    sessionStates[num] = 'connecting';
    var sock = makeWASocket({
        auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, pinoLogger) },
        printQRInTerminal: false, logger: pinoLogger,
        browser: ['Vanzzz Tools','Chrome','120.0.0'], connectTimeoutMs: 30000
    });
    sock.ev.on('creds.update', saveCreds);
    sock.ev.on('connection.update', async function(update) {
        var { qr, connection, lastDisconnect } = update;
        if (qr) { qrCodes[num] = await qrcode.toDataURL(qr); sessionStates[num] = 'qr'; }
        if (connection === 'open') {
            sessionStates[num] = 'connected'; qrCodes[num] = null; sessions[num] = sock;
            if (isGlobal) {
                var gs = loadJson(GLOBAL_SENDER, {});
                gs[num] = { status: 'connected', connectedAt: new Date().toISOString() };
                saveJson(GLOBAL_SENDER, gs);
            }
        }
        if (connection === 'close') {
            var code = lastDisconnect&&lastDisconnect.error&&lastDisconnect.error.output
                ? lastDisconnect.error.output.statusCode : 0;
            sessionStates[num] = 'disconnected'; delete sessions[num];
            if (code !== DisconnectReason.loggedOut) setTimeout(function(){ createSession(num, isGlobal); }, 5000);
            else {
                var d = path.join(__dirname,'sessions',num);
                if (fs.existsSync(d)) fs.rmSync(d,{recursive:true,force:true});
                delete sessionStates[num]; delete qrCodes[num]; delete senderPasswords[num];
                saveJson(PASS_FILE, senderPasswords);
                if (isGlobal) {
                    var gs = loadJson(GLOBAL_SENDER, {}); delete gs[num]; saveJson(GLOBAL_SENDER, gs);
                }
            }
        }
    });
    sessions[num] = sock;
}

async function loadSessions() {
    var dir = path.join(__dirname, 'sessions');
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir); return; }
    var gs = loadJson(GLOBAL_SENDER, {});
    for (var d of fs.readdirSync(dir)) {
        await createSession(d, !!gs[d]);
        await sleep(1000);
    }
}

// ===================== AUTH =====================
app.post('/api/auth/register', async function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { username, email, password } = req.body;
    if (!username||!email||!password) return res.status(400).json({error:'username, email, password wajib'});
    if (users[email]) return res.status(409).json({error:'Email sudah terdaftar!'});
    var hash = await bcrypt.hash(password, 10);
    var type = determineType(email);
    users[email] = { username, email, password:hash, accountType:type,
        unlockedFeatures:defaultFeatures(type), tokenUsed:{}, balance:0,
        createdAt:new Date().toISOString() };
    saveJson(USERS_FILE, users);
    res.json({ success:true, user:sanitize(users[email]) });
});

app.post('/api/auth/login', async function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { email, password } = req.body;
    if (!email||!password) return res.status(400).json({error:'email dan password wajib'});
    var user = users[email];
    if (!user) return res.status(404).json({error:'Akun tidak ditemukan! Daftar dulu.'});
    var ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({error:'Password salah!'});
    if (user.balance === undefined) user.balance = 0;
    saveJson(USERS_FILE, users);
    res.json({ success:true, user:sanitize(user) });
});

app.get('/api/auth/profile', function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { email } = req.query;
    if (!email||!users[email]) return res.status(404).json({error:'User tidak ditemukan'});
    res.json({ user:sanitize(users[email]) });
});

// ===================== SALDO =====================
app.get('/api/balance', function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { email } = req.query;
    if (!email||!users[email]) return res.status(404).json({error:'User tidak ditemukan'});
    res.json({ balance: users[email].balance||0 });
});

app.post('/api/balance/redeem', function(req, res) {
    var { code, email } = req.body;
    if (!code||!email) return res.status(400).json({error:'code dan email wajib'});
    var codes = loadJson(BAL_CODES, {});
    var users = loadJson(USERS_FILE, {});
    var entry = codes[code.toUpperCase()];
    if (!entry) return res.status(404).json({error:'Kode saldo tidak valid!'});
    if (entry.used) return res.status(400).json({error:'Kode sudah digunakan!'});
    var user = users[email];
    if (!user) return res.status(404).json({error:'User tidak ditemukan!'});
    user.balance = (user.balance||0) + entry.amount;
    entry.used = true; entry.usedBy = email; entry.usedAt = new Date().toISOString();
    saveJson(BAL_CODES, codes); saveJson(USERS_FILE, users);
    res.json({ success:true, added:entry.amount, balance:user.balance });
});

app.post('/api/balance/buy-feature', function(req, res) {
    var { email, feature } = req.body;
    if (!email||!feature) return res.status(400).json({error:'email dan feature wajib'});
    var users = loadJson(USERS_FILE, {});
    var user  = users[email];
    if (!user) return res.status(404).json({error:'User tidak ditemukan!'});
    var price = FEATURE_PRICES[feature];
    if (price === undefined) return res.status(400).json({error:'Fitur tidak dikenal'});
    if (price === 0) {
        if (!user.unlockedFeatures.includes(feature)) user.unlockedFeatures.push(feature);
        saveJson(USERS_FILE, users);
        return res.json({ success:true, balance:user.balance, message:'Fitur gratis diaktifkan!' });
    }
    var balance = user.balance||0;
    if (balance < price) return res.status(402).json({error:'Saldo tidak cukup!', balance, price});
    user.balance = balance - price;
    if (feature.startsWith('upgrade_')) {
        var newType = feature.replace('upgrade_','');
        var curIdx = TYPE_ORDER.indexOf(user.accountType);
        var newIdx = TYPE_ORDER.indexOf(newType);
        if (newIdx > curIdx) {
            user.accountType = newType;
            defaultFeatures(newType).forEach(function(f){
                if (!user.unlockedFeatures.includes(f)) user.unlockedFeatures.push(f);
            });
        }
    } else {
        if (!user.unlockedFeatures.includes(feature)) user.unlockedFeatures.push(feature);
    }
    saveJson(USERS_FILE, users);
    res.json({ success:true, balance:user.balance, feature, price, user:sanitize(user) });
});

// Buat kode saldo (semua user bisa, sesuai saldo; owner bebas)
app.post('/api/owner/create-balance-code', function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { email, amount, count } = req.body;
    if (!email) return res.status(400).json({error:'email wajib'});
    var user = users[email];
    if (!user) return res.status(404).json({error:'User tidak ditemukan!'});
    if (!amount||amount<=0) return res.status(400).json({error:'Nominal wajib'});
    if (user.accountType !== 'owner' && user.accountType !== 'admin') {
        var total = parseInt(amount) * Math.min(parseInt(count)||1, 100);
        var bal   = user.balance||0;
        if (bal < total) return res.status(402).json({error:'Saldo tidak cukup! Butuh Rp '+total+', saldo kamu Rp '+bal});
        user.balance = bal - total;
        saveJson(USERS_FILE, users);
    }
    var n = Math.min(parseInt(count)||1, 100);
    var codes = loadJson(BAL_CODES, {});
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', generated = [];
    for (var i=0;i<n;i++) {
        var code = 'SAL-';
        for (var j=0;j<12;j++) { if(j===4||j===8) code+='-'; code+=chars[Math.floor(Math.random()*chars.length)]; }
        codes[code] = { amount:parseInt(amount), used:false, usedBy:null, createdBy:email, createdAt:new Date().toISOString() };
        generated.push({ code, amount:parseInt(amount) });
    }
    saveJson(BAL_CODES, codes);
    res.json({ success:true, codes:generated });
});

app.get('/api/balance/codes/user', function(req, res) {
    var { email } = req.query;
    if (!email) return res.status(400).json({error:'email wajib'});
    var codes = loadJson(BAL_CODES, {});
    var result = {};
    for (var c in codes) if (codes[c].createdBy === email) result[c] = codes[c];
    res.json({ codes:result });
});

// ===================== TOKEN =====================
app.post('/api/user/use-token', function(req, res) {
    var users = loadJson(USERS_FILE, {});
    var { email, feature } = req.body;
    if (!email||!feature) return res.status(400).json({error:'email dan feature wajib'});
    var user = users[email];
    if (!user) return res.status(404).json({error:'User tidak ditemukan'});
    if (user.accountType==='owner'||user.accountType==='admin') return res.json({ok:true,remaining:-1});
    if (!user.unlockedFeatures.includes(feature)) return res.status(403).json({ok:false,error:'Fitur terkunci!'});
    var today = new Date().toISOString().slice(0,10);
    var limit = tokenLimit(user.accountType);
    var used  = user.tokenUsed[today]||0;
    if (limit!==-1&&used>=limit) return res.status(429).json({ok:false,error:'Token harian habis!',remaining:0});
    user.tokenUsed[today] = used+1;
    saveJson(USERS_FILE, users);
    res.json({ ok:true, remaining:limit===-1?-1:limit-(used+1), used:used+1, limit });
});

// ===================== SENDER PRIBADI =====================
app.get('/api/status', function(req, res) {
    var connected = Object.values(sessionStates).filter(function(s){return s==='connected';}).length;
    res.json({ status:'running', totalSenders:Object.keys(sessionStates).length, connectedSenders:connected,
        senders:Object.keys(sessionStates).map(function(n){return{number:n,status:sessionStates[n]};}) });
});

app.post('/api/sender/add', async function(req, res) {
    if (!makeWASocket) return res.status(503).json({error:'Baileys tidak tersedia'});
    var { number, name, password, email } = req.body;
    if (!number||!name||!password||!email) return res.status(400).json({error:'number, name, password, email wajib'});
    var num = number.replace(/[^0-9]/g,'');
    if (sessionStates[num]==='connected') return res.json({status:'already_connected',number:num});
    senderPasswords[num] = { name, hash:hashPass(password), ownerEmail:email, isGlobal:false };
    saveJson(PASS_FILE, senderPasswords);
    createSession(num, false);
    res.json({ status:'connecting', number:num, name, message:'Tunggu QR lalu scan' });
});

app.post('/api/sender/add-global', async function(req, res) {
    if (!makeWASocket) return res.status(503).json({error:'Baileys tidak tersedia'});
    var { number, name, password, email } = req.body;
    if (!number||!name||!password||!email) return res.status(400).json({error:'number, name, password, email wajib'});
    // Cek user sudah beli global_sender
    var users = loadJson(USERS_FILE, {});
    var user  = users[email];
    if (!user) return res.status(404).json({error:'User tidak ditemukan'});
    if (!user.unlockedFeatures.includes('global_sender') && user.accountType!=='owner' && user.accountType!=='admin')
        return res.status(403).json({error:'Beli fitur Global Sender dulu di keranjang!'});
    var num = number.replace(/[^0-9]/g,'');
    if (sessionStates[num]==='connected') return res.json({status:'already_connected',number:num});
    senderPasswords[num] = { name, hash:hashPass(password), ownerEmail:email, isGlobal:true };
    saveJson(PASS_FILE, senderPasswords);
    createSession(num, true);
    res.json({ status:'connecting', number:num, name, message:'Tunggu QR lalu scan' });
});

app.post('/api/sender/verify', function(req, res) {
    var { number, password } = req.body;
    if (!number||!password) return res.status(400).json({error:'number dan password wajib'});
    var num = number.replace(/[^0-9]/g,''), data = senderPasswords[num];
    if (!data) return res.status(404).json({valid:false,error:'Sender tidak ditemukan di server'});
    res.json({ valid:data.hash===hashPass(password), name:data.name||num, isGlobal:data.isGlobal||false });
});

app.get('/api/sender/list', function(req, res) {
    var { email } = req.query;
    res.json({ senders:Object.keys(sessionStates).map(function(num) {
        var info = senderPasswords[num]||{};
        return { number:num, name:info.name||'-', status:sessionStates[num], hasQr:!!qrCodes[num],
            isGlobal:info.isGlobal||false,
            isMine: email && info.ownerEmail===email };
    })});
});

// List global sender saja
app.get('/api/sender/global', function(req, res) {
    var gs = loadJson(GLOBAL_SENDER, {});
    var list = Object.keys(gs).map(function(num) {
        return { number:num, status:sessionStates[num]||'disconnected', name:(senderPasswords[num]&&senderPasswords[num].name)||'-' };
    });
    res.json({ senders:list });
});

app.get('/api/sender/qr/:number', function(req, res) {
    var qr = qrCodes[req.params.number];
    if (!qr) return res.status(404).json({error:'QR tidak tersedia', status:sessionStates[req.params.number]||'unknown'});
    res.json({ qr, number:req.params.number });
});

app.delete('/api/sender/:number', async function(req, res) {
    var num = req.params.number, data = senderPasswords[num];
    var { password, email } = req.body||{};
    if (data && password && data.hash!==hashPass(password)) return res.status(403).json({error:'Password salah'});
    if (data && email && data.ownerEmail!==email && email!==OWNER_EMAIL) return res.status(403).json({error:'Bukan sender kamu'});
    if (sessions[num]) { try{await sessions[num].logout();}catch(e){} delete sessions[num]; }
    delete sessionStates[num]; delete qrCodes[num]; delete senderPasswords[num];
    saveJson(PASS_FILE, senderPasswords);
    var dir = path.join(__dirname,'sessions',num);
    if (fs.existsSync(dir)) fs.rmSync(dir,{recursive:true,force:true});
    var gs = loadJson(GLOBAL_SENDER, {}); delete gs[num]; saveJson(GLOBAL_SENDER, gs);
    res.json({ status:'deleted', number:num });
});

// ===================== SPAM =====================
function getActiveSenders(senderList) {
    return (senderList||[]).filter(function(s){ var n=s.replace(/[^0-9]/g,''); return sessionStates[n]==='connected'; });
}

app.post('/api/spam/message', async function(req, res) {
    var { senders, target, message, count } = req.body;
    count = Math.min(parseInt(count)||5, 100);
    if (!senders||!target||!message) return res.status(400).json({error:'senders, target, message wajib'});
    var targetJid = target.replace(/[^0-9]/g,'')+'@s.whatsapp.net', results=[];
    for (var i=0;i<senders.length;i++) {
        var sNum=senders[i].replace(/[^0-9]/g,''), sock=sessions[sNum];
        if (!sock||sessionStates[sNum]!=='connected'){results.push({sender:sNum,status:'not_connected',sent:0});continue;}
        var sent=0;
        for(var j=0;j<count;j++){try{await sock.sendMessage(targetJid,{text:message});sent++;await sleep(500);}catch(e){}}
        results.push({sender:sNum,status:'done',sent:sent});
    }
    res.json({success:true,results:results});
});

app.post('/api/spam/call', async function(req, res) {
    var { senders, target, count } = req.body;
    count = Math.min(parseInt(count)||10, 100);
    if (!senders||!target) return res.status(400).json({error:'senders dan target wajib'});
    var targetJid=target.replace(/[^0-9]/g,'')+'@s.whatsapp.net', results=[], idx=0;
    for (var i=0;i<count;i++) {
        var sNum=senders[idx%senders.length].replace(/[^0-9]/g,''); idx++;
        var sock=sessions[sNum];
        if (!sock||sessionStates[sNum]!=='connected'){results.push({call:i+1,sender:sNum,status:'not_connected'});continue;}
        try {
            await sock.sendMessage(targetJid,{audio:{url:'https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3'},pttPlayback:true,mimetype:'audio/ogg; codecs=opus'});
            results.push({call:i+1,sender:sNum,status:'called'});
        } catch(e){ results.push({call:i+1,sender:sNum,status:'error',msg:e.message}); }
        await sleep(2000);
    }
    res.json({success:true,results:results,totalCalls:count});
});

app.post('/api/spam/fake-voice', async function(req, res) {
    var { senders, target, count } = req.body;
    count = Math.min(parseInt(count)||5, 10);
    if (!senders||!target) return res.status(400).json({error:'senders dan target wajib'});
    var targetJid=target.replace(/[^0-9]/g,'')+'@s.whatsapp.net', results=[];
    var fakeAudioUrl='https://www.soundhelix.com/examples/mp3/SoundHelix-Song-1.mp3';
    for (var i=0;i<senders.length;i++) {
        var sNum=senders[i].replace(/[^0-9]/g,''), sock=sessions[sNum];
        if (!sock||sessionStates[sNum]!=='connected'){results.push({sender:sNum,status:'not_connected',sent:0});continue;}
        var sent=0;
        for(var j=0;j<count;j++){
            try{await sock.sendMessage(targetJid,{audio:{url:fakeAudioUrl},ptt:true,mimetype:'audio/ogg; codecs=opus'});sent++;await sleep(400);}catch(e){}
        }
        results.push({sender:sNum,status:'done',sent:sent});
    }
    res.json({success:true,results:results});
});

app.post('/api/spam/fake-pdf', async function(req, res) {
    var { senders, target, count, filename } = req.body;
    count = Math.min(parseInt(count)||5, 10);
    filename = filename||'By Vanzzz Tools.PDF';
    if (!senders||!target) return res.status(400).json({error:'senders dan target wajib'});
    var targetJid=target.replace(/[^0-9]/g,'')+'@s.whatsapp.net', results=[];
    var fakePdfUrl='https://www.w3.org/WAI/WCAG21/Techniques/pdf/PDF1.pdf';
    for (var i=0;i<senders.length;i++) {
        var sNum=senders[i].replace(/[^0-9]/g,''), sock=sessions[sNum];
        if (!sock||sessionStates[sNum]!=='connected'){results.push({sender:sNum,status:'not_connected',sent:0});continue;}
        var sent=0;
        for(var j=0;j<count;j++){
            try{await sock.sendMessage(targetJid,{document:{url:fakePdfUrl},mimetype:'application/pdf',fileName:filename,caption:''});sent++;await sleep(400);}catch(e){}
        }
        results.push({sender:sNum,status:'done',sent:sent});
    }
    res.json({success:true,results:results});
});

app.post('/api/spam/fake-image', async function(req, res) {
    var { senders, target, count } = req.body;
    count = Math.min(parseInt(count)||5, 10);
    if (!senders||!target) return res.status(400).json({error:'senders dan target wajib'});
    var targetJid=target.replace(/[^0-9]/g,'')+'@s.whatsapp.net', results=[];
    var fakeImgUrl='https://www.gstatic.com/webp/gallery/1.jpg';
    for (var i=0;i<senders.length;i++) {
        var sNum=senders[i].replace(/[^0-9]/g,''), sock=sessions[sNum];
        if (!sock||sessionStates[sNum]!=='connected'){results.push({sender:sNum,status:'not_connected',sent:0});continue;}
        var sent=0;
        for(var j=0;j<count;j++){
            try{await sock.sendMessage(targetJid,{image:{url:fakeImgUrl},caption:''});sent++;await sleep(400);}catch(e){}
        }
        results.push({sender:sNum,status:'done',sent:sent});
    }
    res.json({success:true,results:results});
});

// ===================== UTIL =====================
app.get('/', function(req, res) {
    res.json({ status:'Vanzzz Tools Server berjalan', version:'3.0.0' });
});
app.get('/ping', function(req, res) { res.json({ ok:true }); });

// ===================== START =====================
loadSessions().then(function() {
    app.listen(PORT, function() { console.log('Vanzzz Tools Server v3 jalan di port '+PORT); });
});
