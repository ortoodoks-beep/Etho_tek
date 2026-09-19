const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

const root = __dirname;
const publicDir = path.join(root, "public");
const uploadDir = path.join(root, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use("/uploads", express.static(uploadDir));
app.use(express.static(publicDir));

const db = new sqlite3.Database(path.join(root, "database.sqlite"));

function run(sql, params=[]) {
  return new Promise((resolve,reject)=>db.run(sql,params,function(err){
    if(err) reject(err); else resolve({id:this.lastID,changes:this.changes});
  }));
}
function get(sql, params=[]) {
  return new Promise((resolve,reject)=>db.get(sql,params,(e,row)=>e?reject(e):resolve(row)));
}
function all(sql, params=[]) {
  return new Promise((resolve,reject)=>db.all(sql,params,(e,rows)=>e?reject(e):resolve(rows)));
}
function ageFromYear(y){ return new Date().getFullYear()-Number(y); }
function tokenFor(u){ return jwt.sign({id:u.id,username:u.username},JWT_SECRET,{expiresIn:"30d"}); }

async function init(){
  await run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL, phone TEXT, password_hash TEXT NOT NULL,
    gender TEXT, birth_year INTEGER, bio TEXT DEFAULT '', avatar TEXT DEFAULT '',
    is_admin INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await run(`CREATE TABLE IF NOT EXISTS otp_codes(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,code TEXT,expires_at INTEGER)`);
  await run(`CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER,following_id INTEGER,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(follower_id,following_id))`);
  await run(`CREATE TABLE IF NOT EXISTS videos(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,filename TEXT,caption TEXT DEFAULT '',hashtags TEXT DEFAULT '',views INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS likes(user_id INTEGER,video_id INTEGER,UNIQUE(user_id,video_id))`);
  await run(`CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,video_id INTEGER,text TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,type TEXT,message TEXT,read INTEGER DEFAULT 0,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS conversations(id INTEGER PRIMARY KEY AUTOINCREMENT,user1 INTEGER,user2 INTEGER,UNIQUE(user1,user2))`);
  await run(`CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,conversation_id INTEGER,sender_id INTEGER,text TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS live_sessions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS wallets(user_id INTEGER PRIMARY KEY,balance REAL DEFAULT 0)`);
  await run(`CREATE TABLE IF NOT EXISTS gifts(id INTEGER PRIMARY KEY AUTOINCREMENT,sender_id INTEGER,creator_id INTEGER,amount REAL,created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
  await run(`CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,reporter_id INTEGER,target_type TEXT,target_id INTEGER,reason TEXT,status TEXT DEFAULT 'open',created_at TEXT DEFAULT CURRENT_TIMESTAMP)`);
}
const auth = async (req,res,next)=>{
  try{
    const h=req.headers.authorization||"";
    if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Login required"});
    const p=jwt.verify(h.slice(7),JWT_SECRET);
    const u=await get("SELECT * FROM users WHERE id=?",[p.id]);
    if(!u || u.banned) return res.status(401).json({error:"Account unavailable"});
    req.user=u; next();
  }catch(e){res.status(401).json({error:"Invalid token"});}
};
const adminOnly=(req,res,next)=>req.user?.is_admin?next():res.status(403).json({error:"Admin only"});

const storage=multer.diskStorage({
  destination:(req,file,cb)=>cb(null,uploadDir),
  filename:(req,file,cb)=>{
    const ext=path.extname(file.originalname)||".mp4";
    cb(null,Date.now()+"-"+crypto.randomBytes(6).toString("hex")+ext);
  }
});
const upload=multer({storage,limits:{fileSize:300*1024*1024}});

app.get("/api/health",(req,res)=>res.json({ok:true,app:"Etho_tek"}));

app.post("/api/auth/register",async(req,res)=>{
  try{
    const {username,email,phone,password,gender,birthYear}=req.body;
    if(!username||!email||!password||!birthYear) return res.status(400).json({error:"Required fields missing"});
    if(ageFromYear(birthYear)<17) return res.status(400).json({error:"You must be at least 17"});
    const hash=await bcrypt.hash(password,12);
    const r=await run("INSERT INTO users(username,email,phone,password_hash,gender,birth_year) VALUES(?,?,?,?,?,?)",
      [username,email,phone||"",hash,gender||"",birthYear]);
    await run("INSERT OR IGNORE INTO wallets(user_id,balance) VALUES(?,0)",[r.id]);
    const u=await get("SELECT * FROM users WHERE id=?",[r.id]);
    res.json({token:tokenFor(u),user:{id:u.id,username:u.username,email:u.email}});
  }catch(e){res.status(400).json({error:e.message.includes("UNIQUE")?"Username or email already exists":e.message});}
});
app.post("/api/auth/login",async(req,res)=>{
  const {login,password}=req.body;
  const u=await get("SELECT * FROM users WHERE username=? OR email=? OR phone=?",[login,login,login]);
  if(!u||!(await bcrypt.compare(password||"",u.password_hash))) return res.status(401).json({error:"Invalid login"});
  res.json({token:tokenFor(u),user:{id:u.id,username:u.username,email:u.email}});
});
app.post("/api/auth/request-otp",async(req,res)=>{
  const {email,phone}=req.body;
  const u=await get("SELECT * FROM users WHERE email=? OR phone=?",[email||"",phone||""]);
  if(!u) return res.status(404).json({error:"User not found"});
  const code=String(Math.floor(100000+Math.random()*900000));
  await run("INSERT INTO otp_codes(user_id,code,expires_at) VALUES(?,?,?)",[u.id,code,Date.now()+10*60*1000]);
  console.log("ETHO_TEK OTP:",code);
  res.json({message:"OTP created (development mode)",developmentOtp:code});
});
app.post("/api/auth/verify-otp",async(req,res)=>{
  const {email,phone,code}=req.body;
  const u=await get("SELECT * FROM users WHERE email=? OR phone=?",[email||"",phone||""]);
  const o=u&&await get("SELECT * FROM otp_codes WHERE user_id=? AND code=? AND expires_at>? ORDER BY id DESC",[u.id,code,Date.now()]);
  if(!o) return res.status(400).json({error:"Invalid or expired OTP"});
  res.json({token:tokenFor(u),user:{id:u.id,username:u.username,email:u.email}});
});

app.get("/api/profile/me",auth,async(req,res)=>res.json(req.user));
app.get("/api/profile/:username",async(req,res)=>{
  const u=await get("SELECT id,username,email,gender,bio,avatar,created_at FROM users WHERE username=?",[req.params.username]);
  if(!u)return res.status(404).json({error:"User not found"});
  const followers=await get("SELECT COUNT(*) n FROM follows WHERE following_id=?",[u.id]);
  const following=await get("SELECT COUNT(*) n FROM follows WHERE follower_id=?",[u.id]);
  res.json({...u,followers:followers.n,following:following.n});
});
app.put("/api/profile",auth,async(req,res)=>{
  const {bio,avatar}=req.body;
  await run("UPDATE users SET bio=COALESCE(?,bio),avatar=COALESCE(?,avatar) WHERE id=?",[bio,avatar,req.user.id]);
  res.json(await get("SELECT * FROM users WHERE id=?",[req.user.id]));
});

app.post("/api/users/:id/follow",auth,async(req,res)=>{
  const id=Number(req.params.id); if(id===req.user.id)return res.status(400).json({error:"Cannot follow yourself"});
  await run("INSERT OR IGNORE INTO follows(follower_id,following_id) VALUES(?,?)",[req.user.id,id]);
  await run("INSERT INTO notifications(user_id,type,message) VALUES(?,?,?)",[id,"follow",req.user.username+" followed you"]);
  res.json({ok:true});
});
app.delete("/api/users/:id/follow",auth,async(req,res)=>{
  await run("DELETE FROM follows WHERE follower_id=? AND following_id=?",[req.user.id,Number(req.params.id)]);
  res.json({ok:true});
});
app.get("/api/users/:id/followers",async(req,res)=>res.json(await all(`SELECT u.id,u.username,u.avatar FROM follows f JOIN users u ON u.id=f.follower_id WHERE f.following_id=?`,[req.params.id])));
app.get("/api/users/:id/following",async(req,res)=>res.json(await all(`SELECT u.id,u.username,u.avatar FROM follows f JOIN users u ON u.id=f.following_id WHERE f.follower_id=?`,[req.params.id])));

app.post("/api/videos",auth,upload.single("video"),async(req,res)=>{
  if(!req.file)return res.status(400).json({error:"Video file required"});
  const r=await run("INSERT INTO videos(user_id,filename,caption,hashtags) VALUES(?,?,?,?)",[req.user.id,req.file.filename,req.body.caption||"",req.body.hashtags||""]);
  res.json({id:r.id,url:"/uploads/"+req.file.filename});
});
app.get("/api/videos",async(req,res)=>{
  const rows=await all(`SELECT v.*,u.username,u.avatar,
    (SELECT COUNT(*) FROM likes l WHERE l.video_id=v.id) likes,
    (SELECT COUNT(*) FROM comments c WHERE c.video_id=v.id) comments
    FROM videos v JOIN users u ON u.id=v.user_id WHERE u.banned=0 ORDER BY v.id DESC LIMIT ?`,[Math.min(Number(req.query.limit)||30,100)]);
  res.json(rows.map(x=>({...x,url:"/uploads/"+x.filename})));
});
app.get("/api/videos/:id",async(req,res)=>{
  const v=await get(`SELECT v.*,u.username FROM videos v JOIN users u ON u.id=v.user_id WHERE v.id=?`,[req.params.id]);
  if(!v)return res.status(404).json({error:"Video not found"});
  await run("UPDATE videos SET views=views+1 WHERE id=?",[req.params.id]);
  res.json({...v,url:"/uploads/"+v.filename});
});
app.delete("/api/videos/:id",auth,async(req,res)=>{
  const v=await get("SELECT * FROM videos WHERE id=?",[req.params.id]);
  if(!v)return res.status(404).json({error:"Not found"});
  if(v.user_id!==req.user.id&&!req.user.is_admin)return res.status(403).json({error:"Forbidden"});
  await run("DELETE FROM videos WHERE id=?",[req.params.id]); await run("DELETE FROM likes WHERE video_id=?",[req.params.id]);
  res.json({ok:true});
});
app.post("/api/videos/:id/like",auth,async(req,res)=>{await run("INSERT OR IGNORE INTO likes(user_id,video_id) VALUES(?,?)",[req.user.id,req.params.id]);res.json({ok:true});});
app.delete("/api/videos/:id/like",auth,async(req,res)=>{await run("DELETE FROM likes WHERE user_id=? AND video_id=?",[req.user.id,req.params.id]);res.json({ok:true});});
app.get("/api/videos/:id/like",async(req,res)=>res.json(await get("SELECT COUNT(*) n FROM likes WHERE video_id=?",[req.params.id])));
app.get("/api/videos/:id/comments",async(req,res)=>res.json(await all(`SELECT c.*,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.video_id=? ORDER BY c.id DESC`,[req.params.id])));
app.post("/api/videos/:id/comments",auth,async(req,res)=>{if(!req.body.text)return res.status(400).json({error:"Text required"});const r=await run("INSERT INTO comments(user_id,video_id,text) VALUES(?,?,?)",[req.user.id,req.params.id,req.body.text]);res.json({id:r.id});});
app.delete("/api/comments/:id",auth,async(req,res)=>{const c=await get("SELECT * FROM comments WHERE id=?",[req.params.id]);if(!c)return res.status(404).json({error:"Not found"});if(c.user_id!==req.user.id&&!req.user.is_admin)return res.status(403).json({error:"Forbidden"});await run("DELETE FROM comments WHERE id=?",[req.params.id]);res.json({ok:true});});

app.get("/api/search/users",async(req,res)=>res.json(await all("SELECT id,username,avatar,bio FROM users WHERE username LIKE ? AND banned=0 LIMIT 30",["%"+(req.query.q||"")+"%"])));
app.get("/api/search/videos",async(req,res)=>res.json(await all("SELECT v.*,u.username FROM videos v JOIN users u ON u.id=v.user_id WHERE v.caption LIKE ? OR v.hashtags LIKE ? ORDER BY v.id DESC LIMIT 30",["%"+(req.query.q||"")+"%","%"+(req.query.q||"")+"%"])));

app.get("/api/notifications",auth,async(req,res)=>res.json(await all("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",[req.user.id])));
app.post("/api/notifications/read-all",auth,async(req,res)=>{await run("UPDATE notifications SET read=1 WHERE user_id=?",[req.user.id]);res.json({ok:true});});

app.post("/api/chat/conversations",auth,async(req,res)=>{
  const other=Number(req.body.userId); const a=Math.min(req.user.id,other),b=Math.max(req.user.id,other);
  let c=await get("SELECT * FROM conversations WHERE user1=? AND user2=?",[a,b]);
  if(!c){const r=await run("INSERT INTO conversations(user1,user2) VALUES(?,?)",[a,b]);c=await get("SELECT * FROM conversations WHERE id=?",[r.id]);}
  res.json(c);
});
app.get("/api/chat/conversations",auth,async(req,res)=>res.json(await all("SELECT * FROM conversations WHERE user1=? OR user2=? ORDER BY id DESC",[req.user.id,req.user.id])));
app.get("/api/chat/:id/messages",auth,async(req,res)=>res.json(await all("SELECT m.*,u.username FROM messages m JOIN users u ON u.id=m.sender_id WHERE conversation_id=? ORDER BY m.id",[req.params.id])));
app.post("/api/chat/:id/messages",auth,async(req,res)=>{const r=await run("INSERT INTO messages(conversation_id,sender_id,text) VALUES(?,?,?)",[req.params.id,req.user.id,req.body.text||""]);res.json({id:r.id});});

app.post("/api/live/start",auth,async(req,res)=>{
  if(ageFromYear(req.user.birth_year)<17)return res.status(403).json({error:"Live requires age 17+"});
  const f=await get("SELECT COUNT(*) n FROM follows WHERE following_id=?",[req.user.id]);
  if(f.n<50)return res.status(403).json({error:"50 followers required to start Live"});
  const r=await run("INSERT INTO live_sessions(user_id,title) VALUES(?,?)",[req.user.id,req.body.title||"Live"]);
  res.json({id:r.id,message:"Live session created. Real video streaming requires WebRTC/media server."});
});
app.get("/api/live",async(req,res)=>res.json(await all(`SELECT l.*,u.username,u.avatar FROM live_sessions l JOIN users u ON u.id=l.user_id WHERE l.active=1 ORDER BY l.id DESC`)));
app.post("/api/live/:id/end",auth,async(req,res)=>{await run("UPDATE live_sessions SET active=0 WHERE id=? AND user_id=?",[req.params.id,req.user.id]);res.json({ok:true});});

app.get("/api/wallet",auth,async(req,res)=>{await run("INSERT OR IGNORE INTO wallets(user_id,balance) VALUES(?,0)",[req.user.id]);res.json(await get("SELECT * FROM wallets WHERE user_id=?",[req.user.id]));});
app.post("/api/gifts",auth,async(req,res)=>{
  const creator=Number(req.body.creatorId), amount=Number(req.body.amount);
  if(!creator||amount<=0)return res.status(400).json({error:"Invalid gift"});
  await run("INSERT OR IGNORE INTO wallets(user_id,balance) VALUES(?,0)",[req.user.id]);
  const w=await get("SELECT * FROM wallets WHERE user_id=?",[req.user.id]);
  if(w.balance<amount)return res.status(400).json({error:"Insufficient balance"});
  await run("UPDATE wallets SET balance=balance-? WHERE user_id=?",[amount,req.user.id]);
  const creatorShare=amount*0.30, ownerShare=amount*0.70;
  await run("INSERT OR IGNORE INTO wallets(user_id,balance) VALUES(?,0)",[creator]);
  await run("UPDATE wallets SET balance=balance+? WHERE user_id=?",[creatorShare,creator]);
  const r=await run("INSERT INTO gifts(sender_id,creator_id,amount) VALUES(?,?,?)",[req.user.id,creator,amount]);
  res.json({id:r.id,gross:amount,creatorShare,ownerShare,note:"Development ledger; payment/payout integration required."});
});
app.post("/api/wallet/dev-credit",auth,async(req,res)=>{
  const amount=Number(req.body.amount); if(amount<=0)return res.status(400).json({error:"Invalid amount"});
  await run("INSERT OR IGNORE INTO wallets(user_id,balance) VALUES(?,0)",[req.user.id]);
  await run("UPDATE wallets SET balance=balance+? WHERE user_id=?",[amount,req.user.id]);
  res.json(await get("SELECT * FROM wallets WHERE user_id=?",[req.user.id]));
});

app.post("/api/reports",auth,async(req,res)=>{const r=await run("INSERT INTO reports(reporter_id,target_type,target_id,reason) VALUES(?,?,?,?)",[req.user.id,req.body.targetType,req.body.targetId,req.body.reason||""]);res.json({id:r.id});});

app.get("/api/admin/stats",auth,adminOnly,async(req,res)=>{
  const users=await get("SELECT COUNT(*) n FROM users"), videos=await get("SELECT COUNT(*) n FROM videos"), reports=await get("SELECT COUNT(*) n FROM reports WHERE status='open'");
  res.json({users:users.n,videos:videos.n,openReports:reports.n});
});
app.get("/api/admin/users",auth,adminOnly,async(req,res)=>res.json(await all("SELECT id,username,email,phone,is_admin,banned,created_at FROM users ORDER BY id DESC")));
app.post("/api/admin/users/:id/ban",auth,adminOnly,async(req,res)=>{await run("UPDATE users SET banned=? WHERE id=?",[req.body.banned?1:0,req.params.id]);res.json({ok:true});});
app.get("/api/admin/reports",auth,adminOnly,async(req,res)=>res.json(await all("SELECT * FROM reports ORDER BY id DESC")));

app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:"Server error"});});
init().then(()=>app.listen(PORT,()=>console.log(`Etho_tek running on port ${PORT}`)));
