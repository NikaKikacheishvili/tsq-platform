const express=require("express");
const cookieParser=require("cookie-parser");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const rateLimit=require("express-rate-limit");
const Database=require("better-sqlite3");
const path=require("path");
const crypto=require("crypto");

const app=express(), db=new Database("tsq.db");
const JWT_SECRET=process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

db.exec(`
CREATE TABLE IF NOT EXISTS users(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 referral_code TEXT UNIQUE NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS transactions(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL,
 type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')),
 amount REAL NOT NULL CHECK(amount>0),
 status TEXT NOT NULL DEFAULT 'pending',
 created_at TEXT DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname,"public")));

const authLimiter=rateLimit({windowMs:15*60*1000,max:30});
function tokenFor(user){return jwt.sign({id:user.id},JWT_SECRET,{expiresIn:"2h"});}
function auth(req,res,next){
 try{
  const t=req.cookies.tsq_session;
  if(!t) return res.status(401).json({error:"ავტორიზაცია საჭიროა"});
  req.user=jwt.verify(t,JWT_SECRET);
  next();
 }catch(e){return res.status(401).json({error:"სესია ვადაგასულია"});}
}
function balance(userId){
 const row=db.prepare(`SELECT COALESCE(SUM(CASE WHEN type='deposit' AND status='approved' THEN amount ELSE 0 END),0)
 -COALESCE(SUM(CASE WHEN type='withdrawal' AND status='approved' THEN amount ELSE 0 END),0) bal
 FROM transactions WHERE user_id=?`).get(userId);
 return Number(row.bal.toFixed(2));
}

app.post("/api/register",authLimiter,(req,res)=>{
 const {name,email,password,referral}=req.body||{};
 if(!name||!email||!password||password.length<8) return res.status(400).json({error:"შეავსე ველები; პაროლი მინიმუმ 8 სიმბოლო"});
 try{
  const code=crypto.randomBytes(5).toString("hex").toUpperCase();
  const hash=bcrypt.hashSync(password,12);
  const info=db.prepare("INSERT INTO users(name,email,password_hash,referral_code) VALUES(?,?,?,?)").run(name,email.toLowerCase(),hash,code);
  const user={id:info.lastInsertRowid};
  res.cookie("tsq_session",tokenFor(user),{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict",maxAge:7200000});
  res.json({ok:true});
 }catch(e){res.status(400).json({error:"ეს ელფოსტა უკვე გამოყენებულია"});}
});

app.post("/api/login",authLimiter,(req,res)=>{
 const {email,password}=req.body||{};
 const u=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").toLowerCase());
 if(!u||!bcrypt.compareSync(password||"",u.password_hash)) return res.status(401).json({error:"ელფოსტა ან პაროლი არასწორია"});
 res.cookie("tsq_session",tokenFor(u),{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"strict",maxAge:7200000});
 res.json({ok:true});
});

app.post("/api/logout",(req,res)=>{res.clearCookie("tsq_session");res.json({ok:true});});

app.get("/api/me",auth,(req,res)=>{
 const u=db.prepare("SELECT id,name,email,referral_code,created_at FROM users WHERE id=?").get(req.user.id);
 res.json({...u,balance:balance(u.id),referralLink:`${req.protocol}://${req.get("host")}/?ref=${u.referral_code}`});
});

app.get("/api/transactions",auth,(req,res)=>{
 res.json(db.prepare("SELECT id,type,amount,status,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 50").all(req.user.id));
});

/* Real integrations should create a pending transaction only after
   a trusted payment provider confirms the payment server-to-server. */
app.post("/api/withdraw",auth,(req,res)=>{
 const amount=Number(req.body.amount);
 if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:"არასწორი თანხა"});
 if(amount>balance(req.user.id)) return res.status(400).json({error:"არასაკმარისი ბალანსი"});
 db.prepare("INSERT INTO transactions(user_id,type,amount,status) VALUES(?,?,?,'pending')").run(req.user.id,"withdrawal",amount);
 res.json({ok:true,message:"გატანის მოთხოვნა მიღებულია და ელოდება დადასტურებას"});
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("TSQ platform running on http://localhost:"+(process.env.PORT||3000)));
