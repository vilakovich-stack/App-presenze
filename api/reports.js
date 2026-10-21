const admin=require('firebase-admin');
const crypto=require('node:crypto');
if(!admin.apps.length){
  if(!process.env.FIREBASE_SERVICE_ACCOUNT)throw Error('FIREBASE_SERVICE_ACCOUNT not configured');
  admin.initializeApp({credential:admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT))});
}
const db=admin.firestore();
const error=(res,status,msg)=>res.status(status).json({error:msg});
const hash=(pw,salt)=>crypto.scryptSync(pw,salt,64).toString('hex');
async function owner(req){const m=/^Bearer (.+)$/.exec(req.headers.authorization||'');if(!m)throw Error('unauthorized');const u=await admin.auth().verifyIdToken(m[1],true);if(!u.email_verified && process.env.REPORT_ADMIN_EMAIL)throw Error('unauthorized');if(!process.env.REPORT_ADMIN_EMAIL || u.email?.toLowerCase()!==process.env.REPORT_ADMIN_EMAIL.toLowerCase())throw Error('unauthorized');return u;}
module.exports=async(req,res)=>{
 res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');
 try{
 if(req.method==='POST'&&req.query.action==='unlock'){
   const {id,password}=req.body||{};if(typeof id!=='string'||!/^[-_a-zA-Z0-9]{32,80}$/.test(id)||typeof password!=='string'||password.length>256)return error(res,400,'Richiesta non valida');
   const ref=db.collection('privateReports').doc(id);let result;
   await db.runTransaction(async tx=>{const snap=await tx.get(ref);if(!snap.exists){result={status:404};return;}
     const x=snap.data(),now=Date.now();if(x.revoked||x.expiresAt<=now){result={status:410};return;}
     if(x.blockUntil>now){result={status:429};return;}
     const good=crypto.timingSafeEqual(Buffer.from(hash(password,x.salt),'hex'),Buffer.from(x.hash,'hex'));
     if(!good){const attempts=(x.attempts||0)+1;tx.update(ref,{attempts:attempts>=5?0:attempts,blockUntil:attempts>=5?now+15*60*1000:0});result={status:401};return;}
     tx.update(ref,{attempts:0,blockUntil:0});result={status:200,report:x.report};
   });
   if(result.status!==200)return error(res,result.status,result.status===429?'Troppi tentativi. Riprova più tardi.':'Link scaduto o password errata');
   return res.status(200).json({report:result.report});
 }
 const user=await owner(req);
 if(req.method==='POST'){
  const {password,expiresDays,report}=req.body||{};
  if(typeof password!=='string'||password.length<12||password.length>256||![1,7,30].includes(expiresDays))return error(res,400,'Password o scadenza non valida');
  if(!report||!Array.isArray(report.rows)||!Array.isArray(report.dates)||report.rows.length>800||report.dates.length>370)return error(res,400,'Report troppo grande');
  if(report.rows.some(r=>!Array.isArray(r.statuses)||r.statuses.length!==report.dates.length))return error(res,400,'Report non valido');
  const payload=JSON.stringify(report);if(Buffer.byteLength(payload)>650000)return error(res,413,'Report troppo grande');
  const id=crypto.randomBytes(24).toString('base64url'),salt=crypto.randomBytes(16).toString('hex');
  await db.collection('privateReports').doc(id).set({owner:user.uid,label:String(report.month||'Report').slice(0,80),salt,hash:hash(password,salt),report,createdAt:Date.now(),expiresAt:Date.now()+expiresDays*86400000,revoked:false,attempts:0,blockUntil:0});
  return res.status(201).json({id});
 }
 if(req.method==='GET'){
  const snaps=await db.collection('privateReports').where('owner','==',user.uid).limit(100).get();
  return res.json({items:snaps.docs.map(d=>({id:d.id,label:d.data().label,expiresAt:d.data().expiresAt,revoked:d.data().revoked||d.data().expiresAt<Date.now()})).sort((a,b)=>b.expiresAt-a.expiresAt)});
 }
 if(req.method==='DELETE'){
  const id=req.body?.id;if(typeof id!=='string')return error(res,400,'ID mancante');const ref=db.collection('privateReports').doc(id);const doc=await ref.get();if(!doc.exists||doc.data().owner!==user.uid)return error(res,404,'Non trovato');await ref.update({revoked:true,report:admin.firestore.FieldValue.delete()});return res.json({ok:true});
 }
 return error(res,405,'Metodo non supportato');
 }catch(e){if(e.message==='unauthorized')return error(res,403,'Accesso non autorizzato');console.error(e);return error(res,500,'Errore server');}
};
