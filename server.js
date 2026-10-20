const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/', rateLimit({ windowMs: 60_000, limit: 100, standardHeaders: 'draft-7', legacyHeaders: false }));
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.PGSSL === 'true' ? { rejectUnauthorized: false } : undefined });
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
if (process.env.NODE_ENV === 'production' && (!JWT_SECRET || JWT_SECRET.length < 32 || !ADMIN_EMAIL || ADMIN_PASSWORD.length < 12)) {
  console.warn('SECURITY CONFIG: set JWT_SECRET (32+ chars), ADMIN_EMAIL, and ADMIN_PASSWORD (12+ chars). Admin login will remain disabled until configured.');
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY, username VARCHAR(32) NOT NULL, email VARCHAR(254) NOT NULL UNIQUE,
      password_hash TEXT NOT NULL, ff_uid VARCHAR(32) NOT NULL UNIQUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS teams (
      id BIGSERIAL PRIMARY KEY, name VARCHAR(48) NOT NULL UNIQUE, captain_id BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS team_members (
      team_id BIGINT NOT NULL REFERENCES teams(id) ON DELETE CASCADE, player_id BIGINT NOT NULL REFERENCES players(id) ON DELETE CASCADE,
      role VARCHAR(16) NOT NULL DEFAULT 'member', joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY(team_id, player_id), UNIQUE(player_id)
    );
    CREATE TABLE IF NOT EXISTS tournaments (
      id BIGSERIAL PRIMARY KEY, title VARCHAR(100) NOT NULL, mode VARCHAR(12) NOT NULL CHECK(mode IN ('Solo','Duo','Squad')),
      map_name VARCHAR(40) NOT NULL DEFAULT 'Bermuda', starts_at TIMESTAMPTZ NOT NULL, slots INTEGER NOT NULL CHECK(slots BETWEEN 2 AND 500),
      prize_pool VARCHAR(80) NOT NULL DEFAULT 'Bragging rights', entry_fee_paise INTEGER NOT NULL DEFAULT 0 CHECK(entry_fee_paise >= 0),
      status VARCHAR(16) NOT NULL DEFAULT 'upcoming' CHECK(status IN ('upcoming','live','completed','cancelled')),
      room_id TEXT, room_password TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS registrations (
      id BIGSERIAL PRIMARY KEY, tournament_id BIGINT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
      player_id BIGINT REFERENCES players(id) ON DELETE CASCADE, team_id BIGINT REFERENCES teams(id) ON DELETE CASCADE,
      registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), CHECK ((player_id IS NOT NULL)::int + (team_id IS NOT NULL)::int = 1),
      UNIQUE(tournament_id, player_id), UNIQUE(tournament_id, team_id)
    );
    CREATE TABLE IF NOT EXISTS match_results (
      id BIGSERIAL PRIMARY KEY, tournament_id BIGINT NOT NULL REFERENCES tournaments(id) ON DELETE CASCADE,
      registration_id BIGINT NOT NULL REFERENCES registrations(id) ON DELETE CASCADE, placement INTEGER NOT NULL CHECK(placement > 0),
      kills INTEGER NOT NULL DEFAULT 0 CHECK(kills >= 0), points INTEGER NOT NULL DEFAULT 0 CHECK(points >= 0),
      UNIQUE(tournament_id, registration_id)
    );
    CREATE INDEX IF NOT EXISTS registrations_tournament_idx ON registrations(tournament_id);
    CREATE INDEX IF NOT EXISTS results_tournament_points_idx ON match_results(tournament_id, points DESC, placement ASC);
  `);
}
function signToken(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d', issuer: 'ff-arena' }); }
function auth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  if (!token || !JWT_SECRET) return res.status(401).json({ error: 'Please sign in first.' });
  try { req.user = jwt.verify(token, JWT_SECRET, { issuer: 'ff-arena' }); next(); }
  catch { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}
function admin(req, res, next) { auth(req, res, () => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin access required.' })); }
function str(v, max=100) { return typeof v === 'string' ? v.trim().slice(0, max) : ''; }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }

app.get('/api/health', async (_req, res) => {
  try { await pool.query('SELECT 1'); res.json({ ok: true, database: 'connected' }); }
  catch { res.status(503).json({ ok: false, database: 'unavailable' }); }
});
app.post('/api/register', async (req, res) => {
  try {
    const username = str(req.body.username, 32), email = str(req.body.email, 254).toLowerCase();
    const password = typeof req.body.password === 'string' ? req.body.password : '', ffUid = str(req.body.ffUid, 32);
    if (username.length < 3 || !/^[\p{L}\p{N}_ -]+$/u.test(username)) return res.status(400).json({ error: 'Name must be 3–32 letters, numbers, spaces or underscores.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 10 || password.length > 128) return res.status(400).json({ error: 'Password must be at least 10 characters.' });
    if (!/^\d{6,32}$/.test(ffUid)) return res.status(400).json({ error: 'Free Fire UID must contain 6–32 digits.' });
    const hash = await bcrypt.hash(password, 12);
    const q = await pool.query('INSERT INTO players(username,email,password_hash,ff_uid) VALUES($1,$2,$3,$4) RETURNING id,username,email,ff_uid', [username,email,hash,ffUid]);
    res.status(201).json({ player: q.rows[0], token: signToken({ sub: String(q.rows[0].id), role: 'player' }) });
  } catch (e) { if (e.code === '23505') return res.status(409).json({ error: 'That email or Free Fire UID is already registered.' }); console.error(e); res.status(500).json({ error: 'Could not create account.' }); }
});
app.post('/api/login', async (req, res) => {
  try {
    const email = str(req.body.email,254).toLowerCase(), password = typeof req.body.password === 'string' ? req.body.password : '';
    const q = await pool.query('SELECT id,username,email,ff_uid,password_hash FROM players WHERE email=$1', [email]);
    if (!q.rowCount || !(await bcrypt.compare(password, q.rows[0].password_hash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
    const p = q.rows[0]; res.json({ player: { id:p.id, username:p.username, email:p.email, ff_uid:p.ff_uid }, token: signToken({ sub:String(p.id), role:'player' }) });
  } catch(e) { console.error(e); res.status(500).json({ error:'Could not sign in.' }); }
});
app.post('/api/admin/login', async (req,res) => {
  if (!JWT_SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) return res.status(503).json({ error:'Admin login is not configured. Set ADMIN_EMAIL and a strong ADMIN_PASSWORD in the hosting dashboard.' });
  const email = str(req.body.email,254).toLowerCase(), password = typeof req.body.password === 'string' ? req.body.password : '';
  if (email !== ADMIN_EMAIL || password.length !== ADMIN_PASSWORD.length || !require('crypto').timingSafeEqual(Buffer.from(password), Buffer.from(ADMIN_PASSWORD))) return res.status(401).json({ error:'Admin credentials are incorrect.' });
  res.json({ token:signToken({sub:'admin',role:'admin'}), player:{username:'Administrator',role:'admin'} });
});
app.get('/api/me', auth, async (req,res) => {
  if (req.user.role === 'admin') return res.json({ player:{ username:'Administrator', role:'admin' } });
  const q = await pool.query('SELECT id,username,email,ff_uid FROM players WHERE id=$1',[req.user.sub]);
  if (!q.rowCount) return res.status(404).json({error:'Account not found.'}); res.json({player:q.rows[0]});
});
app.get('/api/tournaments', async (_req,res) => {
  try { const q = await pool.query(`SELECT t.id,t.title,t.mode,t.map_name,t.starts_at,t.slots,t.prize_pool,t.entry_fee_paise,t.status,COUNT(r.id)::int AS registered FROM tournaments t LEFT JOIN registrations r ON r.tournament_id=t.id GROUP BY t.id ORDER BY t.starts_at ASC`); res.json({tournaments:q.rows}); }
  catch(e) { console.error(e); res.status(500).json({error:'Could not load tournaments.'}); }
});
app.post('/api/tournaments', admin, async (req,res) => {
  try {
    const title=str(req.body.title,100), mode=str(req.body.mode,12), map=str(req.body.mapName||'Bermuda',40), prize=str(req.body.prizePool||'Bragging rights',80), slots=Number(req.body.slots), fee=Number(req.body.entryFeePaise||0), startsAt=new Date(req.body.startsAt);
    if (!title || !['Solo','Duo','Squad'].includes(mode) || !Number.isInteger(slots) || slots<2 || slots>500 || !Number.isFinite(fee) || fee<0 || !Number.isFinite(startsAt.getTime())) return res.status(400).json({error:'Check title, mode, slots, fee and start time.'});
    const q=await pool.query('INSERT INTO tournaments(title,mode,map_name,starts_at,slots,prize_pool,entry_fee_paise) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *',[title,mode,map,startsAt,slots,prize,fee]); res.status(201).json({tournament:q.rows[0]});
  } catch(e) { console.error(e); res.status(500).json({error:'Could not create tournament.'}); }
});
app.patch('/api/tournaments/:id', admin, async(req,res)=>{
  const status=str(req.body.status,16); if(!['upcoming','live','completed','cancelled'].includes(status)) return res.status(400).json({error:'Invalid status.'});
  try { const q=await pool.query('UPDATE tournaments SET status=$1,room_id=$2,room_password=$3 WHERE id=$4 RETURNING id,title,status,room_id,room_password',[status,str(req.body.roomId,80)||null,str(req.body.roomPassword,80)||null,req.params.id]); if(!q.rowCount)return res.status(404).json({error:'Tournament not found.'}); res.json({tournament:q.rows[0]}); }
  catch(e){console.error(e);res.status(500).json({error:'Could not update tournament.'});}
});
app.post('/api/teams', auth, async(req,res)=>{
  if(req.user.role!=='player')return res.status(403).json({error:'Player account required.'});
  const name=str(req.body.name,48); if(name.length<3)return res.status(400).json({error:'Team name must be at least 3 characters.'});
  const client=await pool.connect(); try { await client.query('BEGIN'); const tq=await client.query('INSERT INTO teams(name,captain_id) VALUES($1,$2) RETURNING *',[name,req.user.sub]); await client.query("INSERT INTO team_members(team_id,player_id,role) VALUES($1,$2,'captain')",[tq.rows[0].id,req.user.sub]); await client.query('COMMIT'); res.status(201).json({team:tq.rows[0]}); }
  catch(e){await client.query('ROLLBACK'); if(e.code==='23505')return res.status(409).json({error:'Team name is taken or you already belong to a team.'});console.error(e);res.status(500).json({error:'Could not create team.'});} finally{client.release();}
});
app.get('/api/teams/mine',auth,async(req,res)=>{if(req.user.role!=='player')return res.json({teams:[]});const q=await pool.query('SELECT t.id,t.name,t.captain_id,tm.role FROM teams t JOIN team_members tm ON tm.team_id=t.id WHERE tm.player_id=$1 ORDER BY t.created_at DESC',[req.user.sub]);res.json({teams:q.rows});});
app.post('/api/teams/:id/members',auth,async(req,res)=>{
  if(req.user.role!=='player')return res.status(403).json({error:'Player account required.'});const uid=str(req.body.ffUid,32);if(!/^\d{6,32}$/.test(uid))return res.status(400).json({error:'Enter a valid player UID.'});
  try{const t=await pool.query('SELECT id FROM teams WHERE id=$1 AND captain_id=$2',[req.params.id,req.user.sub]);if(!t.rowCount)return res.status(403).json({error:'Only the captain can add teammates.'});const p=await pool.query('SELECT id FROM players WHERE ff_uid=$1',[uid]);if(!p.rowCount)return res.status(404).json({error:'Player must register before joining a team.'});await pool.query("INSERT INTO team_members(team_id,player_id,role) VALUES($1,$2,'member')",[req.params.id,p.rows[0].id]);res.status(201).json({ok:true});}catch(e){if(e.code==='23505')return res.status(409).json({error:'Player already belongs to a team.'});console.error(e);res.status(500).json({error:'Could not add teammate.'});}
});
app.post('/api/tournaments/:id/join',auth,async(req,res)=>{
  if(req.user.role!=='player')return res.status(403).json({error:'Player account required.'});const client=await pool.connect();try{await client.query('BEGIN');const tq=await client.query('SELECT * FROM tournaments WHERE id=$1 FOR UPDATE',[req.params.id]);if(!tq.rowCount){await client.query('ROLLBACK');return res.status(404).json({error:'Tournament not found.'});}const t=tq.rows[0];if(t.status!=='upcoming'){await client.query('ROLLBACK');return res.status(400).json({error:'Registration is closed.'});}const own=await client.query('SELECT id FROM registrations WHERE tournament_id=$1 AND player_id=$2',[t.id,req.user.sub]);if(own.rowCount){await client.query('ROLLBACK');return res.status(409).json({error:'Already registered.'});}let teamId=null,playerId=req.user.sub;if(t.mode==='Solo'){teamId=null;}else{const tm=await client.query('SELECT t.id FROM teams t JOIN team_members m ON m.team_id=t.id WHERE m.player_id=$1',[req.user.sub]);if(!tm.rowCount){await client.query('ROLLBACK');return res.status(400).json({error:'Create or join a team first.'});}teamId=tm.rows[0].id;playerId=null;const count=await client.query('SELECT COUNT(*)::int n FROM team_members WHERE team_id=$1',[teamId]);const required=t.mode==='Duo'?2:4;if(count.rows[0].n<required){await client.query('ROLLBACK');return res.status(400).json({error:`Your ${t.mode} team needs ${required} registered members.`});}const registered=await client.query('SELECT id FROM registrations WHERE tournament_id=$1 AND team_id=$2',[t.id,teamId]);if(registered.rowCount){await client.query('ROLLBACK');return res.status(409).json({error:'Your team is already registered.'});}}
  const cnt=await client.query('SELECT COUNT(*)::int n FROM registrations WHERE tournament_id=$1',[t.id]);if(cnt.rows[0].n>=t.slots){await client.query('ROLLBACK');return res.status(409).json({error:'Tournament is full.'});}const ins=await client.query('INSERT INTO registrations(tournament_id,player_id,team_id) VALUES($1,$2,$3) RETURNING id,tournament_id,registered_at',[t.id,playerId,teamId]);await client.query('COMMIT');res.status(201).json({registration:ins.rows[0]});}catch(e){await client.query('ROLLBACK');console.error(e);res.status(500).json({error:'Could not register for tournament.'});}finally{client.release();}
});
app.get('/api/registrations/mine',auth,async(req,res)=>{if(req.user.role!=='player')return res.json({registrations:[]});const q=await pool.query(`SELECT r.id,r.registered_at,t.id tournament_id,t.title,t.mode,t.starts_at,t.status,t.map_name,CASE WHEN t.status IN ('live','completed') THEN t.room_id END room_id,CASE WHEN t.status IN ('live','completed') THEN t.room_password END room_password,COALESCE(tm.name,p.username) entrant FROM registrations r JOIN tournaments t ON t.id=r.tournament_id LEFT JOIN teams tm ON tm.id=r.team_id LEFT JOIN players p ON p.id=r.player_id WHERE p.id=$1 OR tm.id IN(SELECT team_id FROM team_members WHERE player_id=$1) ORDER BY t.starts_at`,[req.user.sub]);res.json({registrations:q.rows});});
app.get('/api/tournaments/:id/leaderboard',async(req,res)=>{try{const q=await pool.query(`SELECT r.id registration_id,COALESCE(tm.name,p.username,'Entrant') entrant,m.placement,m.kills,m.points FROM registrations r LEFT JOIN teams tm ON tm.id=r.team_id LEFT JOIN players p ON p.id=r.player_id LEFT JOIN match_results m ON m.registration_id=r.id AND m.tournament_id=r.tournament_id WHERE r.tournament_id=$1 ORDER BY m.points DESC NULLS LAST,m.placement ASC NULLS LAST,entrant ASC`,[req.params.id]);res.json({leaderboard:q.rows});}catch(e){console.error(e);res.status(500).json({error:'Could not load leaderboard.'});}});
app.get('/api/admin/registrations',admin,async(_req,res)=>{const q=await pool.query(`SELECT r.id,r.tournament_id,t.title,COALESCE(tm.name,p.username) entrant,COALESCE(p.ff_uid,'') ff_uid,r.registered_at FROM registrations r JOIN tournaments t ON t.id=r.tournament_id LEFT JOIN teams tm ON tm.id=r.team_id LEFT JOIN players p ON p.id=r.player_id ORDER BY t.starts_at,r.registered_at`);res.json({registrations:q.rows});});
app.post('/api/admin/results',admin,async(req,res)=>{const tournamentId=Number(req.body.tournamentId),registrationId=Number(req.body.registrationId),placement=Number(req.body.placement),kills=Number(req.body.kills),points=Number(req.body.points);if(![tournamentId,registrationId,placement,kills,points].every(Number.isInteger)||tournamentId<1||registrationId<1||placement<1||kills<0||points<0)return res.status(400).json({error:'Enter valid tournament, registration, placement, kills and points.'});try{const q=await pool.query(`INSERT INTO match_results(tournament_id,registration_id,placement,kills,points) SELECT $1,$2,$3,$4,$5 WHERE EXISTS(SELECT 1 FROM registrations WHERE id=$2 AND tournament_id=$1) ON CONFLICT(tournament_id,registration_id) DO UPDATE SET placement=EXCLUDED.placement,kills=EXCLUDED.kills,points=EXCLUDED.points RETURNING *`,[tournamentId,registrationId,placement,kills,points]);if(!q.rowCount)return res.status(400).json({error:'Registration does not belong to this tournament.'});res.json({result:q.rows[0]});}catch(e){console.error(e);res.status(500).json({error:'Could not save result.'});}});
app.get('/api/leaderboard',async(_req,res)=>{try{const q=await pool.query(`SELECT COALESCE(tm.name,p.username,'Entrant') entrant,SUM(m.points)::int points,SUM(m.kills)::int kills,COUNT(DISTINCT m.tournament_id)::int matches FROM match_results m JOIN registrations r ON r.id=m.registration_id LEFT JOIN teams tm ON tm.id=r.team_id LEFT JOIN players p ON p.id=r.player_id GROUP BY entrant ORDER BY points DESC,kills DESC,entrant ASC LIMIT 100`);res.json({leaderboard:q.rows});}catch(e){console.error(e);res.status(500).json({error:'Could not load leaderboard.'});}});
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
const port=Number(process.env.PORT)||3000;
initDb().then(()=>app.listen(port,'0.0.0.0',()=>console.log(`FF Arena listening on ${port}`))).catch(e=>{console.error('Database initialization failed:',e.message);process.exit(1);});
process.on('SIGTERM',async()=>{await pool.end();process.exit(0)});
