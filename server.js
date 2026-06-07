const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const cloudinary = require('cloudinary').v2;
const dotenv = require('dotenv');
const fs = require('fs');

dotenv.config();

const app = express();

// ----- ค่าตั้งบัญชีผู้ใช้ (เก็บใน .env / Render เท่านั้น ไม่ฝังในโค้ด) -----
const APP_USERNAME = process.env.APP_USERNAME;
const APP_PASSWORD_HASH = process.env.APP_PASSWORD_HASH; // bcrypt hash (ดู scripts/hash-password.js)
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me';
const isProd = process.env.NODE_ENV === 'production';
const ANNIVERSARY_DATE = process.env.ANNIVERSARY_DATE; // วันครบรอบ ให้คุณแฟนเข้าแบบดูอย่างเดียว (เช่น 2024-02-14 หรือ 02-14)

if (!APP_USERNAME || !APP_PASSWORD_HASH) {
  console.warn('⚠️  ยังไม่ได้ตั้ง APP_USERNAME / APP_PASSWORD_HASH — จะล็อกอินไม่ได้จนกว่าจะตั้งค่า (ดู .env.example)');
}
if (!process.env.SESSION_SECRET) {
  console.warn('⚠️  ยังไม่ได้ตั้ง SESSION_SECRET — กรุณาตั้งค่าก่อนใช้งานจริง');
}
if (!ANNIVERSARY_DATE) {
  console.warn('⚠️  ยังไม่ได้ตั้ง ANNIVERSARY_DATE — โหมดเข้าสู่ระบบสำหรับคุณแฟนจะยังใช้ไม่ได้');
}

// โฟลเดอร์ไฟล์ชั่วคราวของ multer (สร้างให้แน่ใจว่ามีอยู่)
const UPLOAD_DIR = 'uploads';
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
const upload = multer({ dest: UPLOAD_DIR + '/' });

// ตั้งค่า Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUD_NAME || process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.API_KEY || process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.API_SECRET || process.env.CLOUDINARY_API_SECRET,
});

// ----- ความปลอดภัยพื้นฐาน -----
// ปิด CSP เพราะหน้าเว็บใช้สคริปต์ inline + CDN หลายตัว (ฟอนต์, ไอคอน, SweetAlert)
// ส่วน header ความปลอดภัยอื่น ๆ ของ helmet ยังเปิดอยู่
app.use(helmet({ contentSecurityPolicy: false }));

app.set('trust proxy', 1); // อยู่หลัง proxy ของ Render เพื่อให้ secure cookie ทำงาน
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    name: 'bunwadee.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: isProd, // ส่ง cookie เฉพาะ HTTPS เมื่อรันจริง
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 วัน
    },
  })
);

// ----- เข้าสู่ระบบ / ออกจากระบบ -----
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10, // ลองได้ 10 ครั้งต่อ 15 นาที กัน brute-force
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'พยายามเข้าสู่ระบบบ่อยเกินไป กรุณารอสักครู่แล้วลองใหม่' },
});

app.post('/login', loginLimiter, (req, res) => {
  if (!APP_USERNAME || !APP_PASSWORD_HASH) {
    return res.status(500).json({ error: 'ระบบยังไม่ได้ตั้งค่าบัญชีผู้ใช้' });
  }
  const { username, password } = req.body || {};
  const userOk = username === APP_USERNAME;
  // เทียบรหัสเสมอเพื่อลด timing attack
  const passOk = bcrypt.compareSync(String(password || ''), APP_PASSWORD_HASH);

  if (userOk && passOk) {
    req.session.user = { username, role: 'owner' };
    return res.json({ success: true });
  }
  return res.status(401).json({ error: 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง' });
});

// เข้าสู่ระบบสำหรับคุณแฟน: ใส่ "วันครบรอบ" ถูกต้องก็เข้าได้ (สิทธิ์ดูอย่างเดียว)
app.post('/login-partner', loginLimiter, (req, res) => {
  if (!ANNIVERSARY_DATE) {
    return res.status(500).json({ error: 'ระบบยังไม่ได้ตั้งค่าวันครบรอบ' });
  }
  const target = monthDay(ANNIVERSARY_DATE);
  const given = monthDay((req.body || {}).date);
  if (target && given && target === given) {
    req.session.user = { username: 'แฟน', role: 'partner' };
    return res.json({ success: true });
  }
  return res.status(401).json({ error: 'วันครบรอบไม่ถูกต้อง' });
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('bunwadee.sid');
    res.json({ success: true });
  });
});

// ----- ด่านตรวจล็อกอิน (กั้นทั้งเว็บ) -----
// ปล่อยผ่านเฉพาะหน้า/ไฟล์ที่จำเป็นก่อนล็อกอิน
const PUBLIC_PATHS = new Set(['/login.html', '/login', '/style.css', '/favicon.ico']);
// เส้นทางที่เป็น API → ถ้าไม่ล็อกอินให้ตอบ 401 (ไม่ใช่ redirect) เพื่อให้ frontend จัดการเองได้
const API_PREFIXES = ['/images', '/upload', '/delete', '/api/'];
const isApiRequest = (req) =>
  req.method !== 'GET' || API_PREFIXES.some((p) => req.path === p || req.path.startsWith(p));

app.use((req, res, next) => {
  if (req.session && req.session.user) {
    // ล็อกอินแล้วเข้าหน้า login → ส่งกลับหน้าหลัก
    if (req.path === '/login.html') return res.redirect('/');
    return next();
  }
  if (PUBLIC_PATHS.has(req.path)) return next();

  // ยังไม่ล็อกอิน: API ตอบ 401, ส่วนการเปิดหน้าเว็บให้ redirect ไปหน้า login
  if (isApiRequest(req)) {
    return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อน' });
  }
  return res.redirect('/login.html');
});

// ----- ไฟล์ static (ทุกอย่างใต้บรรทัดนี้ต้องล็อกอินแล้ว ยกเว้น whitelist ด้านบน) -----
app.use(express.static('public'));

// ----- ข้อมูลผู้ใช้ปัจจุบัน (ให้ frontend แสดงชื่อ + ซ่อนปุ่มตามสิทธิ์) -----
app.get('/api/me', (req, res) => {
  res.json({ username: req.session.user.username, role: req.session.user.role });
});

// ----- helper: แปลงชื่อที่ผู้ใช้ตั้ง เป็น slug ปลอดภัยสำหรับ public_id -----
function makeSlug(name) {
  return String(name || '')
    .normalize('NFC')
    .trim()
    .replace(/\s+/g, '-') // ช่องว่าง → -
    .replace(/[^\p{L}\p{N}_-]+/gu, '') // เก็บตัวอักษร/ตัวเลขทุกภาษา ตัดอักขระพิเศษ
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60) || 'image';
}

// ----- helper: ดึงเดือน-วัน จากสตริงวันที่ (รองรับ YYYY-MM-DD หรือ MM-DD) เทียบเฉพาะเดือน+วัน -----
function monthDay(str) {
  const parts = String(str || '').split(/\D+/).filter(Boolean).map(Number);
  if (parts.length < 2) return null;
  const mo = parts.length >= 3 ? parts[1] : parts[0];
  const day = parts.length >= 3 ? parts[2] : parts[1];
  if (!mo || !day || mo < 1 || mo > 12 || day < 1 || day > 31) return null;
  return mo + '-' + day;
}

// ----- middleware: เฉพาะเจ้าของ (owner) เท่านั้นที่อัปโหลด/ลบได้ คุณแฟนดูอย่างเดียว -----
function requireOwner(req, res, next) {
  if (req.session.user && req.session.user.role === 'owner') return next();
  return res.status(403).json({ error: 'เฉพาะเจ้าของเท่านั้นที่ทำรายการนี้ได้' });
}

// ----- helper: แปลง resource ของ Cloudinary → object ที่ frontend ใช้ -----
function toImage(resource, captionOverride) {
  const publicId = resource.public_id;
  const caption =
    captionOverride ||
    resource.context?.custom?.caption ||
    resource.context?.caption ||
    publicId.split('/').pop();

  const album =
    resource.context?.custom?.album ||
    resource.context?.album ||
    'ทั่วไป';

  // รูปย่อหลายขนาด (เล็กลง + บีบอัดแบบ eco) เพื่อให้โหลดเร็ว
  const thumbUrl = (w) =>
    cloudinary.url(publicId, {
      secure: true,
      transformation: [{ width: w, crop: 'limit', quality: 'auto:eco', fetch_format: 'auto' }],
    });

  return {
    public_id: publicId,
    display_name: caption,
    width: resource.width,
    height: resource.height,
    created_at: resource.created_at, // เวลาที่อัปโหลด (สำหรับ timeline)
    album: album,
    thumb: thumbUrl(480),
    srcset: [320, 480, 768].map((w) => `${thumbUrl(w)} ${w}w`).join(', '),
    // รูปเต็มสำหรับเปิดดู
    full: resource.secure_url || cloudinary.url(publicId, { secure: true }),
    // ลิงก์บังคับดาวน์โหลด พร้อมตั้งชื่อไฟล์ตามชื่อที่ตั้ง
    download: cloudinary.url(publicId, {
      secure: true,
      flags: 'attachment:' + makeSlug(caption),
    }),
  };
}

// อัปโหลดรูป (ต้องล็อกอินแล้ว — ผ่านด่านตรวจด้านบน)
app.post('/upload', requireOwner, upload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'ไม่มีไฟล์อัปโหลด' });

  const filePath = req.file.path;
  try {
    const niceName = String(req.body.filename || '').trim() || 'รูปภาพ';
    const album = String(req.body.album || '').trim() || 'ทั่วไป';
    const publicId = `bunwadee/${makeSlug(niceName)}-${Date.now().toString(36)}`;

    const result = await cloudinary.uploader.upload(filePath, {
      resource_type: 'image',
      format: 'jpg', // แปลง HEIC → JPG
      public_id: publicId,
      context: { caption: niceName, album: album }, // เก็บชื่อ + อัลบั้มที่ผู้ใช้ตั้ง
      overwrite: false,
    });

    fs.unlinkSync(filePath); // ลบไฟล์ชั่วคราว
    res.json({ success: true, ...toImage(result, niceName), album });
  } catch (err) {
    try { fs.unlinkSync(filePath); } catch (_) {}
    console.error(err);
    res.status(500).json({ error: 'Upload failed: ' + err.message });
  }
});

// ดึงรูปทั้งหมดจาก Cloudinary
app.get('/images', async (req, res) => {
  try {
    const result = await cloudinary.api.resources({
      resource_type: 'image',
      type: 'upload',
      context: true, // ขอ caption มาด้วย
      max_results: 100,
    });

    const images = result.resources.map((img) => toImage(img));
    res.json(images);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Cannot fetch images: ' + err.message });
  }
});

// ลบรูป (ต้องล็อกอินแล้ว) — รับ public_id ตรง ๆ จาก frontend
app.delete('/delete', requireOwner, async (req, res) => {
  const { public_id } = req.body || {};
  if (!public_id) return res.status(400).json({ error: 'Missing public_id' });

  try {
    const result = await cloudinary.uploader.destroy(public_id, { resource_type: 'image' });
    console.log('Cloudinary delete result:', result);

    if (result.result === 'ok') return res.json({ success: true });
    if (result.result === 'not found') return res.status(404).json({ error: 'ไฟล์ไม่พบบน Cloudinary' });
    return res.status(500).json({ error: 'ลบไม่สำเร็จ: ' + result.result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'ลบไฟล์ไม่สำเร็จ: ' + err.message });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
