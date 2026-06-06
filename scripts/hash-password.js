// สร้าง bcrypt hash จากรหัสผ่าน เพื่อนำไปใส่ APP_PASSWORD_HASH ใน .env
//
// วิธีใช้:
//   node scripts/hash-password.js "รหัสผ่านของคุณ"
//   (หรือ)  npm run hash -- "รหัสผ่านของคุณ"
//
// แล้วคัดลอกบรรทัด APP_PASSWORD_HASH=... ที่ได้ ไปใส่ใน .env (และตั้งใน Render ด้วย)

const bcrypt = require('bcryptjs');

const password = process.argv[2];

if (!password) {
  console.error('\n❌ กรุณาใส่รหัสผ่าน เช่น:');
  console.error('   node scripts/hash-password.js "myStrongPass"\n');
  process.exit(1);
}

const hash = bcrypt.hashSync(password, 12);

console.log('\n✅ คัดลอกบรรทัดด้านล่างไปใส่ใน .env (และตั้งใน Render dashboard ด้วย):\n');
console.log('APP_PASSWORD_HASH=' + hash + '\n');
