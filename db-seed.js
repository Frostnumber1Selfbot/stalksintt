require('dotenv').config();
const crypto = require('crypto');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function seed() {
  const client = await pool.connect();
  try {
    // Seed admin user (frontend hardcodes stalksint@stalk.com / stalksint2026!)
    const adminHash = crypto.createHash('sha256').update('stalksint2026!').digest('hex');
    await client.query(
      `INSERT INTO admin_users (email, password_hash, role)
       VALUES ($1, $2, 'admin')
       ON CONFLICT (email) DO NOTHING`,
      ['stalksint@stalk.com', adminHash]
    );
    console.log('Admin user seeded: stalksint@stalk.com');

    // Seed admin from .env ADMIN_PASSWORD
    if (process.env.ADMIN_PASSWORD) {
      const envHash = crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD).digest('hex');
      await client.query(
        `INSERT INTO admin_users (email, password_hash, role)
         VALUES ($1, $2, 'admin')
         ON CONFLICT (email) DO NOTHING`,
        ['admin@stalksint.local', envHash]
      );
      console.log('Admin user seeded: admin@stalksint.local');
    }

    // Seed a demo license key
    await client.query(
      `INSERT INTO license_keys (key, status, owner_email, max_users, expires_at)
       VALUES ($1, 'active', 'demo@stalksint.local', 5, NOW() + INTERVAL '1 year')
       ON CONFLICT (key) DO NOTHING`,
      ['STALKSDEMO-2026-ABCD-EFGH']
    );
    console.log('Demo license key seeded: STALKSDEMO-2026-ABCD-EFGH');

    console.log('Seed complete.');
  } catch (err) {
    console.error('Seed failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

seed();
