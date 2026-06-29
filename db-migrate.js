require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

async function migrate() {
  const c = await pool.connect();
  try {
    await c.query('BEGIN');

    await c.query(`CREATE TABLE IF NOT EXISTS license_keys (
      id SERIAL PRIMARY KEY,
      key VARCHAR(255) UNIQUE NOT NULL,
      status VARCHAR(50) DEFAULT 'active',
      owner_email VARCHAR(255),
      ip_lock VARCHAR(45),
      max_users INTEGER DEFAULT 1,
      expires_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS app_users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255),
      license_key_id INTEGER REFERENCES license_keys(id) ON DELETE SET NULL,
      ip_address VARCHAR(45),
      last_login TIMESTAMP,
      is_active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS admin_users (
      id SERIAL PRIMARY KEY,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      role VARCHAR(50) DEFAULT 'admin',
      created_at TIMESTAMP DEFAULT NOW(),
      last_login TIMESTAMP
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS search_logs (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES app_users(id) ON DELETE SET NULL,
      search_type VARCHAR(50),
      query TEXT,
      endpoint VARCHAR(255),
      status_code INTEGER,
      response_size INTEGER,
      ip_address VARCHAR(45),
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS user_sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      user_type VARCHAR(20) DEFAULT 'app',
      session_token VARCHAR(255) UNIQUE NOT NULL,
      ip_address VARCHAR(45),
      user_agent TEXT,
      expires_at TIMESTAMP NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query(`CREATE TABLE IF NOT EXISTS key_events (
      id SERIAL PRIMARY KEY,
      license_key_id INTEGER REFERENCES license_keys(id) ON DELETE CASCADE,
      action VARCHAR(50) NOT NULL,
      detail TEXT,
      ip_address VARCHAR(45),
      performed_by VARCHAR(255),
      created_at TIMESTAMP DEFAULT NOW()
    )`);

    await c.query('COMMIT');
    console.log('All tables migrated successfully.');
  } catch (e) {
    await c.query('ROLLBACK');
    console.error('Migration failed:', e.message);
    process.exit(1);
  } finally {
    c.release();
    await pool.end();
  }
}
migrate();
