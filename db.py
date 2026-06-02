import hashlib
import binascii
import os
import secrets

from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set. Add it to your .env file (Supabase connection string).")

ITERATIONS = 100_000
SALT_BYTES = 16
HASH_BYTES = 32

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_NAME = os.getenv("ADMIN_NAME", "Yosan Admin").strip() or "Yosan Admin"


def get_conn():
    import psycopg2
    from psycopg2.extras import RealDictCursor

    return psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)


def generate_salt() -> str:
    return binascii.hexlify(secrets.token_bytes(SALT_BYTES)).decode()


def hash_password(password: str, salt_hex: str) -> str:
    salt = binascii.unhexlify(salt_hex.encode())
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, ITERATIONS, dklen=HASH_BYTES
    )
    return binascii.hexlify(dk).decode()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    return hash_password(password, salt_hex) == stored_hash


def init_db():
    conn = get_conn()
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS admins (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS login_logs (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            name TEXT,
            status TEXT NOT NULL,
            ip TEXT,
            logged_at TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS login_bans (
            id SERIAL PRIMARY KEY,
            email TEXT,
            ip TEXT,
            reason TEXT,
            banned_by TEXT,
            banned_at TIMESTAMPTZ DEFAULT NOW(),
            active BOOLEAN NOT NULL DEFAULT TRUE
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS motion_events (
            id SERIAL PRIMARY KEY,
            start_time TEXT NOT NULL,
            end_time TEXT,
            duration_seconds DOUBLE PRECISION
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS user_activities (
            id SERIAL PRIMARY KEY,
            email TEXT NOT NULL,
            action TEXT NOT NULL,
            timestamp TIMESTAMPTZ DEFAULT NOW()
        )
        """
    )
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            id SERIAL PRIMARY KEY,
            jti TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    cursor.execute("DELETE FROM revoked_tokens WHERE expires_at <= NOW()")
    conn.commit()
    _ensure_default_admin(cursor)
    conn.commit()
    conn.close()


def _ensure_default_admin(cursor):
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return
    cursor.execute("SELECT id FROM admins WHERE email = %s", (ADMIN_EMAIL,))
    if cursor.fetchone():
        return
    salt = generate_salt()
    pw_hash = hash_password(ADMIN_PASSWORD, salt)
    cursor.execute(
        "INSERT INTO admins (name, email, password_hash, salt) VALUES (%s, %s, %s, %s)",
        (ADMIN_NAME, ADMIN_EMAIL, pw_hash, salt),
    )


init_db()
