import sqlite3
import json
from config import DB_FILE, logger  # Import constants and logger from config

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            ioc TEXT PRIMARY KEY,
            data TEXT,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            command TEXT,
            result TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.exception(f"Error initializing database: {e}")

def store_ioc_data(ioc_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        ioc = ioc_data.get("ioc")
        data_json = json.dumps(ioc_data)
        cursor.execute("""
        INSERT OR REPLACE INTO iocs (ioc, data, last_updated)
        VALUES (?, ?, CURRENT_TIMESTAMP)
        """, (ioc, data_json))
        conn.commit()
        conn.close()
        logger.info(f"Stored IOC data for {ioc}.")
    except Exception as e:
        logger.exception(f"Error storing IOC data: {e}")

def update_cache(ioc, new_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
        UPDATE iocs SET data = ?, last_updated = CURRENT_TIMESTAMP WHERE ioc = ?
        """, (json.dumps(new_data), ioc))
        conn.commit()
        conn.close()
        logger.info(f"Cache updated for {ioc}.")
    except Exception as e:
        logger.exception(f"Error updating cache for {ioc}: {e}")

def store_user_logs(user_id, command, result):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
        INSERT INTO user_logs (user_id, command, result)
        VALUES (?, ?, ?)
        """, (user_id, command, json.dumps(result)))
        conn.commit()
        conn.close()
        logger.info(f"Stored user log for {user_id} -> {command}")
    except Exception as e:
        logger.exception(f"Error storing user logs: {e}")