import sqlite3

def init_db():
    conn = sqlite3.connect('panel.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            uuid TEXT UNIQUE,
            protocol TEXT,
            traffic_limit INTEGER DEFAULT 0,
            traffic_used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def add_user_to_db(email, uuid, protocol):
    conn = sqlite3.connect('panel.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (email, uuid, protocol) VALUES (?, ?, ?)", (email, uuid, protocol))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()
