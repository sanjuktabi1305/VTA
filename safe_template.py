# safe_template.py - CodeGuard corrected output (runnable & clean)
import os
import logging
import sqlite3
from typing import Iterable, Tuple, Any

logging.basicConfig(level=logging.INFO)

def get_user_info(user_id: str, conn: sqlite3.Connection) -> Iterable[Tuple[Any, ...]]:
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM users WHERE id = ?", (user_id,))
    return cur.fetchall()

def execute_query_safe(query: str, conn: sqlite3.Connection, params: Iterable[Any] = ()):
    cur = conn.cursor()
    cur.execute(query, params)
    conn.commit()
    logging.info("Executed database operation safely.")

def safe_function(x: int, y: int) -> int:
    return x * y

def main():
    db_path = os.getenv("DB_PATH", ":memory:")
    conn = sqlite3.connect(db_path)

    conn.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, name TEXT)")
    conn.execute("INSERT OR REPLACE INTO users (id, name) VALUES (?, ?)", ("1", "Alice"))
    conn.commit()

    user_input = input("Enter user ID: ").strip()
    rows = get_user_info(user_input, conn)
    logging.info("User info: %s", rows)

    result = safe_function(5, 7)
    logging.info("Result is %s", result)

    conn.close()

if __name__ == "__main__":
    main()
