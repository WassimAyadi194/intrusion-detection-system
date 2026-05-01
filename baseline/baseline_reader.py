# baseline/baseline_reader.py
"""
Read-only access to the baseline table stored in SQLite.

"""

import sqlite3
from logs.ids_logger import get_logger

from config import DB_NAME


log = get_logger(__name__)

def get_all_baselines() -> dict[str, dict]:
    """
    Return every row currently stored in the ``baseline`` table.
    Returns an empty dict when the table is empty or the database file does not yet exist.
    
    """
    try:
        with sqlite3.connect(DB_NAME, timeout=5) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM baseline ORDER BY host_ip ASC")
            rows = cursor.fetchall()
    except sqlite3.Error as e:
        log.error(f"Database error while reading baseline: {e}")
        return {}

    return {row["host_ip"]: dict(row) for row in rows}
