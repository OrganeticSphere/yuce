"""Orders of a small shop."""
import sqlite3


def open_db(path):
    return sqlite3.connect(path)


def order_by_id(conn, order_id):
    query = "SELECT * FROM orders WHERE id = ?"
    return conn.execute(query, (order_id,)).fetchone()
