import sqlite3

from config import DATABASE_PATH

def get_connection():

connection = sqlite3.connect(
    DATABASE_PATH
)

connection.row_factory = sqlite3.Row

return connection
def initialize_database():

connection = get_connection()

connection.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP
    )
""")

connection.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        findings TEXT NOT NULL,
        created_at TIMESTAMP
            DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id)
            REFERENCES users(id)
    )
""")

connection.commit()
connection.close()
def create_user(
username,
email,
password_hash,
role="user"
):

connection = get_connection()

try:

    cursor = connection.execute(
        """
        INSERT INTO users
        (username, email, password_hash, role)
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            email,
            password_hash,
            role
        )
    )

    connection.commit()

    return cursor.lastrowid

except sqlite3.IntegrityError:

    return None

finally:

    connection.close()
def get_user_by_username(username):

connection = get_connection()

user = connection.execute(
    """
    SELECT *
    FROM users
    WHERE username = ?
    """,
    (username,)
).fetchone()

connection.close()

return user
def get_user_by_email(email):

connection = get_connection()

user = connection.execute(
    """
    SELECT *
    FROM users
    WHERE email = ?
    """,
    (email,)
).fetchone()

connection.close()

return user
def get_user_by_id(user_id):

connection = get_connection()

user = connection.execute(
    """
    SELECT *
    FROM users
    WHERE id = ?
    """,
    (user_id,)
).fetchone()

connection.close()

return user
def save_scan(
user_id,
scan_type,
target,
risk_level,
risk_score,
findings
):

connection = get_connection()

cursor = connection.execute(
    """
    INSERT INTO scans
    (
        user_id,
        scan_type,
        target,
        risk_level,
        risk_score,
        findings
    )
    VALUES (?, ?, ?, ?, ?, ?)
    """,
    (
        user_id,
        scan_type,
        target,
        risk_level,
        risk_score,
        findings
    )
)

connection.commit()

scan_id = cursor.lastrowid

connection.close()

return scan_id
def get_user_scans(user_id):

connection = get_connection()

scans = connection.execute(
    """
    SELECT *
    FROM scans
    WHERE user_id = ?
    ORDER BY created_at DESC
    """,
    (user_id,)
).fetchall()

connection.close()

return scans
def get_scan(scan_id, user_id):

connection = get_connection()

scan = connection.execute(
    """
    SELECT *
    FROM scans
    WHERE id = ?
    AND user_id = ?
    """,
    (
        scan_id,
        user_id
    )
).fetchone()

connection.close()

return scan
def get_all_users():

connection = get_connection()

users = connection.execute(
    """
    SELECT *
    FROM users
    ORDER BY created_at DESC
    """
).fetchall()

connection.close()

return users
def get_all_scans():

connection = get_connection()

scans = connection.execute(
    """
    SELECT
        scans.*,
        users.username
    FROM scans
    JOIN users
        ON scans.user_id = users.id
    ORDER BY scans.created_at DESC
    """
).fetchall()

connection.close()

return scans
def get_statistics():

connection = get_connection()

users = connection.execute(
    "SELECT COUNT(*) FROM users"
).fetchone()[0]

scans = connection.execute(
    "SELECT COUNT(*) FROM scans"
).fetchone()[0]

high_risk = connection.execute(
    """
    SELECT COUNT(*)
    FROM scans
    WHERE risk_level IN ('High', 'Critical')
    """
).fetchone()[0]

url_scans = connection.execute(
    """
    SELECT COUNT(*)
    FROM scans
    WHERE scan_type = 'URL'
    """
).fetchone()[0]

file_scans = connection.execute(
    """
    SELECT COUNT(*)
    FROM scans
    WHERE scan_type = 'File'
    """
).fetchone()[0]

connection.close()

return {
    "users": users,
    "scans": scans,
    "high_risk": high_risk,
    "url_scans": url_scans,
    "file_scans": file_scans
}
