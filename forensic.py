import sqlite3

conn = sqlite3.connect('forensic.db')
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT,
    filehash TEXT,
    upload_time TEXT
)
''')

conn.commit()
conn.close()

print("Database and table created successfully!")
