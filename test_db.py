import sqlite3
from datetime import datetime

# Connect to forensic database
conn = sqlite3.connect("forensic.db")
cursor = conn.cursor()

# Insert test record
cursor.execute("""
INSERT INTO files (filename, filehash, upload_time)
VALUES (?, ?, ?)
""", ("sample.txt", "123abc", datetime.now().strftime("%Y-%m-%d %H:%M:%S")))

conn.commit()

# Check inserted data
cursor.execute("SELECT * FROM files")
rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()
