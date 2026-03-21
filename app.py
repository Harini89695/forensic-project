from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from flask import send_file
from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import hashlib
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = "supersecretkey"

UPLOAD_FOLDER = "uploads"
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# -------------------------
# DATABASE SETUP
# -------------------------

def init_db():
    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS records (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        hash TEXT,
        upload_time TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT
    )
    """)

    # Create default admin if not exists
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            ("admin", "admin123")
        )

    conn.commit()
    conn.close()

init_db()

# -------------------------
# HELPER: Compute all hashes
# -------------------------

def compute_hashes(file_bytes):
    """Compute SHA-256, SHA-1, and MD5 hashes for given bytes."""
    return {
        "sha256": hashlib.sha256(file_bytes).hexdigest(),
        "sha1": hashlib.sha1(file_bytes).hexdigest(),
        "md5": hashlib.md5(file_bytes).hexdigest(),
    }

# -------------------------
# HOME
# -------------------------

@app.route("/")
def home():
    return render_template("index.html")

# -------------------------
# LOGIN
# -------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("forensic.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        )
        user = cursor.fetchone()
        conn.close()

        if user:
            session["user"] = username
            return redirect(url_for("home"))
        else:
            error = "Invalid username or password"

    return render_template("login.html", error=error)

# -------------------------
# LOGOUT
# -------------------------

@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))

# -------------------------
# UPLOAD
# -------------------------

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files["file"]

        if file and file.filename != "":
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    sha256.update(chunk)

            file_hash = sha256.hexdigest()
            upload_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            conn = sqlite3.connect("forensic.db")
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO records (filename, hash, upload_time) VALUES (?, ?, ?)",
                (file.filename, file_hash, upload_time)
            )
            conn.commit()
            conn.close()

            return redirect(url_for("logs"))

    return render_template("upload.html")

# -------------------------
# VERIFY
# -------------------------

@app.route("/verify", methods=["GET", "POST"])
def verify():
    if "user" not in session:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":
        file = request.files["file"]

        if file and file.filename != "":
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            sha256 = hashlib.sha256()
            with open(filepath, "rb") as f:
                while True:
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    sha256.update(chunk)

            file_hash = sha256.hexdigest()

            conn = sqlite3.connect("forensic.db")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT hash FROM records WHERE filename=?",
                (file.filename,)
            )
            record = cursor.fetchone()
            conn.close()

            if record:
                if file_hash == record[0]:
                    result = "File is Authentic"
                else:
                    result = "File has been Modified"
            else:
                result = "No record found for this file"

    return render_template("verify.html", result=result)

# -------------------------
# LOGS
# -------------------------

@app.route("/logs")
def logs():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM records")
    records = cursor.fetchall()
    conn.close()

    return render_template("logs.html", records=records)

# -------------------------
# REPORT (PDF)
# -------------------------

@app.route("/report")
def report():
    if "user" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("forensic.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM records")
    records = cursor.fetchall()
    conn.close()

    pdf_path = "report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)
    width, height = letter

    y = height - 40
    c.setFont("Helvetica", 10)

    c.drawString(200, y, "Digital Forensics Report")
    y -= 30

    for row in records:
        text = f"ID: {row[0]} | File: {row[1]} | Hash: {row[2][:20]}..."
        c.drawString(40, y, text)
        y -= 20

        if y < 40:
            c.showPage()
            y = height - 40

    c.save()

    return send_file(pdf_path, as_attachment=True)

# -------------------------
# FILE FINGERPRINT (Single & Compare)
# -------------------------

@app.route('/fingerprint', methods=['GET', 'POST'])
def fingerprint():
    if "user" not in session:
        return redirect(url_for("login"))

    file_info = None
    comparison_result = None

    if request.method == 'POST':
        # Check if comparing two files or single file
        file1 = request.files.get('file1')
        file2 = request.files.get('file2')
        single_file = request.files.get('file')

        if file1 and file2 and file1.filename != "" and file2.filename != "":
            # Compare two files
            bytes1 = file1.read()
            bytes2 = file2.read()

            hashes1 = compute_hashes(bytes1)
            hashes2 = compute_hashes(bytes2)

            match = (hashes1["sha256"] == hashes2["sha256"])

            comparison_result = {
                "file1_name": file1.filename,
                "file1_size": len(bytes1),
                "file1_hashes": hashes1,
                "file2_name": file2.filename,
                "file2_size": len(bytes2),
                "file2_hashes": hashes2,
                "match": match,
            }
        elif single_file and single_file.filename != "":
            # Single file fingerprint
            file_bytes = single_file.read()
            hashes = compute_hashes(file_bytes)

            file_info = {
                "name": single_file.filename,
                "sha256": hashes["sha256"],
                "sha1": hashes["sha1"],
                "md5": hashes["md5"],
                "size": len(file_bytes),
            }

    return render_template("fingerprint.html", file_info=file_info, comparison_result=comparison_result)

# -------------------------
# RUN APP
# -------------------------

if __name__ == "__main__":
    app.run(debug=True)

