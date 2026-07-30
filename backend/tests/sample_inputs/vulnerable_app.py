"""Sample vulnerable Python file for Pipeline A end-to-end testing."""
import os
import sqlite3
import subprocess

# HARDCODED SECRET (intentional for testing)
API_KEY = "sk-live-abc123def456ghi789jklmno"
DB_PASSWORD = "admin123!"

def get_user(username):
    # SQL INJECTION VULNERABILITY
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def run_report(report_name):
    # COMMAND INJECTION VULNERABILITY
    output = subprocess.run(f"generate_report {report_name}", shell=True, capture_output=True)
    return output.stdout

def read_file(filename):
    # PATH TRAVERSAL VULNERABILITY
    base_dir = "/app/reports/"
    filepath = base_dir + filename  # No validation
    with open(filepath, "r") as f:
        return f.read()

def login(username, password):
    # HARDCODED CREDENTIALS
    if password == "supersecret":
        return True
    user = get_user(username)
    return user is not None
