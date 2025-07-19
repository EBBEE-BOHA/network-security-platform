import sqlite3
import hashlib
import bcrypt
from datetime import datetime
import os

DATABASE_PATH = "data/app.db"

def init_database():
    """Initialize the SQLite database with required tables."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create scans table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_type TEXT NOT NULL,  -- 'file' or 'url'
            target TEXT NOT NULL,     -- filename or URL
            file_hash TEXT,           -- for files
            analysis_id TEXT,         -- VirusTotal analysis ID
            status TEXT DEFAULT 'pending',  -- 'pending', 'completed', 'error'
            malicious_count INTEGER DEFAULT 0,
            suspicious_count INTEGER DEFAULT 0,
            clean_count INTEGER DEFAULT 0,
            result_summary TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def create_user(username, email, password, role='user'):
    """
    Create a new user in the database.
    
    Args:
        username: User's username
        email: User's email
        password: Plain text password (will be hashed)
        role: User role (default: 'user')
        
    Returns:
        dict: Success/error message
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        # Hash the password
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, role))
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "User created successfully"}
    except sqlite3.IntegrityError as e:
        return {"success": False, "message": "Username or email already exists"}
    except Exception as e:
        return {"success": False, "message": str(e)}

def authenticate_user(username, password):
    """
    Authenticate a user.
    
    Args:
        username: User's username
        password: Plain text password
        
    Returns:
        dict: User info if successful, None if failed
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, password_hash, role
            FROM users WHERE username = ?
        ''', (username,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            return {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[4]
            }
        return None
    except Exception as e:
        print(f"Authentication error: {e}")
        return None

def get_user_by_id(user_id):
    """Get user information by ID."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, email, role
            FROM users WHERE id = ?
        ''', (user_id,))
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            return {
                "id": user[0],
                "username": user[1],
                "email": user[2],
                "role": user[3]
            }
        return None
    except Exception as e:
        print(f"Error getting user: {e}")
        return None

def save_scan_result(user_id, scan_type, target, file_hash=None, analysis_id=None, 
                    status='pending', malicious_count=0, suspicious_count=0, 
                    clean_count=0, result_summary=None):
    """
    Save scan result to database.
    
    Args:
        user_id: ID of the user who initiated the scan
        scan_type: 'file' or 'url'
        target: filename or URL
        file_hash: hash of the file (for file scans)
        analysis_id: VirusTotal analysis ID
        status: scan status
        malicious_count: number of engines that detected malware
        suspicious_count: number of engines that found suspicious content
        clean_count: number of engines that found it clean
        result_summary: summary of the scan results
        
    Returns:
        int: ID of the created scan record
    """
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans (user_id, scan_type, target, file_hash, analysis_id,
                             status, malicious_count, suspicious_count, clean_count, result_summary)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, scan_type, target, file_hash, analysis_id, status,
              malicious_count, suspicious_count, clean_count, result_summary))
        
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return scan_id
    except Exception as e:
        print(f"Error saving scan result: {e}")
        return None

def update_scan_result(scan_id, status=None, malicious_count=None, 
                      suspicious_count=None, clean_count=None, result_summary=None, analysis_id=None):
    """Update an existing scan result."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        updates = []
        values = []
        
        if status is not None:
            updates.append("status = ?")
            values.append(status)
        if malicious_count is not None:
            updates.append("malicious_count = ?")
            values.append(malicious_count)
        if suspicious_count is not None:
            updates.append("suspicious_count = ?")
            values.append(suspicious_count)
        if clean_count is not None:
            updates.append("clean_count = ?")
            values.append(clean_count)
        if result_summary is not None:
            updates.append("result_summary = ?")
            values.append(result_summary)
        if analysis_id is not None:
           updates.append("analysis_id = ?")
           values.append(analysis_id)
    
        
        if updates:
            values.append(scan_id)
            query = f"UPDATE scans SET {', '.join(updates)} WHERE id = ?"
            cursor.execute(query, values)
            conn.commit()
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating scan result: {e}")
        return False

def get_user_scans(user_id, limit=50):
    """Get recent scans for a user."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, scan_type, target, status, malicious_count, 
                   suspicious_count, clean_count, created_at
            FROM scans 
            WHERE user_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        ''', (user_id, limit))
        
        scans = cursor.fetchall()
        conn.close()
        
        return [
            {
                "id": scan[0],
                "scan_type": scan[1],
                "target": scan[2],
                "status": scan[3],
                "malicious_count": scan[4],
                "suspicious_count": scan[5],
                "clean_count": scan[6],
                "created_at": scan[7]
            }
            for scan in scans
        ]
    except Exception as e:
        print(f"Error getting user scans: {e}")
        return []

def get_scan_by_id(scan_id):
    """Get a specific scan by ID."""
    try:
        conn = sqlite3.connect(DATABASE_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, user_id, scan_type, target, file_hash, analysis_id,
                   status, malicious_count, suspicious_count, clean_count,
                   result_summary, created_at
            FROM scans WHERE id = ?
        ''', (scan_id,))
        
        scan = cursor.fetchone()
        conn.close()
        
        if scan:
            return {
                "id": scan[0],
                "user_id": scan[1],
                "scan_type": scan[2],
                "target": scan[3],
                "file_hash": scan[4],
                "analysis_id": scan[5],
                "status": scan[6],
                "malicious_count": scan[7],
                "suspicious_count": scan[8],
                "clean_count": scan[9],
                "result_summary": scan[10],
                "created_at": scan[11]
            }
        return None
    except Exception as e:
        print(f"Error getting scan: {e}")
        return None

def calculate_file_hash(file_content):
    """Calculate SHA256 hash of file content."""
    return hashlib.sha256(file_content).hexdigest()

# Initialize database when module is imported
if not os.path.exists("data"):
    os.makedirs("data")
init_database()

