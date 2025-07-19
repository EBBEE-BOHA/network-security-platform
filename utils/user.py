from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import bcrypt

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='USER')  # USER or ADMIN
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f'<User {self.email}>'

    def set_password(self, password):
        """Hash and set the password"""
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    def check_password(self, password):
        """Check if the provided password matches the hash"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'is_active': self.is_active
        }

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scan_type = db.Column(db.String(10), nullable=False)  # 'file' or 'url'
    target_name = db.Column(db.String(500), nullable=False)  # filename or URL
    file_hash = db.Column(db.String(64), nullable=True)  # SHA256 hash for files
    scan_status = db.Column(db.String(20), default='pending')  # pending, scanning, completed, error
    result_status = db.Column(db.String(20), nullable=True)  # clean, threat, suspicious
    threats_found = db.Column(db.Integer, default=0)
    engines_count = db.Column(db.Integer, default=0)
    virustotal_id = db.Column(db.String(100), nullable=True)
    scan_results = db.Column(db.Text, nullable=True)  # JSON string of detailed results
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship('User', backref=db.backref('scans', lazy=True))

    def __repr__(self):
        return f'<ScanResult {self.id}: {self.target_name}>'

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'scan_type': self.scan_type,
            'target_name': self.target_name,
            'file_hash': self.file_hash,
            'scan_status': self.scan_status,
            'result_status': self.result_status,
            'threats_found': self.threats_found,
            'engines_count': self.engines_count,
            'virustotal_id': self.virustotal_id,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }
