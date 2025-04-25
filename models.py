from datetime import datetime
from flask_login import UserMixin
from app import db


class User(UserMixin, db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    salt = db.Column(db.String(64), nullable=False)
    passwords = db.relationship('Password', backref='owner', lazy=True, cascade='all, delete-orphan')

    def __repr__(self):
        return f'<User {self.username}>'


class Password(db.Model):
    """Password model for storing encrypted password entries"""
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(128), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)
    iv = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Password {self.url} - {self.username}>'
