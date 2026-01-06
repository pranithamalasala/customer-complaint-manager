from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), default='customer') # 'admin' or 'customer'
    
    # RELATIONSHIP: This lets us say "user.complaints" to get their list
    complaints = db.relationship('Complaint', backref='author', lazy=True)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False) # e.g., Electrical, Plumbing
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending') # Pending, Solved
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # FOREIGN KEY: This links the complaint to the specific User who filed it
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)