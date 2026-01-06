from app import app
from models import db, User, Complaint

with app.app_context():
    db.create_all()
    print("✅ Database Tables Created (User & Complaint)!")