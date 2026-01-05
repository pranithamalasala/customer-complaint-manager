from app import app
from models import db, User

with app.app_context():
    # Check if admin exists
    if not User.query.filter_by(username='admin').first():
        user = User(username='admin', password='admin123', role='admin')
        db.session.add(user)
        db.session.commit()
        print("✅ SUCCESS: Admin user created.")
    else:
        print("ℹ️ Admin user already exists.")