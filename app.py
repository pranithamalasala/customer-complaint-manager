from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime  # <--- Essential for the chat timestamps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'infomatic_secret_key_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ccms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    # Relationship to access comments written by this user
    # (Defined via backref in Comment, but accessible here)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), default='Low')
    status = db.Column(db.String(20), default='Pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    # Linked comments
    comments = db.relationship('Comment', backref='complaint', lazy=True)
    # Linked user who created it
    user = db.relationship('User', backref='complaints')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    
    # Link to user who wrote the comment
    user = db.relationship('User', backref='comments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_admin():
    with app.app_context():
        db.create_all()
        # Admin Account: Omkar
        if not User.query.filter_by(username='Omkar').first():
            hashed_pw = generate_password_hash('boss123', method='pbkdf2:sha256')
            admin = User(username='Omkar', password=hashed_pw, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print(">>> Admin Account Created: Omkar / boss123")

# --- ROUTES ---

@app.route('/')
def home():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'warning')
            return redirect(url_for('register'))
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw, is_admin=False)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('dashboard'))
        
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    my_complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    
    # Stats
    total = len(my_complaints)
    resolved = sum(1 for c in my_complaints if c.status == 'Resolved')
    pending = total - resolved
    
    return render_template('dashboard.html', complaints=my_complaints, total=total, resolved=resolved, pending=pending)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    all_complaints = Complaint.query.all()
    
    # Stats
    total = len(all_complaints)
    resolved = sum(1 for c in all_complaints if c.status == 'Resolved')
    pending = total - resolved
    high_priority = sum(1 for c in all_complaints if c.priority == 'High')
    
    return render_template('admin_dashboard.html', complaints=all_complaints, total=total, resolved=resolved, pending=pending, high_priority=high_priority)

@app.route('/file-complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    if request.method == 'POST':
        subject = request.form.get('subject')
        category = request.form.get('category')
        priority = request.form.get('priority')
        description = request.form.get('description')
        
        new_complaint = Complaint(user_id=current_user.id, subject=subject, category=category, priority=priority, description=description)
        db.session.add(new_complaint)
        db.session.commit()
        return redirect(url_for('dashboard'))
        
    return render_template('file_complaint.html')

# --- NEW: TICKET DETAIL & CHAT ROUTE ---
@app.route('/ticket/<int:id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(id):
    complaint = Complaint.query.get_or_404(id)
    
    # Handle New Comment
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            new_comment = Comment(content=content, user_id=current_user.id, complaint_id=complaint.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Reply posted successfully!', 'success')
            return redirect(url_for('ticket_detail', id=id))

    return render_template('ticket_detail.html', complaint=complaint)

# --- UPDATED: RESOLVE ROUTE (Redirects to detail view now) ---
@app.route('/resolve/<int:id>')
@login_required
def resolve_complaint(id):
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    complaint = Complaint.query.get_or_404(id)
    complaint.status = 'Resolved'
    db.session.commit()
    flash('Ticket marked as Resolved!', 'success')
    
    # Redirect back to the Ticket Detail page so they see the update
    return redirect(url_for('ticket_detail', id=id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_admin()
    app.run(debug=True)