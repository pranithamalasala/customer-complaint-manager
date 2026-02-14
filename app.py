import os
import pickle 
import csv
import io
from flask import make_response, jsonify # <--- NEW: For loading the AI brain
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'infomatic_secret_key_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ccms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CONFIG FOR FILE UPLOADS ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- NEW: LOAD THE AI MODEL ---
try:
    with open("model.pkl", "rb") as f:
        models = pickle.load(f)
        ai_category_model = models['category_model']
        ai_priority_model = models['priority_model']
    print(">>> AI MODELS LOADED SUCCESSFULLY 🧠")
except FileNotFoundError:
    print(">>> WARNING: model.pkl not found. Run train_model.py first!")
    ai_category_model = None
    ai_priority_model = None

# --- MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), default='Low')
    status = db.Column(db.String(20), default='Pending')
    image_file = db.Column(db.String(100), nullable=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='complaint', lazy=True)
    user = db.relationship('User', backref='complaints')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    complaint_id = db.Column(db.Integer, db.ForeignKey('complaint.id'), nullable=False)
    user = db.relationship('User', backref='comments')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def create_admin():
    with app.app_context():
        db.create_all()
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
        return redirect(url_for('admin_dashboard') if current_user.is_admin else url_for('dashboard'))
    return redirect(url_for('login'))
# --- REAL BACKEND ACTIONS ---

@app.route('/admin/export')
@login_required
def export_data():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))

    # 1. Get all tickets from the Real Database
    complaints = Complaint.query.all()

    # 2. Create a CSV in memory
    si = io.StringIO()
    cw = csv.writer(si)
    # Write Header
    cw.writerow(['ID', 'User', 'Subject', 'Category', 'Priority', 'Status', 'Date'])
    # Write Rows
    for c in complaints:
        cw.writerow([c.id, c.user.username, c.subject, c.category, c.priority, c.status, datetime.utcnow()])

    # 3. Create the real file response
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=InfoMatic_Real_Report.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/restart_service', methods=['POST'])
@login_required
def restart_service():
    if not current_user.is_admin:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    # REAL WORK: Reload the AI Models from disk
    global ai_category_model, ai_priority_model
    try:
        with open("model.pkl", "rb") as f:
            models = pickle.load(f)
            ai_category_model = models['category_model']
            ai_priority_model = models['priority_model']
        print(">>> SYSTEM RESTART: AI Models Reloaded Successfully.")
        return jsonify({'status': 'success', 'message': 'AI Models & Database Connection Refreshed.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/admin/get_logs')
@login_required
def get_logs():
    if not current_user.is_admin:
        return jsonify({'error': 'Unauthorized'}), 403
        
    # REAL WORK: Check System Health
    # 1. Check Database
    try:
        user_count = User.query.count()
        db_status = "Connected (Read/Write OK)"
    except:
        db_status = "Connection Error!"

    # 2. Check AI Model
    ai_status = "Active" if ai_category_model else "Offline (Model file missing)"

    # 3. Generate Real Log Report
    real_logs = f"""
    SYSTEM DIAGNOSTIC REPORT
    -------------------------
    Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    User: {current_user.username}
    
    [STATUS] Database: {db_status}
    [STATUS] User Count: {user_count} Users Registered
    [STATUS] AI Engine: {ai_status}
    [INFO]  Upload Folder: {app.config['UPLOAD_FOLDER']}
    """
    return jsonify({'logs': real_logs})
@app.route('/admin/create_user', methods=['POST'])
@login_required
def admin_create_user():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    username = request.form.get('username')
    password = request.form.get('password')
    role = request.form.get('role') # 'admin' or 'employee'
    
    if User.query.filter_by(username=username).first():
        flash('Username already exists.', 'warning')
        return redirect(url_for('admin_users'))
    
    # Create new user
    hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
    is_admin = True if role == 'admin' else False
    new_user = User(username=username, password=hashed_pw, is_admin=is_admin)

    db.session.add(new_user)
    db.session.commit()
    
    flash(f'User {username} created successfully!', 'success')
    return redirect(url_for('admin_users'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('admin_dashboard') if user.is_admin else url_for('dashboard'))
        else:
            flash('Invalid credentials.', 'danger')
    return render_template('login.html')
@app.route('/admin/users')
@login_required
def admin_users():
    # Security Check: Only Admins allowed
    if not current_user.is_admin:
        flash('Access Denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Fetch ALL users from the database
    all_users = User.query.all()
    
    return render_template('users.html', users=all_users)
# --- NEW ROUTES FOR ANALYTICS & SECURITY ---

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    return render_template('analytics.html')

@app.route('/admin/security')
@login_required
def admin_security():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Fetch the last 5 users to show in the "Live Logs"
    recent_users = User.query.order_by(User.id.desc()).limit(5).all()
    
    return render_template('security.html', users=recent_users)
@app.route('/history')
@login_required
def history():
    my_complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', complaints=my_complaints)

@app.route('/knowledge')
@login_required
def knowledge():
    return render_template('knowledge.html')
@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    new_username = request.form.get('username')
    
    # Check if username is taken
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user and existing_user.id != current_user.id:
        flash('Username already taken.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update DB
    current_user.username = new_username
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    current_pass = request.form.get('current_password')
    new_pass = request.form.get('new_password')
    
    # Verify old password
    if not check_password_hash(current_user.password, current_pass):
        flash('Incorrect current password.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Update Password
    current_user.password = generate_password_hash(new_pass, method='pbkdf2:sha256')
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('dashboard'))
@app.route('/admin/tickets')
@login_required
def admin_tickets():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Get ALL tickets
    all_complaints = Complaint.query.all()
    return render_template('tickets.html', complaints=all_complaints)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        secret_key = request.form.get('secret_key') # <--- Get the code user typed

        # --- 🔒 SECURITY LEVEL 1: DOMAIN CHECK ---
        if "@" not in username or username.split('@')[1] != "infomatic.com":
            flash('Access Denied! You must use a corporate email (@infomatic.com)', 'danger')
            return redirect(url_for('register'))

        # --- 🔒 SECURITY LEVEL 2: SECRET KEY CHECK ---
        # This is the "Password" shared only with employees
        CORRECT_CODE = "INFO-2026"
        
        if secret_key != CORRECT_CODE:
            flash('Access Denied! Incorrect Company Access Code.', 'danger')
            return redirect(url_for('register'))
        # ---------------------------------------------

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
    if current_user.is_admin: return redirect(url_for('admin_dashboard'))
    my_complaints = Complaint.query.filter_by(user_id=current_user.id).all()
    total = len(my_complaints)
    resolved = sum(1 for c in my_complaints if c.status == 'Resolved')
    pending = total - resolved
    return render_template('dashboard.html', complaints=my_complaints, total=total, resolved=resolved, pending=pending)

@app.route('/admin')
@login_required
def admin_dashboard():
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    
    query = request.args.get('q')
    if query:
        all_complaints = Complaint.query.join(User).filter(
            (Complaint.subject.contains(query)) | 
            (Complaint.category.contains(query)) | 
            (User.username.contains(query))
        ).all()
    else:
        all_complaints = Complaint.query.all()
    
    total = len(all_complaints)
    resolved = sum(1 for c in all_complaints if c.status == 'Resolved')
    pending = total - resolved
    high_priority = sum(1 for c in all_complaints if c.priority == 'High')
    categories = [c.category for c in all_complaints]
    category_counts = {x: categories.count(x) for x in set(categories)}
    
    return render_template('admin_dashboard.html', 
                           complaints=all_complaints, 
                           total=total, resolved=resolved, pending=pending, high_priority=high_priority,
                           category_counts=category_counts)

@app.route('/file-complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    if request.method == 'POST':
        subject = request.form.get('subject')
        description = request.form.get('description')
        
        # Get Manual Selection (Fallback)
        manual_category = request.form.get('category')
        manual_priority = request.form.get('priority')
        
        # --- AI PREDICTION MAGIC ---
        final_category = manual_category
        final_priority = manual_priority
        
        if ai_category_model and ai_priority_model:
            try:
                # Predict using the description
                pred_cat = ai_category_model.predict([description])[0]
                pred_prio = ai_priority_model.predict([description])[0]
                
                print(f">>> AI PREDICTION: '{description}' -> {pred_cat} / {pred_prio}")
                
                # OVERRIDE the manual selection with AI prediction
                final_category = pred_cat
                final_priority = pred_prio
                flash(f'AI Auto-detected: {final_category} Category & {final_priority} Priority!', 'info')
            except Exception as e:
                print(f"AI Error: {e}")

        # Handle File Upload
        image_filename = None
        if 'file' in request.files:
            file = request.files['file']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                timestamped_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], timestamped_name))
                image_filename = timestamped_name
        
        new_complaint = Complaint(user_id=current_user.id, subject=subject, category=final_category, 
                                  priority=final_priority, description=description, image_file=image_filename)
        db.session.add(new_complaint)
        db.session.commit()
        return redirect(url_for('dashboard'))
        
    return render_template('file_complaint.html')

@app.route('/ticket/<int:id>', methods=['GET', 'POST'])
@login_required
def ticket_detail(id):
    complaint = Complaint.query.get_or_404(id)
    if request.method == 'POST':
        content = request.form.get('content')
        if content:
            new_comment = Comment(content=content, user_id=current_user.id, complaint_id=complaint.id)
            db.session.add(new_comment)
            db.session.commit()
            flash('Reply posted!', 'success')
            return redirect(url_for('ticket_detail', id=id))
    return render_template('ticket_detail.html', complaint=complaint)

@app.route('/resolve/<int:id>')
@login_required
def resolve_complaint(id):
    if not current_user.is_admin: return redirect(url_for('dashboard'))
    complaint = Complaint.query.get_or_404(id)
    complaint.status = 'Resolved'
    db.session.commit()
    flash('Resolved!', 'success')
    return redirect(url_for('ticket_detail', id=id))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    create_admin()
    app.run(debug=True)
