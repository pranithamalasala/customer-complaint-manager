from flask import Flask, render_template, request, redirect, url_for, flash
from models import db, User, Complaint  # Added Complaint here
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration Successful! Please Login.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid Credentials')
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Pass the user's name to the dashboard
    return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- NEW: FILE COMPLAINT ROUTE ---
@app.route('/file_complaint', methods=['GET', 'POST'])
@login_required
def file_complaint():
    if request.method == 'POST':
        subject = request.form['subject']
        category = request.form['category']
        description = request.form['description']
        
        # Create the complaint and link it to the current user
        new_complaint = Complaint(
            subject=subject,
            category=category,
            description=description,
            user_id=current_user.id  # This links it to the logged-in user!
        )
        
        db.session.add(new_complaint)
        db.session.commit()
        flash('Complaint Submitted Successfully!')
        return redirect(url_for('dashboard'))
        
    return render_template('file_complaint.html')

if __name__ == '__main__':
    app.run(debug=True)