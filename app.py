from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User 

app = Flask(__name__)

# --- SETTINGS ---
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# --- SETUP TOOLS ---
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

# 👇👇👇 NEW REGISTRATION CODE STARTS HERE 👇👇👇
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 1. Get the data
        username = request.form['username']
        password = request.form['password']

        # 2. Check if username is taken
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Choose a different one.')
            return redirect(url_for('register'))

        # 3. Create new user and save to DB
        new_user = User(username=username, password=password, role='customer')
        db.session.add(new_user)
        db.session.commit()
        
        flash('Account created! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')
# 👆👆👆 NEW REGISTRATION CODE ENDS HERE 👆👆👆

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user) 
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required 
def dashboard():
    return f"<h1>Welcome, {current_user.username}!</h1> <a href='/logout'>Logout</a>"

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)