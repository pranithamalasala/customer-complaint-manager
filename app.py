from flask import Flask, render_template
from models import db

app = Flask(__name__)

# Settings
app.config['SECRET_KEY'] = 'secretkey123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Connect the Database
db.init_app(app)

@app.route('/')
def home():
    return render_template('base.html')

# This part runs the app and creates the DB
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)