import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Strong secret key for sessions
# Correct path for SQLite DB to be inside 'instance' folder relative to 'app.py'
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(app.instance_path, 'site.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Database Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False) # Increased length for stronger hashes
    role = db.Column(db.String(20), nullable=False, default='user') # 'user' or 'admin'

    def __repr__(self):
        return f'<User {self.username}>'

# --- Decorators for Route Protection ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: # Should be covered by @login_required if stacked, but good for direct use
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login', next=request.url))
        if session.get('role') != 'admin':
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('dashboard')) # Or to an 'unauthorized' page
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session: # If already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if not username or not email or not password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Check for existing username or email
        existing_user_by_name = User.query.filter_by(username=username).first()
        if existing_user_by_name:
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        existing_user_by_email = User.query.filter_by(email=email).first()
        if existing_user_by_email:
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        role = 'user'
        if User.query.count() == 0: # First user becomes admin
            role = 'admin'
            flash('First user registered as admin!', 'success')

        new_user = User(username=username, email=email, password_hash=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: # If already logged in, redirect to dashboard
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            flash('Logged in successfully!', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'error')
            # No redirect here, just re-render login with the flash message
            return render_template('login.html')


    return render_template('login.html')

@app.route('/logout')
@login_required # User must be logged in to log out
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin')
@login_required # Add login_required before admin_required for layered protection
@admin_required 
def admin_dashboard():
    return render_template('admin_dashboard.html')

# --- Application Context for DB Creation ---
def create_db_if_not_exists(app_instance):
    # Ensure the instance folder exists, Flask creates it on first run if needed
    # but for db.create_all(), it's good to ensure it's there before that call.
    if not os.path.exists(app_instance.instance_path):
        os.makedirs(app_instance.instance_path)
        print(f"Instance path {app_instance.instance_path} created.")

    with app_instance.app_context():
        db_file_path = app_instance.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
        if not os.path.exists(db_file_path):
            print(f"Database not found at {db_file_path}. Creating tables...")
            db.create_all()
            print("Database tables created.")
        else:
            print(f"Database found at {db_file_path}.")

if __name__ == '__main__':
    create_db_if_not_exists(app)
    app.run(debug=True)
    