# This Flask application uses Flask-SQLAlchemy for database persistence
# and is configured to securely connect to a remote PostgreSQL database 
# (like Render) via environment variables.

import os
from flask import Flask, render_template_string, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import OperationalError, ProgrammingError
import sys # Added for more robust error printing

# --- Application and Configuration ---

app = Flask(__name__)

# 1. SECRET_KEY: Read from environment or use a secure default for local testing
#    *** IMPORTANT: Change 'a_temporary_dev_secret_key_12345' on Render settings ***
app.secret_key = os.environ.get('SECRET_KEY', 'a_temporary_dev_secret_key_12345')

# 2. DATABASE_URL: Read the PostgreSQL URL from environment.
#    If running locally and not set, use a local SQLite file (for ease of development).
database_url = os.environ.get('postgresql://santhosh:fv1f8JZCThfXKSq3dRmnX7d5bqbE2XFh@dpg-d4ahpjpe2q1c73b06l10-a.oregon-postgres.render.com/flask_login_gccf')
if database_url:
    # Flask-SQLAlchemy may need 'postgresql://' instead of 'postgres://' for old URLs
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print("Using Remote Database via DATABASE_URL")
else:
    # Local SQLite fallback
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///project.db' 
    print("Using Local SQLite Database")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Database Model (SQLAlchemy ORM) ---

class User(db.Model):
    """Defines the User model for database interactions."""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'
    
    # Helper methods for password handling
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# --- Initialization Function ---

# We only run create_all() once, but we check if we can connect
# before running any other database code.
@app.before_request
def check_db_and_create_tables():
    """
    Checks if the database is ready. If not, it attempts to initialize tables.
    This helps ensure the app doesn't crash on connection issues.
    """
    if not getattr(app, '_db_initialized', False):
        with app.app_context():
            try:
                # Attempt to create tables if they don't exist
                db.create_all()
                app._db_initialized = True
                print("Database tables initialized successfully.")
            except (OperationalError, ProgrammingError) as e:
                # OperationalError: connection failure
                # ProgrammingError: table/schema missing (though less likely after create_all)
                print(f"FATAL DB Initialization Error: Could not connect or create tables. Details: {e}", file=sys.stderr)
                app._db_initialized = False # Keep trying on next request
            except Exception as e:
                print(f"General DB Error: {e}", file=sys.stderr)
                app._db_initialized = False


# --- Template Rendering Functions (Simplified for single file) ---

def render_page(template, **kwargs):
    """
    Renders the HTML using simple, Bootstrap-styled template strings.
    This replaces the use of external HTML files in the 'templates/' folder.
    """
    
    BASE_LAYOUT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <!-- Bootstrap 5 CDN -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
    <style>
        body { 
            font-family: 'Inter', sans-serif; 
            background: linear-gradient(135deg, #f0f4f8 0%, #d9e2ec 100%);
            min-height: 100vh;
        }
        .card {
            border-radius: 1rem;
            box-shadow: 0 10px 25px rgba(0,0,0,.1);
            max-width: 450px;
        }
    </style>
</head>
<body class="d-flex flex-column align-items-center justify-content-center p-3">

    <!-- Flash Messages Area -->
    <div class="container my-3" style="max-width: 450px;">
        {% with messages = get_flashed_messages(with_categories=true) %}
          {% if messages %}
            {% for category, message in messages %}
              <div class="alert alert-{{ 'success' if category == 'success' else 'danger' }} alert-dismissible fade show" role="alert">
                {{ message }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
              </div>
            {% endfor %}
          {% endif %}
        {% endwith %}
    </div>

    <!-- Main Card Content -->
    <div class="card p-4 p-md-5 w-100">
        <h1 class="text-center text-primary mb-4 fw-bold">{{ title }}</h1>
        {% block content %}{% endblock %}
    </div>

    <!-- Bootstrap JS Bundle -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
"""

    SIGNUP_TEMPLATE = """
{% block content %}
    <form method="POST" action="{{ url_for('signup') }}">
        <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" id="username" name="username" required>
        </div>
        <div class="mb-4">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100 py-2">Sign Up</button>
    </form>
    <p class="mt-4 text-center text-muted">
        Already have an account? <a href="{{ url_for('login') }}" class="text-primary fw-medium">Log In</a>
    </p>
{% endblock %}
"""

    LOGIN_TEMPLATE = """
{% block content %}
    <form method="POST" action="{{ url_for('login') }}">
        <div class="mb-3">
            <label for="username" class="form-label">Username</label>
            <input type="text" class="form-control" id="username" name="username" required>
        </div>
        <div class="mb-4">
            <label for="password" class="form-label">Password</label>
            <input type="password" class="form-control" id="password" name="password" required>
        </div>
        <button type="submit" class="btn btn-success w-100 py-2">Log In</button>
    </form>
    <p class="mt-4 text-center text-muted">
        Don't have an account? <a href="{{ url_for('signup') }}" class="text-primary fw-medium">Sign Up</a>
    </p>
{% endblock %}
"""

    DASHBOARD_TEMPLATE = """
{% block content %}
    <div class="text-center p-3">
        <!-- Main Welcome Message -->
        <h2 class="text-secondary mb-3">Hello, <span class="fw-bold text-primary">{{ session['username'] }}</span>!</h2>
        
        <p class="lead text-dark mb-4">
            Welcome to your personal dashboard. You are securely logged in.
        </p>

        <!-- Logout Button -->
        <a href="{{ url_for('logout') }}" class="btn btn-danger btn-lg w-100 mt-3">Log Out</a>
    </div>
{% endblock %}
"""
    
    # Map the template name to its content
    template_map = {
        'signup': SIGNUP_TEMPLATE,
        'login': LOGIN_TEMPLATE,
        'dashboard': DASHBOARD_TEMPLATE
    }
    
    content = template_map.get(template, "")
    
    # Combine base layout and content
    full_html = BASE_LAYOUT.replace("{% block content %}{% endblock %}", content)

    # Render the final HTML string
    return render_template_string(full_html, **kwargs)


# --- FLASK ROUTES ---

@app.route('/')
def index():
    """Root URL redirect to login."""
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user registration, storing hashed password in the database."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('signup'))

        try:
            with app.app_context():
                # 1. Check if user already exists
                user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
                
                if user:
                    flash(f'Username "{username}" is already taken.', 'danger')
                    return redirect(url_for('signup'))

                # 2. Create and insert new user
                new_user = User(username=username)
                new_user.set_password(password) # Hashes the password

                db.session.add(new_user)
                db.session.commit()

                flash('Account created successfully! Please log in.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            # Catch DB errors during signup
            print(f"Error during signup: {e}", file=sys.stderr)
            flash('A database error occurred. Please try again later.', 'danger')
            return redirect(url_for('signup'))

    return render_page('signup', title="Create Account")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login, verifying password against the hash."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        try:
            with app.app_context():
                # 1. Retrieve the user
                user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()

                if user and user.check_password(password):
                    # Authentication successful
                    session['username'] = user.username
                    flash('Login successful!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    # Authentication failed
                    flash('Invalid username or password.', 'danger')
                    return redirect(url_for('login'))
        except Exception as e:
            # Catch DB errors during login
            print(f"Error during login: {e}", file=sys.stderr)
            flash('A database error occurred during login. Please try again.', 'danger')
            return redirect(url_for('login'))

    return render_page('login', title="User Login")


@app.route('/dashboard')
def dashboard():
    """The protected area, requires a session to access."""
    if 'username' in session:
        return render_page('dashboard', title="Secure Dashboard")
    else:
        flash('You must be logged in to view the dashboard.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.pop('username', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


# --- Local Runner ---
if __name__ == '__main__':
    # This block runs ONLY when executed directly (e.g., python app.py)
    # It ensures the database is created if running locally with SQLite.
    with app.app_context():
        print("Running locally. Attempting to create SQLite database (if needed).")
        db.create_all()
    
    # Running the application
    app.run(debug=True)
