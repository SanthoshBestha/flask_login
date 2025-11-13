# app.py - Main Flask Application and Database Logic

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

app = Flask(__name__)
# IMPORTANT: Use a strong, randomly generated key in a real application.
app.secret_key = 'a_very_secure_secret_key_for_session_management'

# --- MySQL Configuration (!!! UPDATE THIS !!!) ---
DB_CONFIG = {
    'host': 'localhost',
    'user': 'santhosh', 
    'password': 'Santhosh@22', # <-- CHANGE THIS
    'database': 'flask_login' 
}

def get_db_connection():
    """Establishes and returns a MySQL database connection."""
    try:
        conn = mysql.connector.connect(**DB_CONFIG)
        return conn
    except mysql.connector.Error as err:
        print(f"Database connection error: {err}")
        return None

# --- FLASK ROUTES ---

@app.route('/')
def index():
    """Root URL redirect to the login page."""
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handles user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if not username or not password:
            flash('Username and password are required.', 'danger')
            return redirect(url_for('signup'))

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed.', 'danger')
            return redirect(url_for('signup'))

        cursor = conn.cursor(dictionary=True)
        try:
            # Check if user already exists
            cursor.execute("SELECT username FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash(f'Username "{username}" is already taken.', 'danger')
                return redirect(url_for('signup'))

            # Hash the password securely and insert the user
            password_hash = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                        (username, password_hash))
            conn.commit()

            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f'An error occurred: {err}', 'danger')
            conn.rollback()
        finally:
            cursor.close()
            conn.close()

    return render_template('signup.html', title="Create Account")


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handles user login and authentication."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        if conn is None:
            flash('Database connection failed.', 'danger')
            return redirect(url_for('login'))

        cursor = conn.cursor(dictionary=True)
        try:
            # Retrieve the user and hash from the database
            cursor.execute("SELECT username, password_hash FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            # Verify password hash
            if user and check_password_hash(user['password_hash'], password):
                session['username'] = user['username']
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
                return redirect(url_for('login'))

        except mysql.connector.Error as err:
            flash(f'An error occurred: {err}', 'danger')
        finally:
            cursor.close()
            conn.close()

    return render_template('login.html', title="User Login")


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        return render_template('dashboard.html')

@app.route('/logout')
def logout():
    """Clears the session and logs the user out."""
    session.pop('username', None)
    flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)