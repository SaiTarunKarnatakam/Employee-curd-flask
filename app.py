import sqlite3
import secrets
import os
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'super_secret_internship_key_change_in_production')
app.permanent_session_lifetime = timedelta(minutes=30)
DATABASE = 'database.db'

def get_db_connection():
    db_path = app.config.get('DATABASE', DATABASE)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    
    # 1. Employees Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # 2. Authenticated Users Table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            department TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # 3. Session Authentication Logs
    conn.execute('''
        CREATE TABLE IF NOT EXISTS login_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            department TEXT NOT NULL,
            login_time TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # 4. Enterprise Mutation Audit Trail (Governance & Compliance)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS audit_mutations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action_type TEXT NOT NULL,
            actor_username TEXT NOT NULL,
            actor_department TEXT NOT NULL,
            target_employee_id INTEGER,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    ''')

    user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    if user_count == 0:
        seed_users = [
            ('admin_hr', generate_password_hash('hr123'), 'HR', 'HR Admin'),
            ('admin_it', generate_password_hash('it123'), 'IT', 'IT Admin'),
            ('eng_user', generate_password_hash('eng123'), 'Engineering', 'Employee'),
            ('ops_user', generate_password_hash('ops123'), 'Operations', 'Employee')
        ]
        conn.executemany(
            'INSERT INTO users (username, password_hash, department, role) VALUES (?, ?, ?, ?)',
            seed_users
        )

    conn.commit()
    conn.close()

with app.app_context():
    init_db()

# --- Audit Helper Function ---
def log_mutation(action_type, target_emp_id, details):
    conn = get_db_connection()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn.execute(
        '''INSERT INTO audit_mutations 
           (action_type, actor_username, actor_department, target_employee_id, details, timestamp) 
           VALUES (?, ?, ?, ?, ?, ?)''',
        (
            action_type,
            session.get('username', 'SYSTEM'),
            session.get('department', 'UNKNOWN'),
            target_emp_id,
            details,
            now_str
        )
    )
    conn.commit()
    conn.close()

# --- Access Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Your session has expired or you are not logged in. Please sign in.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first.', 'warning')
            return redirect(url_for('login'))
        if session.get('department') not in ['HR', 'IT']:
            flash('Access Denied: Only HR and IT administrators can perform this action.', 'danger')
            return redirect(url_for('department_dashboard', dept_name=session.get('department')))
        return f(*args, **kwargs)
    return decorated_function

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # Enforce 2FA for privileged administrator roles
            if user['department'] in ['HR', 'IT']:
                otp = f"{secrets.randbelow(900000) + 100000}"
                session['2fa_pending'] = {
                    'user_id': user['id'],
                    'username': user['username'],
                    'department': user['department'],
                    'role': user['role'],
                    'otp': otp
                }
                print(f"\n[2FA DISPATCH] Security passcode for {user['username']}: {otp}\n")
                flash(f"2FA Required (Demo OTP: {otp})", 'info')
                return redirect(url_for('verify_2fa'))

            session.permanent = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['department'] = user['department']
            session['role'] = user['role']

            conn = get_db_connection()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                'INSERT INTO login_logs (user_id, username, department, login_time) VALUES (?, ?, ?, ?)',
                (user['id'], user['username'], user['department'], current_time)
            )
            conn.commit()
            conn.close()

            flash(f"Welcome back, {user['username']}!", 'success')
            return redirect(url_for('department_dashboard', dept_name=user['department']))
        
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    if '2fa_pending' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form.get('otp', '').strip()
        pending = session['2fa_pending']

        if entered_otp == pending['otp']:
            session.permanent = True
            session['user_id'] = pending['user_id']
            session['username'] = pending['username']
            session['department'] = pending['department']
            session['role'] = pending['role']
            session.pop('2fa_pending', None)

            conn = get_db_connection()
            current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute(
                'INSERT INTO login_logs (user_id, username, department, login_time) VALUES (?, ?, ?, ?)',
                (session['user_id'], session['username'], session['department'], current_time)
            )
            conn.commit()
            conn.close()

            flash('Two-step verification successful.', 'success')
            return redirect(url_for('department_dashboard', dept_name=session['department']))
        
        flash('Incorrect passcode. Please try again.', 'danger')

    return render_template('verify_2fa.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password entered is incorrect.', 'danger')
        elif len(new_password) < 5:
            flash('New password must be at least 5 characters long.', 'warning')
        elif new_password != confirm_password:
            flash('New password and confirmation password do not match.', 'danger')
        else:
            hashed_new = generate_password_hash(new_password)
            conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_new, session['user_id']))
            conn.commit()
            log_mutation('UPDATE_PASSWORD', session['user_id'], f"User {session['username']} updated security credentials.")
            flash('Your password has been updated successfully.', 'success')

        conn.close()
        return redirect(url_for('profile'))

    return render_template('profile.html')

@app.route('/')
@login_required
def root():
    return redirect(url_for('department_dashboard', dept_name=session['department']))

@app.route('/department/<dept_name>')
@login_required
def department_dashboard(dept_name):
    conn = get_db_connection()
    is_admin = session.get('department') in ['HR', 'IT']
    
    if is_admin:
        employees = conn.execute('SELECT * FROM employees WHERE is_active = 1 ORDER BY id DESC').fetchall()
    else:
        employees = conn.execute('SELECT * FROM employees WHERE department = ? AND is_active = 1 ORDER BY id DESC', (dept_name,)).fetchall()
        
    conn.close()
    return render_template('index.html', employees=employees, dept_name=dept_name, is_admin=is_admin)

# --- CRUD Operations with Enterprise Audit Trail ---
@app.route('/add', methods=['POST'])
@admin_required
def add_employee():
    name = request.form['name'].strip()
    email = request.form['email'].strip()
    department = request.form['department'].strip()
    role = request.form['role'].strip()

    conn = get_db_connection()
    existing_active = conn.execute('SELECT id FROM employees WHERE email = ? AND is_active = 1', (email,)).fetchone()

    if existing_active:
        flash(f'An active employee with email "{email}" already exists (ID #{existing_active["id"]}).', 'danger')
    else:
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO employees (name, email, department, role, is_active) VALUES (?, ?, ?, ?, 1)',
            (name, email, department, role)
        )
        new_emp_id = cursor.lastrowid
        conn.commit()
        
        # Log governance event
        log_mutation('CREATE_EMPLOYEE', new_emp_id, f"Onboarded {name} ({role}, {department})")
        flash(f'Employee {name} registered successfully with new ID #{new_emp_id}!', 'success')

    conn.close()
    return redirect(url_for('department_dashboard', dept_name=session['department']))

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@admin_required
def edit(id):
    conn = get_db_connection()
    employee = conn.execute('SELECT * FROM employees WHERE id = ? AND is_active = 1', (id,)).fetchone()

    if not employee:
        conn.close()
        flash('Employee not found or inactive.', 'warning')
        return redirect(url_for('department_dashboard', dept_name=session['department']))

    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        department = request.form['department'].strip()
        role = request.form['role'].strip()

        collision = conn.execute(
            'SELECT id FROM employees WHERE email = ? AND id != ? AND is_active = 1', (email, id)
        ).fetchone()

        if collision:
            flash(f'Email "{email}" is currently used by active employee #{collision["id"]}.', 'danger')
        else:
            conn.execute(
                'UPDATE employees SET name = ?, email = ?, department = ?, role = ? WHERE id = ?',
                (name, email, department, role, id)
            )
            conn.commit()
            log_mutation('UPDATE_EMPLOYEE', id, f"Modified record #{id}: {name}, {role}, {department}")
            conn.close()
            flash('Employee details updated successfully.', 'success')
            return redirect(url_for('department_dashboard', dept_name=session['department']))

    conn.close()
    return render_template('edit.html', employee=employee)

@app.route('/delete/<int:id>', methods=['POST'])
@admin_required
def delete(id):
    conn = get_db_connection()
    emp = conn.execute('SELECT name, department FROM employees WHERE id = ?', (id,)).fetchone()
    conn.execute('UPDATE employees SET is_active = 0 WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    emp_name = emp['name'] if emp else 'Unknown'
    log_mutation('SOFT_DELETE_EMPLOYEE', id, f"Soft-deleted employee #{id} ({emp_name}). Re-hire permitted with fresh ID.")
    flash(f'Employee #{id} has been deactivated. Record retained for historical compliance.', 'info')
    return redirect(url_for('department_dashboard', dept_name=session['department']))

# --- Enterprise Governance Audit View ---
@app.route('/audit/governance')
@admin_required
def view_governance_logs():
    conn = get_db_connection()
    mutation_logs = conn.execute('SELECT * FROM audit_mutations ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return render_template('governance_logs.html', logs=mutation_logs)

@app.route('/audit/logins')
@admin_required
def view_login_logs():
    conn = get_db_connection()
    logs = conn.execute('SELECT * FROM login_logs ORDER BY id DESC LIMIT 50').fetchall()
    conn.close()
    return render_template('logs.html', logs=logs)

# --- AI & Digital Transformation Analytics Endpoint ---
@app.route('/api/v1/workforce-summary', methods=['GET'])
@login_required
def workforce_ai_summary():
    """
    Enterprise Data Transformation Endpoint.
    Outputs structured workforce telemetry formatted for downstream AI model/LLM ingestion.
    """
    conn = get_db_connection()
    
    # 1. Total Metrics
    total_active = conn.execute('SELECT COUNT(*) FROM employees WHERE is_active = 1').fetchone()[0]
    total_inactive = conn.execute('SELECT COUNT(*) FROM employees WHERE is_active = 0').fetchone()[0]
    total_all_time = total_active + total_inactive
    
    # 2. Department Breakdown
    dept_rows = conn.execute('''
        SELECT department, COUNT(*) as headcount 
        FROM employees 
        WHERE is_active = 1 
        GROUP BY department
    ''').fetchall()
    dept_breakdown = {row['department']: row['headcount'] for row in dept_rows}

    # 3. Re-hire / Retention Analysis
    rehire_query = conn.execute('''
        SELECT email, COUNT(id) as tenure_count 
        FROM employees 
        GROUP BY email 
        HAVING COUNT(id) > 1
    ''').fetchall()
    rehire_count = len(rehire_query)

    conn.close()

    attrition_rate_pct = round((total_inactive / total_all_time * 100), 2) if total_all_time > 0 else 0.0

    # Structured prompt payload for LLM/AI Agent consumption
    ai_context_prompt = (
        f"Workforce Telemetry Snapshot: Total Active Headcount is {total_active} across {len(dept_breakdown)} operational departments. "
        f"Current historical turnover count is {total_inactive} with an attrition rate of {attrition_rate_pct}%. "
        f"Re-hired personnel tracking stands at {rehire_count} recurring corporate profiles. "
        f"Department distribution: {', '.join([f'{k}: {v}' for k, v in dept_breakdown.items()]) or 'None active'}."
    )

    payload = {
        "status": "success",
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "requested_by": session.get('username'),
        "metrics": {
            "active_headcount": total_active,
            "inactive_archived": total_inactive,
            "total_records_managed": total_all_time,
            "attrition_rate_percentage": attrition_rate_pct,
            "rehire_profiles_count": rehire_count
        },
        "department_distribution": dept_breakdown,
        "ai_llm_ready_prompt": ai_context_prompt
    }

    return jsonify(payload)

if __name__ == '__main__':
    app.run(debug=True)