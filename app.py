from flask import Flask, render_template, request, redirect, url_for
import sqlite3

# 1. Initialize Flask
app = Flask(__name__)
DATABASE = 'database.db'

# Helper function to connect to SQLite
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Access columns by name: row['name']
    return conn

# Function to initialize the database
def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            department TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

# Run table creation on startup
init_db()


# --- OPERATION 1 (READ) & OPERATION 2 (CREATE) ---
@app.route('/', methods=['GET', 'POST'])
def index():
    conn = get_db_connection()

    # CREATE: When user fills the form and clicks "Save"
    if request.method == 'POST':
        # Grab data entered into the HTML inputs
        name = request.form['name']
        email = request.form['email']
        department = request.form['department']
        role = request.form['role']

        # Safe insert using '?' placeholders to prevent SQL Injection
        conn.execute(
            'INSERT INTO employees (name, email, department, role) VALUES (?, ?, ?, ?)',
            (name, email, department, role)
        )
        conn.commit()
        conn.close()
        
        # Refresh the page cleanly by redirecting to '/'
        return redirect(url_for('index'))

    # READ: When user simply visits the page in their browser
    employees = conn.execute('SELECT * FROM employees').fetchall()
    conn.close()
    
    # Send the list of employees to index.html
    return render_template('index.html', employees=employees)


# --- OPERATION 3: UPDATE (EDIT EMPLOYEE) ---
@app.route('/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    conn = get_db_connection()
    # Fetch the employee record matching this ID
    employee = conn.execute('SELECT * FROM employees WHERE id = ?', (id,)).fetchone()

    # If the user submitted updated information
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        department = request.form['department']
        role = request.form['role']

        conn.execute(
            'UPDATE employees SET name = ?, email = ?, department = ?, role = ? WHERE id = ?',
            (name, email, department, role, id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('index'))

    conn.close()
    return render_template('edit.html', employee=employee)


# --- OPERATION 4: DELETE (REMOVE EMPLOYEE) ---
@app.route('/delete/<int:id>', methods=['POST'])
def delete(id):
    conn = get_db_connection()
    conn.execute('DELETE FROM employees WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    return redirect(url_for('index'))


if __name__ == '__main__':
    # debug=True automatically reloads server when code changes
    app.run(debug=True)