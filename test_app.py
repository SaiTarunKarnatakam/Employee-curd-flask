import unittest
import os
import sqlite3
from app import app, init_db

class EmployeeAppTestSuite(unittest.TestCase):

    def setUp(self):
        """Configure isolated test client and temporary test database before every test."""
        self.test_db = 'test_database.db'
        app.config['DATABASE'] = self.test_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Clean previous instance if leftover
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
        with app.app_context():
            init_db()
            
        self.client = app.test_client()

    def tearDown(self):
        """Remove test database file after each test runs."""
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    # -------------------------------------------------------------------------
    # TEST 1: Login Success with Valid Credentials
    # -------------------------------------------------------------------------
    def test_01_login_success_standard_user(self):
        """Verifies successful login redirects to correct departmental view."""
        response = self.client.post('/login', data={
            'username': 'eng_user',
            'password': 'eng123'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Engineering Department Dashboard', response.data)
        self.assertIn(b'eng_user', response.data)

    # -------------------------------------------------------------------------
    # TEST 2: RBAC Protection - Block Non-Admin from /delete/<id>
    # -------------------------------------------------------------------------
    def test_02_blocked_access_non_admin_delete(self):
        """Verifies non-admin (Engineering) cannot delete records."""
        # 1. Insert an active employee directly into test DB
        conn = sqlite3.connect(self.test_db)
        conn.execute(
            'INSERT INTO employees (name, email, department, role, is_active) VALUES (?, ?, ?, ?, 1)',
            ('Mark Brown', 'mark@company.com', 'Engineering', 'Developer')
        )
        conn.commit()
        emp_id = conn.execute('SELECT id FROM employees WHERE email = ?', ('mark@company.com',)).fetchone()[0]
        conn.close()

        # 2. Authenticate as standard non-admin user
        self.client.post('/login', data={'username': 'eng_user', 'password': 'eng123'})

        # 3. Attempt unauthorized deletion
        response = self.client.post(f'/delete/{emp_id}', follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Access Denied: Only HR and IT administrators can perform this action.', response.data)

        # 4. Verify record is still active in database
        conn = sqlite3.connect(self.test_db)
        emp = conn.execute('SELECT is_active FROM employees WHERE id = ?', (emp_id,)).fetchone()
        conn.close()
        self.assertEqual(emp[0], 1, "Employee must remain active since non-admin cannot delete.")

    # -------------------------------------------------------------------------
    # TEST 3: Re-hire Flow Generates Brand-New Auto-Increment ID
    # -------------------------------------------------------------------------
    def test_03_rehire_generates_new_id(self):
        """Verifies deactivating and re-registering the same email issues a distinct new ID."""
        # 1. Authenticate as HR Admin through 2FA
        self.client.post('/login', data={'username': 'admin_hr', 'password': 'hr123'})
        with self.client.session_transaction() as sess:
            otp = sess['2fa_pending']['otp']
        self.client.post('/verify-2fa', data={'otp': otp}, follow_redirects=True)

        # 2. Hire employee first time
        self.client.post('/add', data={
            'name': 'Priya Nair',
            'email': 'priya@company.com',
            'department': 'Operations',
            'role': 'Coordinator'
        }, follow_redirects=True)

        conn = sqlite3.connect(self.test_db)
        conn.row_factory = sqlite3.Row
        first_hire = conn.execute('SELECT id, is_active FROM employees WHERE email = ? AND is_active = 1', ('priya@company.com',)).fetchone()
        first_id = first_hire['id']
        conn.close()

        # 3. Terminate/Deactivate employee
        self.client.post(f'/delete/{first_id}', follow_redirects=True)

        conn = sqlite3.connect(self.test_db)
        status_after_delete = conn.execute('SELECT is_active FROM employees WHERE id = ?', (first_id,)).fetchone()[0]
        conn.close()
        self.assertEqual(status_after_delete, 0, "Record must be marked inactive after deletion.")

        # 4. Re-hire employee with same email
        self.client.post('/add', data={
            'name': 'Priya Nair',
            'email': 'priya@company.com',
            'department': 'Operations',
            'role': 'Senior Coordinator'
        }, follow_redirects=True)

        # 5. Verify new active record exists with a higher, unique ID
        conn = sqlite3.connect(self.test_db)
        conn.row_factory = sqlite3.Row
        active_records = conn.execute('SELECT id FROM employees WHERE email = ? AND is_active = 1', ('priya@company.com',)).fetchall()
        all_records = conn.execute('SELECT id, is_active FROM employees WHERE email = ?', ('priya@company.com',)).fetchall()
        conn.close()

        self.assertEqual(len(active_records), 1, "Only one record should be active.")
        second_id = active_records[0]['id']
        self.assertNotEqual(first_id, second_id, "Re-hired employee must receive a new ID.")
        self.assertGreater(second_id, first_id, "New ID must be incremented.")
        self.assertEqual(len(all_records), 2, "Database must retain both employment tenure rows.")

    # -------------------------------------------------------------------------
    # TEST 4: 2FA Enforcement on Admin Accounts
    # -------------------------------------------------------------------------
    def test_04_admin_requires_2fa_verification(self):
        """Verifies HR/IT login triggers 2FA pending state instead of direct entry."""
        response = self.client.post('/login', data={
            'username': 'admin_hr',
            'password': 'hr123'
        }, follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Admin Security Verification', response.data)
        
        # Verify protected dashboard cannot be accessed until OTP is confirmed
        dash_response = self.client.get('/department/HR', follow_redirects=True)
        self.assertIn(b'Your session has expired or you are not logged in.', dash_response.data)

if __name__ == '__main__':
    unittest.main()