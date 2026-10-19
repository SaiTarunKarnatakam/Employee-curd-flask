import unittest
import os
import sqlite3
import json
from app import app, init_db

class EmployeeAppTestSuite(unittest.TestCase):

    def setUp(self):
        self.test_db = 'test_database.db'
        app.config['DATABASE'] = self.test_db
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
        with app.app_context():
            init_db()
            
        self.client = app.test_client()

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def _login_as_admin(self):
        self.client.post('/login', data={'username': 'admin_hr', 'password': 'hr123'})
        with self.client.session_transaction() as sess:
            otp = sess['2fa_pending']['otp']
        self.client.post('/verify-2fa', data={'otp': otp}, follow_redirects=True)

    # TEST 1: Standard Login Success
    def test_01_login_success_standard_user(self):
        response = self.client.post('/login', data={
            'username': 'eng_user',
            'password': 'eng123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Engineering Department Dashboard', response.data)

    # TEST 2: RBAC Access Protection
    def test_02_blocked_access_non_admin_delete(self):
        conn = sqlite3.connect(self.test_db)
        conn.execute('INSERT INTO employees (name, email, department, role, is_active) VALUES (?, ?, ?, ?, 1)',
                     ('Mark Brown', 'mark@company.com', 'Engineering', 'Developer'))
        conn.commit()
        emp_id = conn.execute('SELECT id FROM employees WHERE email = ?', ('mark@company.com',)).fetchone()[0]
        conn.close()

        self.client.post('/login', data={'username': 'eng_user', 'password': 'eng123'})
        response = self.client.post(f'/delete/{emp_id}', follow_redirects=True)
        self.assertIn(b'Access Denied: Only HR and IT administrators can perform this action.', response.data)

    # TEST 3: Soft-Delete & Re-hire ID Lineage
    def test_03_rehire_generates_new_id(self):
        self._login_as_admin()

        self.client.post('/add', data={'name': 'Priya Nair', 'email': 'priya@company.com', 'department': 'Operations', 'role': 'Lead'}, follow_redirects=True)
        
        conn = sqlite3.connect(self.test_db)
        first_id = conn.execute('SELECT id FROM employees WHERE email = ?', ('priya@company.com',)).fetchone()[0]
        conn.close()

        self.client.post(f'/delete/{first_id}', follow_redirects=True)
        self.client.post('/add', data={'name': 'Priya Nair', 'email': 'priya@company.com', 'department': 'Operations', 'role': 'Director'}, follow_redirects=True)

        conn = sqlite3.connect(self.test_db)
        active_records = conn.execute('SELECT id FROM employees WHERE email = ? AND is_active = 1', ('priya@company.com',)).fetchall()
        conn.close()

        self.assertEqual(len(active_records), 1)
        self.assertGreater(active_records[0][0], first_id)

    # TEST 4: 2FA Enforcement
    def test_04_admin_requires_2fa_verification(self):
        response = self.client.post('/login', data={'username': 'admin_hr', 'password': 'hr123'}, follow_redirects=True)
        self.assertIn(b'Admin Security Verification', response.data)

    # TEST 5: Enterprise Mutation Audit Trail
    def test_05_mutation_audit_trail_logging(self):
        self._login_as_admin()
        self.client.post('/add', data={'name': 'Kavita Roy', 'email': 'kavita@company.com', 'department': 'HR', 'role': 'Recruiter'}, follow_redirects=True)

        conn = sqlite3.connect(self.test_db)
        conn.row_factory = sqlite3.Row
        log = conn.execute('SELECT * FROM audit_mutations WHERE action_type = "CREATE_EMPLOYEE"').fetchone()
        conn.close()

        self.assertIsNotNone(log)
        self.assertEqual(log['actor_username'], 'admin_hr')
        self.assertIn('Kavita Roy', log['details'])

    # TEST 6: AI-Ready Analytics Telemetry Endpoint
    def test_06_ai_analytics_endpoint(self):
        self._login_as_admin()
        self.client.post('/add', data={'name': 'Anil Rao', 'email': 'anil@company.com', 'department': 'Engineering', 'role': 'Architect'}, follow_redirects=True)

        response = self.client.get('/api/v1/workforce-summary')
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('ai_llm_ready_prompt', data)
        self.assertGreaterEqual(data['metrics']['active_headcount'], 1)
        self.assertEqual(data['department_distribution']['Engineering'], 1)

if __name__ == '__main__':
    unittest.main()