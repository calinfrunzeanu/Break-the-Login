import hashlib
import time
import sqlite3
import os
from flask import Flask, request, session, redirect, url_for, render_template, g, jsonify

portal = Flask(__name__)

# VULN 4.5: cheie secreta hardcodata si slaba
portal.secret_key = 'authx-secret'

# VULN 4.5: cookie fara HttpOnly si fara SameSite
portal.config['SESSION_COOKIE_HTTPONLY'] = False
portal.config['SESSION_COOKIE_SAMESITE'] = None

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'authx_beta.db')


def wants_json():
    return request.headers.get('Accept') == 'application/json'


def connect_db():
    conn = getattr(g, '_conn', None)
    if conn is None:
        conn = g._conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
    return conn


@portal.teardown_appcontext
def disconnect_db(exception):
    conn = getattr(g, '_conn', None)
    if conn is not None:
        conn.close()


def create_tables():
    with portal.app_context():
        conn = connect_db()
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'ANALYST',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_token_expires TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked INTEGER DEFAULT 0,
                locked_until TEXT
            );
            CREATE TABLE IF NOT EXISTS tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                severity TEXT DEFAULT 'LOW',
                status TEXT DEFAULT 'OPEN',
                owner_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                resource TEXT,
                resource_id TEXT,
                timestamp TEXT,
                ip_address TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')
        conn.commit()


def audit_event(user_id, action, resource, resource_id=None):
    try:
        conn = connect_db()
        conn.execute(
            'INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address) '
            'VALUES (?, ?, ?, ?, datetime("now"), ?)',
            (user_id, action, resource, resource_id, request.remote_addr)
        )
        conn.commit()
    except Exception:
        pass


@portal.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home_page'))
    return redirect(url_for('signin'))


@portal.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        mail = request.form.get('email', '').strip()
        raw_pw = request.form.get('password', '')
        # VULN 4.1: utilizatorul isi alege singur rolul
        chosen_role = request.form.get('role', 'ANALYST')

        # VULN 4.1: nicio validare a parolei
        # VULN 4.2: MD5 fara salt
        hashed_pw = hashlib.md5(raw_pw.encode()).hexdigest()

        conn = connect_db()
        try:
            conn.execute(
                'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                (mail, hashed_pw, chosen_role)
            )
            conn.commit()
            if wants_json():
                return jsonify({
                    "status": "ok",
                    "message": "Cont creat cu succes.",
                    "email": mail,
                    "role": chosen_role,
                    "vuln_4.1": "Parola acceptata fara validare. Rol ales de utilizator.",
                    "vuln_4.2": f"Parola stocata ca MD5: {hashed_pw}"
                }), 201
            return redirect(url_for('signin'))
        except sqlite3.IntegrityError:
            if wants_json():
                return jsonify({"status": "error", "message": "Email deja inregistrat."}), 409
            return render_template('signup.html', error='Email deja inregistrat.')

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: email, password, role"})
    return render_template('signup.html', error=None)


@portal.route('/login', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        mail = request.form.get('email', '').strip()
        raw_pw = request.form.get('password', '')

        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE email = ?', (mail,)).fetchone()

        # VULN 4.4: mesaje diferite => user enumeration
        if not record:
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "User not found.",
                    "vuln_4.4": "Mesaj diferit => emailul NU este inregistrat"
                }), 401
            return render_template('signin.html', error='User not found.')

        hashed_pw = hashlib.md5(raw_pw.encode()).hexdigest()
        if record['password_hash'] != hashed_pw:
            # VULN 4.4: alt mesaj => userul EXISTA
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "Wrong password.",
                    "vuln_4.4": "Mesaj diferit => emailul ESTE inregistrat"
                }), 401
            return render_template('signin.html', error='Wrong password.')

        # VULN 4.5: fara session fixation protection, fara expirare
        # VULN 4.3: fara blocare cont sau rate limiting
        session['user_id'] = record['id']
        session['email'] = record['email']
        session['role'] = record['role']
        audit_event(record['id'], 'LOGIN_SUCCESS', 'auth')

        if wants_json():
            return jsonify({
                "status": "ok",
                "message": "Login reusit.",
                "user": {"email": record['email'], "role": record['role']},
                "vuln_4.3": "Nicio blocare cont. Incercari nelimitate.",
                "vuln_4.5": "Cookie fara HttpOnly si fara SameSite."
            })
        return redirect(url_for('home_page'))

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: email, password"})
    return render_template('signin.html', error=None)


@portal.route('/logout')
def signout():
    uid = session.get('user_id')
    mail = session.get('email')
    if uid:
        audit_event(uid, 'LOGOUT', 'auth')
    session.clear()
    if wants_json():
        return jsonify({"status": "ok", "message": f"Utilizator {mail} delogat."})
    return redirect(url_for('signin'))


@portal.route('/dashboard')
def home_page():
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    if wants_json():
        return jsonify({
            "status": "ok",
            "email": session.get('email'),
            "role": session.get('role'),
            "user_id": session.get('user_id')
        })
    return render_template('home.html', email=session.get('email'), role=session.get('role'))


@portal.route('/forgot-password', methods=['GET', 'POST'])
def recover_account():
    if request.method == 'POST':
        mail = request.form.get('email', '').strip()
        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE email = ?', (mail,)).fetchone()

        # VULN 4.4: mesaj diferit => user enumeration
        if not record:
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "No account found with this email.",
                    "vuln_4.4": "Mesaj diferit confirma ca emailul NU exista"
                }), 404
            return render_template('recover_account.html', message=None, error='No account found with this email.')

        # VULN 4.6: token predictibil = timestamp hex
        reset_tok = hex(int(time.time()))[2:]
        conn.execute('UPDATE users SET reset_token = ? WHERE id = ?', (reset_tok, record['id']))
        conn.commit()

        if wants_json():
            return jsonify({
                "status": "ok",
                "message": "Token de resetare generat.",
                "vuln_4.6_token": reset_tok,
                "vuln_4.6_link": f"http://localhost:5001/reset-password?token={reset_tok}",
                "vuln_4.6_explicatie": "Token = hex(timestamp) => predictibil si reutilizabil"
            })
        return render_template('recover_account.html',
                               message=f'Token generat: {reset_tok} | Link: /reset-password?token={reset_tok}',
                               error=None)

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: email"})
    return render_template('recover_account.html', message=None, error=None)


@portal.route('/reset-password', methods=['GET', 'POST'])
def set_new_password():
    tok = request.args.get('token', '')
    if request.method == 'POST':
        tok = request.form.get('token', '')
        raw_pw = request.form.get('password', '')

        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE reset_token = ?', (tok,)).fetchone()

        if not record:
            if wants_json():
                return jsonify({"status": "error", "message": "Token invalid."}), 400
            return render_template('new_password.html', token=tok, message=None, error='Token invalid.')

        # VULN 4.2: MD5
        # VULN 4.6: tokenul NU e invalidat => reutilizabil la infinit, fara expirare
        hashed_pw = hashlib.md5(raw_pw.encode()).hexdigest()
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (hashed_pw, record['id']))
        conn.commit()

        if wants_json():
            return jsonify({
                "status": "ok",
                "message": "Parola resetata cu succes.",
                "email": record['email'],
                "vuln_4.6": "Tokenul RAMANE valid in DB => poate fi reutilizat.",
                "vuln_4.2": f"Noua parola stocata tot ca MD5: {hashed_pw}"
            })
        return render_template('new_password.html', token=tok, message='Parola resetata cu succes.', error=None)

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: token, password"})
    return render_template('new_password.html', token=tok, message=None, error=None)


@portal.route('/tickets')
def list_issues():
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    conn = connect_db()
    current_role = session.get('role')
    uid = session['user_id']
    if current_role == 'MANAGER':
        rows = conn.execute(
            'SELECT t.*, u.email AS owner_email FROM tickets t '
            'JOIN users u ON t.owner_id = u.id ORDER BY t.created_at DESC'
        ).fetchall()
    else:
        rows = conn.execute(
            'SELECT t.*, u.email AS owner_email FROM tickets t '
            'JOIN users u ON t.owner_id = u.id WHERE t.owner_id = ? ORDER BY t.created_at DESC',
            (uid,)
        ).fetchall()
    if wants_json():
        return jsonify({
            "status": "ok",
            "role": current_role,
            "count": len(rows),
            "tickets": [dict(r) for r in rows]
        })
    return render_template('issues.html', tickets=rows, role=current_role)


@portal.route('/tickets/new', methods=['GET', 'POST'])
def create_issue():
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        body = request.form.get('description', '')
        priority = request.form.get('severity', 'LOW')
        if not title:
            if wants_json():
                return jsonify({"status": "error", "message": "Titlul este obligatoriu."}), 400
            return render_template('issue_form.html', error='Titlul este obligatoriu.', ticket=None)
        conn = connect_db()
        cur = conn.execute(
            'INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)',
            (title, body, priority, session['user_id'])
        )
        conn.commit()
        audit_event(session['user_id'], 'CREATE_TICKET', 'ticket', str(cur.lastrowid))
        if wants_json():
            return jsonify({"status": "ok", "message": "Ticket creat.", "ticket_id": cur.lastrowid}), 201
        return redirect(url_for('list_issues'))
    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: title, description, severity"})
    return render_template('issue_form.html', error=None, ticket=None)


@portal.route('/tickets/<int:ticket_id>', methods=['GET', 'POST'])
def edit_issue(ticket_id):
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    conn = connect_db()
    # VULN: IDOR - nicio verificare de ownership
    item = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not item:
        if wants_json():
            return jsonify({"status": "error", "message": "Ticket negasit."}), 404
        return 'Ticket negasit.', 404
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        body = request.form.get('description', '')
        priority = request.form.get('severity', item['severity'])
        state = request.form.get('status', item['status'])
        conn.execute(
            'UPDATE tickets SET title=?, description=?, severity=?, status=?, updated_at=datetime("now") WHERE id=?',
            (title, body, priority, state, ticket_id)
        )
        conn.commit()
        audit_event(session['user_id'], 'EDIT_TICKET', 'ticket', str(ticket_id))
        if wants_json():
            return jsonify({"status": "ok", "message": f"Ticket {ticket_id} actualizat."})
        return redirect(url_for('list_issues'))
    if wants_json():
        return jsonify({"status": "ok", "ticket": dict(item),
                        "vuln_IDOR": "Nicio verificare de ownership. Orice user poate edita."})
    return render_template('issue_form.html', error=None, ticket=item)


@portal.route('/audit-logs')
def view_activity():
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    # VULN: nicio verificare de rol
    conn = connect_db()
    entries = conn.execute(
        'SELECT a.*, u.email FROM audit_logs a '
        'LEFT JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC'
    ).fetchall()
    if wants_json():
        return jsonify({
            "status": "ok",
            "vuln": "Nicio verificare de rol. Orice user autentificat vede toate logurile.",
            "count": len(entries),
            "logs": [dict(e) for e in entries]
        })
    return render_template('activity.html', logs=entries, role=session.get('role'))


if __name__ == '__main__':
    create_tables()
    print('[BETA] AuthX webapp_beta pornit pe http://localhost:5001')
    portal.run(port=5001, debug=True)
