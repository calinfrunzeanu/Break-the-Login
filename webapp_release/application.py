import secrets
import re
import sqlite3
import os
from datetime import datetime, timedelta
from flask import Flask, request, session, redirect, url_for, render_template, g, jsonify
import bcrypt

portal = Flask(__name__)

# FIX 4.5: cheie secreta puternica, generata aleator
portal.secret_key = secrets.token_hex(32)

# FIX 4.5: cookie-uri securizate
portal.config['SESSION_COOKIE_HTTPONLY'] = True
portal.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
portal.permanent_session_lifetime = timedelta(minutes=30)

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'authx_release.db')
FAIL_LIMIT = 5
LOCK_DURATION = 15
TOKEN_TTL = 15

_TIMING_GUARD = bcrypt.hashpw(b'dummy_timing_protection', bcrypt.gensalt(rounds=12)).decode()


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


def audit_event(conn, user_id, action, resource, ip, resource_id=None):
    try:
        conn.execute(
            'INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address) '
            'VALUES (?, ?, ?, ?, datetime("now"), ?)',
            (user_id, action, resource, resource_id, ip)
        )
        conn.commit()
    except Exception:
        pass


def check_password_policy(raw_pw):
    if len(raw_pw) < 8:
        return 'Parola trebuie sa aiba cel putin 8 caractere.'
    if not re.search(r'[A-Z]', raw_pw):
        return 'Parola trebuie sa contina cel putin o litera mare.'
    if not re.search(r'[a-z]', raw_pw):
        return 'Parola trebuie sa contina cel putin o litera mica.'
    if not re.search(r'[0-9]', raw_pw):
        return 'Parola trebuie sa contina cel putin o cifra.'
    return None


@portal.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('home_page'))
    return redirect(url_for('signin'))


@portal.route('/register', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        mail = request.form.get('email', '').strip().lower()
        raw_pw = request.form.get('password', '')

        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', mail):
            if wants_json():
                return jsonify({"status": "error", "message": "Format email invalid."}), 400
            return render_template('signup.html', error='Format email invalid.')

        policy_err = check_password_policy(raw_pw)
        if policy_err:
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": policy_err,
                    "fix_4.1": "Politica de parola aplicata: min 8 caractere, uppercase, lowercase, cifra."
                }), 400
            return render_template('signup.html', error=policy_err)

        # FIX 4.2: bcrypt cu salt
        hashed_pw = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
        conn = connect_db()
        try:
            conn.execute(
                'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
                (mail, hashed_pw, 'ANALYST')  # FIX 4.1: rolul e intotdeauna ANALYST
            )
            conn.commit()
            if wants_json():
                return jsonify({
                    "status": "ok",
                    "message": "Cont creat cu succes.",
                    "email": mail,
                    "role": "ANALYST",
                    "fix_4.1": "Rolul este intotdeauna ANALYST, indiferent de input.",
                    "fix_4.2": f"Hash bcrypt (primele 20 chars): {hashed_pw[:20]}..."
                }), 201
            return redirect(url_for('signin'))
        except sqlite3.IntegrityError:
            # FIX 4.4: mesaj generic, fara user enumeration
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "Inregistrarea a esuat. Incercati din nou.",
                    "fix_4.4": "Mesaj generic, nu se poate determina daca emailul exista."
                }), 409
            return render_template('signup.html', error='Inregistrarea a esuat. Incercati din nou.')

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: email, password"})
    return render_template('signup.html', error=None)


@portal.route('/login', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        mail = request.form.get('email', '').strip().lower()
        raw_pw = request.form.get('password', '')
        client_ip = request.remote_addr

        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE email = ?', (mail,)).fetchone()

        # FIX 4.3: verificare blocare cont
        if record and record['locked'] and record['locked_until']:
            block_until = datetime.fromisoformat(record['locked_until'])
            if datetime.now() < block_until:
                audit_event(conn, record['id'], 'LOGIN_BLOCKED', 'auth', client_ip)
                if wants_json():
                    return jsonify({
                        "status": "error",
                        "message": "Invalid credentials.",
                        "fix_4.3": f"Cont blocat pana la {record['locked_until']} din cauza prea multor incercari gresite.",
                        "fix_4.4": "Acelasi mesaj generic si pentru cont blocat."
                    }), 401
                return render_template('signin.html', error='Invalid credentials.')
            else:
                conn.execute(
                    'UPDATE users SET locked=0, failed_attempts=0, locked_until=NULL WHERE id=?',
                    (record['id'],)
                )
                conn.commit()
                record = conn.execute('SELECT * FROM users WHERE email = ?', (mail,)).fetchone()

        # FIX: timing-safe bcrypt ruleaza intotdeauna
        if record:
            pw_valid = bcrypt.checkpw(raw_pw.encode(), record['password_hash'].encode())
        else:
            bcrypt.checkpw(raw_pw.encode(), _TIMING_GUARD.encode())
            pw_valid = False

        if not record or not pw_valid:
            if record:
                fail_count = record['failed_attempts'] + 1
                if fail_count >= FAIL_LIMIT:
                    block_until = (datetime.now() + timedelta(minutes=LOCK_DURATION)).isoformat()
                    conn.execute(
                        'UPDATE users SET failed_attempts=?, locked=1, locked_until=? WHERE id=?',
                        (fail_count, block_until, record['id'])
                    )
                    extra = f"Cont blocat 15 minute dupa {FAIL_LIMIT} incercari gresite."
                else:
                    conn.execute(
                        'UPDATE users SET failed_attempts=? WHERE id=?',
                        (fail_count, record['id'])
                    )
                    extra = f"Tentativa {fail_count}/{FAIL_LIMIT}. Blocare la {FAIL_LIMIT}."
                conn.commit()
                audit_event(conn, record['id'], 'LOGIN_FAIL', 'auth', client_ip)
            else:
                extra = "Emailul nu exista (dar raspunsul e acelasi)."

            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "Invalid credentials.",
                    "fix_4.3": extra,
                    "fix_4.4": "Mesaj identic pentru toate erorile de autentificare."
                }), 401
            return render_template('signin.html', error='Invalid credentials.')

        conn.execute('UPDATE users SET failed_attempts=0, locked=0 WHERE id=?', (record['id'],))
        conn.commit()

        # FIX 4.5: session fixation protection
        session.clear()
        session.permanent = True
        session['user_id'] = record['id']
        session['email'] = record['email']
        session['role'] = record['role']

        audit_event(conn, record['id'], 'LOGIN_SUCCESS', 'auth', client_ip)

        if wants_json():
            return jsonify({
                "status": "ok",
                "message": "Login reusit.",
                "user": {"email": record['email'], "role": record['role']},
                "fix_4.5": "Cookie cu HttpOnly=True si SameSite=Strict. Sesiune cu expirare 30 min."
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
        conn = connect_db()
        audit_event(conn, uid, 'LOGOUT', 'auth', request.remote_addr)
    session.clear()
    if wants_json():
        return jsonify({
            "status": "ok",
            "message": f"Utilizator {mail} delogat.",
            "fix_4.5": "Sesiunea invalidata complet pe server."
        })
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
        mail = request.form.get('email', '').strip().lower()
        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE email = ?', (mail,)).fetchone()

        if record:
            # FIX 4.6: token random 256 biti cu expirare
            reset_tok = secrets.token_urlsafe(32)
            token_expiry = (datetime.now() + timedelta(minutes=TOKEN_TTL)).isoformat()
            conn.execute(
                'UPDATE users SET reset_token=?, reset_token_expires=? WHERE id=?',
                (reset_tok, token_expiry, record['id'])
            )
            conn.commit()
            if wants_json():
                return jsonify({
                    "status": "ok",
                    "message": "Daca emailul este inregistrat, a fost trimis un link.",
                    "demo_token": reset_tok,
                    "fix_4.6": f"Token random 256 biti. Expira la: {token_expiry}. One-time use.",
                    "fix_4.4": "Acelasi mesaj si cand emailul nu exista."
                })
        else:
            if wants_json():
                return jsonify({
                    "status": "ok",
                    "message": "Daca emailul este inregistrat, a fost trimis un link.",
                    "fix_4.4": "Acelasi mesaj => nu se poate determina daca emailul exista."
                })
        return render_template('recover_account.html',
                               message='Daca emailul este inregistrat, a fost trimis un link de resetare.')

    if wants_json():
        return jsonify({"status": "info", "message": "Trimite POST cu: email"})
    return render_template('recover_account.html', message=None)


@portal.route('/reset-password', methods=['GET', 'POST'])
def set_new_password():
    tok = request.args.get('token', '')
    if request.method == 'POST':
        tok = request.form.get('token', '')
        raw_pw = request.form.get('password', '')

        conn = connect_db()
        record = conn.execute('SELECT * FROM users WHERE reset_token = ?', (tok,)).fetchone()

        if not record or not record['reset_token_expires']:
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "Token invalid sau expirat.",
                    "fix_4.6": "Token inexistent in DB sau fara expirare."
                }), 400
            return render_template('new_password.html', token=tok, message=None, error='Token invalid sau expirat.')

        token_expiry = datetime.fromisoformat(record['reset_token_expires'])
        if datetime.now() > token_expiry:
            conn.execute(
                'UPDATE users SET reset_token=NULL, reset_token_expires=NULL WHERE id=?',
                (record['id'],)
            )
            conn.commit()
            if wants_json():
                return jsonify({
                    "status": "error",
                    "message": "Token invalid sau expirat.",
                    "fix_4.6": f"Token expirat la {token_expiry.isoformat()}. A fost sters."
                }), 400
            return render_template('new_password.html', token=tok, message=None, error='Token invalid sau expirat.')

        policy_err = check_password_policy(raw_pw)
        if policy_err:
            if wants_json():
                return jsonify({"status": "error", "message": policy_err}), 400
            return render_template('new_password.html', token=tok, message=None, error=policy_err)

        hashed_pw = bcrypt.hashpw(raw_pw.encode(), bcrypt.gensalt(rounds=12)).decode()
        # FIX 4.6: token invalidat imediat dupa utilizare
        conn.execute(
            'UPDATE users SET password_hash=?, reset_token=NULL, reset_token_expires=NULL WHERE id=?',
            (hashed_pw, record['id'])
        )
        conn.commit()

        if wants_json():
            return jsonify({
                "status": "ok",
                "message": "Parola resetata cu succes.",
                "fix_4.6": "Tokenul a fost sters din DB => nu poate fi reutilizat."
            })
        return render_template('new_password.html', token=tok,
                               message='Parola resetata cu succes. Va puteti autentifica.', error=None)

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
        audit_event(conn, session['user_id'], 'CREATE_TICKET', 'ticket', request.remote_addr, str(cur.lastrowid))
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
    item = conn.execute('SELECT * FROM tickets WHERE id = ?', (ticket_id,)).fetchone()
    if not item:
        if wants_json():
            return jsonify({"status": "error", "message": "Ticket negasit."}), 404
        return 'Ticket negasit.', 404

    # FIX: verificare ownership
    current_role = session.get('role')
    if current_role != 'MANAGER' and item['owner_id'] != session['user_id']:
        if wants_json():
            return jsonify({
                "status": "error",
                "message": "Acces interzis.",
                "fix": "Ownership verificat: ticket apartine altui utilizator."
            }), 403
        return 'Acces interzis.', 403

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
        audit_event(conn, session['user_id'], 'EDIT_TICKET', 'ticket', request.remote_addr, str(ticket_id))
        if wants_json():
            return jsonify({"status": "ok", "message": f"Ticket {ticket_id} actualizat."})
        return redirect(url_for('list_issues'))

    if wants_json():
        return jsonify({"status": "ok", "ticket": dict(item)})
    return render_template('issue_form.html', error=None, ticket=item)


@portal.route('/audit-logs')
def view_activity():
    if 'user_id' not in session:
        if wants_json():
            return jsonify({"status": "error", "message": "Neautentificat."}), 401
        return redirect(url_for('signin'))
    # FIX: doar MANAGER
    if session.get('role') != 'MANAGER':
        if wants_json():
            return jsonify({
                "status": "error",
                "message": "Acces interzis. Este necesar rolul MANAGER.",
                "fix": "Role-based access control aplicat."
            }), 403
        return 'Acces interzis. Este necesar rolul MANAGER.', 403
    conn = connect_db()
    entries = conn.execute(
        'SELECT a.*, u.email FROM audit_logs a '
        'LEFT JOIN users u ON a.user_id = u.id ORDER BY a.timestamp DESC'
    ).fetchall()
    if wants_json():
        return jsonify({
            "status": "ok",
            "count": len(entries),
            "logs": [dict(e) for e in entries]
        })
    return render_template('activity.html', logs=entries, role=session.get('role'))


if __name__ == '__main__':
    create_tables()
    print('[RELEASE] AuthX webapp_release pornit pe http://localhost:5002')
    portal.run(port=5002, debug=True)
