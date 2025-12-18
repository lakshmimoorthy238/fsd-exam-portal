import json
from datetime import datetime,timedelta
from flask import Flask, g, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from werkzeug.security import generate_password_hash
DATABASE = 'exam_prep.db'
SECRET_KEY = 'replace_this_with_a_random_secret_key'  # change for production
FORBIDDEN_ADMIN_EMAIL = 'admin@admin.local'  # admin is predefined; users cannot register this email

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ---------- DB helpers ----------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exc):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

def execute_db(query, args=()):
    db = get_db()
    cur = db.execute(query, args)
    db.commit()
    return cur.lastrowid

# ---------- decorators ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

# ---------- routes ----------
@app.route('/')
def index():
    return render_template('index.html')

# Registration (users only)



@app.route('/register', methods=['GET', 'POST'])
def register():
    # Show registration form
    if request.method == 'GET':
        today = datetime.now().strftime('%Y-%m-%d')
        return render_template('register.html', today=today)

    # Handle POST (form submission)
    email = (request.form.get('email') or '').strip().lower()
    password = request.form.get('password') or ''
    full_name = (request.form.get('full_name') or '').strip()
    qualification = (request.form.get('qualification') or '').strip() or None
    dob = request.form.get('dob') or None

    # Basic server-side validation
    if not email:
        flash('Email is required.', 'danger')
        return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))
    if not password or len(password) < 6:
        flash('Password must be at least 6 characters.', 'danger')
        return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))
    if not full_name:
        flash('Full name is required.', 'danger')
        return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))

    # Prevent future DOB
    if dob:
        try:
            dob_date = datetime.strptime(dob, '%Y-%m-%d').date()
            if dob_date > datetime.now().date():
                flash('Date of birth cannot be in the future.', 'danger')
                return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))
        except ValueError:
            flash('Invalid date of birth format.', 'danger')
            return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))

    # Check for existing account
    try:
        existing = query_db('SELECT id FROM users WHERE email = ?', (email,), one=True)
    except Exception:
        existing = None

    if existing:
        flash('An account with this email already exists. Please login or use a different email.', 'danger')
        return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))

    # Hash the password
    pw_hash = generate_password_hash(password)

    # Insert into users table — column names match your schema
    sql = '''
        INSERT INTO users (email, password_hash, full_name, qualification, dob)
        VALUES (?, ?, ?, ?, ?)
    '''
    params = (email, pw_hash, full_name, qualification, dob)

    try:
        # Prefer using your execute_db helper if available
        try:
            execute_db(sql, params)
        except NameError:
            # Fallback: direct sqlite3 if execute_db is not defined
            import sqlite3
            con = sqlite3.connect('exam_prep.db')
            cur = con.cursor()
            cur.execute(sql, params)
            con.commit()
            con.close()
    except Exception as e:
        app.logger.exception("Register DB error: %s", e)
        flash('Failed to create account (database error).', 'danger')
        return render_template('register.html', today=datetime.now().strftime('%Y-%m-%d'))

    flash('Account created successfully. Please log in.', 'success')
    return redirect(url_for('login'))



# Login (both admin and users)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip().lower()
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE email = ?', (email,), one=True)
        if not user:
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))
        if not check_password_hash(user['password_hash'], password):
            flash('Invalid credentials.', 'danger')
            return redirect(url_for('login'))

        # set session
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['user_name'] = user['full_name'] or user['email']

        flash('Logged in successfully.', 'success')
        # redirect based on role
        if user['role'] == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))

    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('index'))

# Change password (for any logged-in user)
@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current_password']
        newpw = request.form['new_password']
        user = query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
        if not user or not check_password_hash(user['password_hash'], current):
            flash('Current password incorrect.', 'danger')
            return redirect(url_for('change_password'))
        new_hash = generate_password_hash(newpw)
        execute_db('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, session['user_id']))
        flash('Password changed successfully. Please log in again.', 'success')
        return redirect(url_for('logout'))
    return render_template('change_password.html')

# User dashboard
@app.route('/dashboard')
@login_required
def user_dashboard():
    # Example: list subjects for the user to choose quizzes from
    subjects = query_db('SELECT * FROM subjects')
    return render_template('user_dashboard.html', subjects=subjects)

# Admin dashboard
# at top of app.py ensure these imports exist:
# from datetime import datetime
# import json

@app.route('/admin')
@admin_required
def admin_dashboard():
    # summary counts
    user_count = query_db('SELECT COUNT(*) as c FROM users', one=True)['c']
    subject_count = query_db('SELECT COUNT(*) as c FROM subjects', one=True)['c']
    chapter_count = query_db('SELECT COUNT(*) as c FROM chapters', one=True)['c']
    quiz_count = query_db('SELECT COUNT(*) as c FROM quizzes', one=True)['c']

    # recent quizzes and users
    recent_quizzes = query_db('''
        SELECT q.id, q.title, q.start_datetime, ch.name as chapter_name
        FROM quizzes q
        LEFT JOIN chapters ch ON q.chapter_id = ch.id
        ORDER BY COALESCE(q.created_on, q.id) DESC LIMIT 6
    ''')
    recent_users = query_db('SELECT id, email, full_name FROM users ORDER BY id DESC LIMIT 6')

    # average per quiz for chart
    avg_rows = query_db('''
        SELECT q.title, ROUND( AVG(1.0 * s.score / s.total * 100), 2) as avg_percent
        FROM quizzes q
        LEFT JOIN scores s ON s.quiz_id = q.id
        GROUP BY q.id
        ORDER BY avg_percent DESC
        LIMIT 12
    ''')

    avg_quiz_labels = [r['title'] for r in avg_rows]
    avg_quiz_avgs = [r['avg_percent'] or 0 for r in avg_rows]

    return render_template(
        'admin_dashboard.html',
        user_count=user_count,
        subject_count=subject_count,
        chapter_count=chapter_count,
        quiz_count=quiz_count,
        recent_quizzes=recent_quizzes,
        recent_users=recent_users,
        avg_quiz_labels=json.dumps(avg_quiz_labels),
        avg_quiz_avgs=json.dumps(avg_quiz_avgs),
        last_refreshed=datetime.now().strftime('%Y-%m-%d %H:%M')
    )



# Example protected admin route: add subject
@app.route('/admin/add_subject', methods=['GET', 'POST'])
@admin_required
def add_subject():
    if request.method == 'POST':
        name = request.form['name'].strip()
        desc = request.form.get('description', '').strip()
        if query_db('SELECT id FROM subjects WHERE name = ?', (name,), one=True):
            flash('Subject already exists.', 'warning')
            return redirect(url_for('add_subject'))
        execute_db('INSERT INTO subjects (name, description) VALUES (?,?)', (name, desc))
        flash('Subject added.', 'success')
        return redirect(url_for('admin_dashboard'))
    return render_template('add_subject.html')

# View a subject (user)
@app.route('/subject/<int:subject_id>')
@login_required
def view_subject(subject_id):
    subject = query_db('SELECT * FROM subjects WHERE id = ?', (subject_id,), one=True)
    if not subject:
        flash('Subject not found', 'danger')
        return redirect(url_for('user_dashboard'))
    chapters = query_db('SELECT * FROM chapters WHERE subject_id = ?', (subject_id,))
    return render_template('view_subject.html', subject=subject, chapters=chapters)
# -------------------------
# Admin: Subjects CRUD
# -------------------------
@app.route('/admin/subjects')
@admin_required
def admin_subjects():
    subjects = query_db('SELECT * FROM subjects ORDER BY created_on DESC')
    return render_template('admin_subjects.html', subjects=subjects)

@app.route('/admin/subject/add', methods=['GET','POST'])
@admin_required
def admin_add_subject():
    if request.method == 'POST':
        name = request.form['name'].strip()
        desc = request.form.get('description','').strip()
        if query_db('SELECT id FROM subjects WHERE name = ?', (name,), one=True):
            flash('Subject already exists', 'warning')
            return redirect(url_for('admin_add_subject'))
        execute_db('INSERT INTO subjects (name, description) VALUES (?,?)', (name, desc))
        flash('Subject added', 'success')
        return redirect(url_for('admin_subjects'))
    return render_template('admin_add_edit_subject.html', action='Add')

@app.route('/admin/subject/<int:subject_id>/edit', methods=['GET','POST'])
@admin_required
def admin_edit_subject(subject_id):
    subj = query_db('SELECT * FROM subjects WHERE id = ?', (subject_id,), one=True)
    if not subj:
        flash('Subject not found', 'danger')
        return redirect(url_for('admin_subjects'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        desc = request.form.get('description','').strip()
        execute_db('UPDATE subjects SET name=?, description=? WHERE id=?', (name, desc, subject_id))
        flash('Subject updated', 'success')
        return redirect(url_for('admin_subjects'))
    return render_template('admin_add_edit_subject.html', action='Edit', subject=subj)

@app.route('/admin/subject/<int:subject_id>/delete', methods=['POST'])
@admin_required
def admin_delete_subject(subject_id):
    execute_db('DELETE FROM subjects WHERE id = ?', (subject_id,))
    flash('Subject deleted', 'info')
    return redirect(url_for('admin_subjects'))


# -------------------------
# Admin: Chapters CRUD
# -------------------------
@app.route('/admin/chapters')
@admin_required
def admin_chapters():
    # join with subject name for display
    chapters = query_db('''
        SELECT ch.*, s.name as subject_name FROM chapters ch
        JOIN subjects s ON ch.subject_id = s.id
        ORDER BY ch.created_on DESC
    ''')
    return render_template('admin_chapters.html', chapters=chapters)

@app.route('/admin/chapter/add', methods=['GET','POST'])
@admin_required
def admin_add_chapter():
    subjects = query_db('SELECT * FROM subjects ORDER BY name')
    if request.method == 'POST':
        subject_id = request.form['subject_id']
        name = request.form['name'].strip()
        desc = request.form.get('description','').strip()
        execute_db('INSERT INTO chapters (subject_id, name, description) VALUES (?,?,?)', (subject_id, name, desc))
        flash('Chapter added', 'success')
        return redirect(url_for('admin_chapters'))
    return render_template('admin_add_edit_chapter.html', subjects=subjects, action='Add')

@app.route('/admin/chapter/<int:chapter_id>/edit', methods=['GET','POST'])
@admin_required
def admin_edit_chapter(chapter_id):
    chapter = query_db('SELECT * FROM chapters WHERE id = ?', (chapter_id,), one=True)
    if not chapter:
        flash('Chapter not found', 'danger')
        return redirect(url_for('admin_chapters'))
    subjects = query_db('SELECT * FROM subjects ORDER BY name')
    if request.method == 'POST':
        execute_db('UPDATE chapters SET subject_id=?, name=?, description=? WHERE id=?',
                   (request.form['subject_id'], request.form['name'].strip(), request.form.get('description','').strip(), chapter_id))
        flash('Chapter updated', 'success')
        return redirect(url_for('admin_chapters'))
    return render_template('admin_add_edit_chapter.html', chapter=chapter, subjects=subjects, action='Edit')

@app.route('/admin/chapter/<int:chapter_id>/delete', methods=['POST'])
@admin_required
def admin_delete_chapter(chapter_id):
    execute_db('DELETE FROM chapters WHERE id = ?', (chapter_id,))
    flash('Chapter deleted', 'info')
    return redirect(url_for('admin_chapters'))


# -------------------------
# Admin: Quizzes CRUD
# -------------------------
@app.route('/admin/quizzes')
@admin_required
def admin_quizzes():
    quizzes = query_db('''
        SELECT q.*, ch.name as chapter_name, s.name as subject_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects s ON ch.subject_id = s.id
        ORDER BY q.created_on DESC
    ''')
    return render_template('admin_quizzes.html', quizzes=quizzes)

@app.route('/admin/quiz/add', methods=['GET','POST'])
@admin_required
def admin_add_quiz():
    chapters = query_db('SELECT ch.id, ch.name, s.name as subject_name FROM chapters ch JOIN subjects s ON ch.subject_id = s.id ORDER BY s.name, ch.name')
    if request.method == 'POST':
        chapter_id = request.form['chapter_id']
        title = request.form['title'].strip()
        desc = request.form.get('description','').strip()
        start_dt = request.form.get('start_datetime') or None  # expect 'YYYY-MM-DDTHH:MM' or empty
        # duration as minutes: [hours] and [minutes] fields or single minutes input
        duration_minutes = int(request.form.get('duration_minutes') or 0)
        execute_db('INSERT INTO quizzes (chapter_id, title, description, start_datetime, duration_minutes) VALUES (?,?,?,?,?)',
                   (chapter_id, title, desc, start_dt, duration_minutes))
        flash('Quiz created', 'success')
        return redirect(url_for('admin_quizzes'))
    return render_template('admin_add_edit_quiz.html', chapters=chapters, action='Add')

@app.route('/admin/quiz/<int:quiz_id>/edit', methods=['GET','POST'])
@admin_required
def admin_edit_quiz(quiz_id):
    quiz = query_db('SELECT * FROM quizzes WHERE id = ?', (quiz_id,), one=True)
    if not quiz:
        flash('Quiz not found', 'danger')
        return redirect(url_for('admin_quizzes'))
    chapters = query_db('SELECT id, name FROM chapters ORDER BY name')
    if request.method == 'POST':
        execute_db('UPDATE quizzes SET chapter_id=?, title=?, description=?, start_datetime=?, duration_minutes=? WHERE id=?',
                   (request.form['chapter_id'], request.form['title'].strip(), request.form.get('description','').strip(), request.form.get('start_datetime') or None, int(request.form.get('duration_minutes') or 0), quiz_id))
        flash('Quiz updated', 'success')
        return redirect(url_for('admin_quizzes'))
    return render_template('admin_add_edit_quiz.html', quiz=quiz, chapters=chapters, action='Edit')

@app.route('/admin/quiz/<int:quiz_id>/delete', methods=['POST'])
@admin_required
def admin_delete_quiz(quiz_id):
    execute_db('DELETE FROM quizzes WHERE id = ?', (quiz_id,))
    flash('Quiz deleted', 'info')
    return redirect(url_for('admin_quizzes'))


# -------------------------
# Admin: Questions CRUD (within a quiz)
# -------------------------
@app.route('/admin/quiz/<int:quiz_id>/questions')
@admin_required
def admin_quiz_questions(quiz_id):
    quiz = query_db('SELECT q.*, ch.name as chapter_name FROM quizzes q JOIN chapters ch ON q.chapter_id = ch.id WHERE q.id = ?', (quiz_id,), one=True)
    if not quiz:
        flash('Quiz not found', 'danger')
        return redirect(url_for('admin_quizzes'))
    questions = query_db('SELECT * FROM questions WHERE quiz_id = ? ORDER BY created_on DESC', (quiz_id,))
    return render_template('admin_quiz_questions.html', quiz=quiz, questions=questions)

@app.route('/admin/quiz/<int:quiz_id>/question/add', methods=['GET','POST'])
@admin_required
def admin_add_question(quiz_id):
    quiz = query_db('SELECT * FROM quizzes WHERE id = ?', (quiz_id,), one=True)
    if not quiz:
        flash('Quiz not found', 'danger')
        return redirect(url_for('admin_quizzes'))
    if request.method == 'POST':
        qtext = request.form['question_text'].strip()
        a = request.form['option_a'].strip()
        b = request.form['option_b'].strip()
        c = request.form['option_c'].strip()
        d = request.form['option_d'].strip()
        correct = request.form['correct_option']
        execute_db('INSERT INTO questions (quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option) VALUES (?,?,?,?,?,?,?)',
                   (quiz_id, qtext, a, b, c, d, correct))
        flash('Question added', 'success')
        return redirect(url_for('admin_quiz_questions', quiz_id=quiz_id))
    return render_template('admin_add_edit_question.html', quiz=quiz, action='Add')

@app.route('/admin/question/<int:question_id>/edit', methods=['GET','POST'])
@admin_required
def admin_edit_question(question_id):
    q = query_db('SELECT * FROM questions WHERE id = ?', (question_id,), one=True)
    if not q:
        flash('Question not found', 'danger')
        return redirect(url_for('admin_quizzes'))
    if request.method == 'POST':
        execute_db('UPDATE questions SET question_text=?, option_a=?, option_b=?, option_c=?, option_d=?, correct_option=? WHERE id=?',
                   (request.form['question_text'].strip(), request.form['option_a'].strip(), request.form['option_b'].strip(), request.form['option_c'].strip(), request.form['option_d'].strip(), request.form['correct_option'], question_id))
        flash('Question updated', 'success')
        return redirect(url_for('admin_quiz_questions', quiz_id=q['quiz_id']))
    return render_template('admin_add_edit_question.html', q=q, action='Edit')

@app.route('/admin/question/<int:question_id>/delete', methods=['POST'])
@admin_required
def admin_delete_question(question_id):
    q = query_db('SELECT quiz_id FROM questions WHERE id = ?', (question_id,), one=True)
    if q:
        execute_db('DELETE FROM questions WHERE id = ?', (question_id,))
        flash('Question deleted', 'info')
        return redirect(url_for('admin_quiz_questions', quiz_id=q['quiz_id']))
    flash('Question not found', 'danger')
    return redirect(url_for('admin_quizzes'))


# -------------------------
# Admin: Users list
# -------------------------
@app.route('/admin/users')
@admin_required
def admin_users():
    users = query_db('SELECT id, email, full_name, qualification, dob, role, created_on FROM users ORDER BY created_on DESC')
    return render_template('admin_users.html', users=users)



# (ensure these imports are present at top of file)

# --- List quizzes per subject (user view) ---


# add imports near top of app.py if not already present


# add imports near top of app.py if not already present

from datetime import datetime, timedelta

@app.route('/quizzes')
@login_required
def list_quizzes():
    # fetch all quizzes (no filtering)
    rows = query_db('''
        SELECT q.*, ch.name AS chapter_name, s.name AS subject_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects s ON ch.subject_id = s.id
        ORDER BY q.start_datetime IS NULL, q.start_datetime DESC
    ''')

    # convert sqlite3.Row -> plain dict so we can add/modify fields
    quizzes = [dict(r) for r in rows]

    now = datetime.now()
    GRACE_SECONDS = 60  # optional tolerance

    for q in quizzes:
        q['is_active'] = False
        q['server_end_ts'] = None

        start_raw = q.get('start_datetime')
        duration = q.get('duration_minutes') or 0

        if start_raw:
            start_dt = None
            try:
                start_dt = datetime.fromisoformat(start_raw)
            except Exception:
                try:
                    start_dt = datetime.strptime(start_raw, '%Y-%m-%dT%H:%M')
                except Exception:
                    app.logger.debug("Cannot parse start_datetime for quiz %s: %s", q.get('id'), start_raw)
                    start_dt = None

            if start_dt:
                try:
                    end_dt = start_dt + timedelta(minutes=int(duration))
                except Exception:
                    end_dt = start_dt

                # mark active if current time between start and end+grace
                if start_dt <= now <= (end_dt + timedelta(seconds=GRACE_SECONDS)):
                    q['is_active'] = True
                    q['server_end_ts'] = end_dt.isoformat()
        else:
            # no schedule => available
            q['is_active'] = True

    subjects = query_db('SELECT * FROM subjects ORDER BY name')
    return render_template('list_quizzes.html', quizzes=quizzes, subjects=subjects)



# --- quizzes by subject (optional direct) ---
@app.route('/subject/<int:subject_id>/quizzes')
@login_required
def quizzes_by_subject(subject_id):
    quizzes = query_db('''
        SELECT q.*, ch.name AS chapter_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        WHERE ch.subject_id = ? AND q.is_active = 1
        ORDER BY q.created_on DESC
    ''', (subject_id,))
    subject = query_db('SELECT * FROM subjects WHERE id = ?', (subject_id,), one=True)
    return render_template('list_quizzes.html', quizzes=quizzes, subject=subject)

# --- Take quiz (GET shows questions; POST submits answers) ---


from datetime import datetime, timedelta

from datetime import datetime, timedelta
import sqlite3

@app.route('/quiz/<int:quiz_id>', methods=['GET', 'POST'])
@login_required
def take_quiz(quiz_id):
    # --- load quiz ---
    quiz_row = query_db('SELECT * FROM quizzes WHERE id = ?', (quiz_id,), one=True)
    if not quiz_row:
        flash('Quiz not found.', 'danger')
        return redirect(url_for('list_quizzes'))

    # ensure mutable dict for quiz
    try:
        quiz = dict(quiz_row)
    except Exception:
        quiz = quiz_row

    # --- optional availability check (kept non-blocking by default) ---
    now = datetime.now()
    GRACE_SECONDS = 60
    start_raw = quiz.get('start_datetime')
    duration = quiz.get('duration_minutes') or 0
    can_start = True
    if start_raw:
        try:
            start_dt = datetime.fromisoformat(start_raw)
        except Exception:
            try:
                start_dt = datetime.strptime(start_raw, '%Y-%m-%dT%H:%M')
            except Exception:
                start_dt = None
        if start_dt:
            try:
                end_dt = start_dt + timedelta(minutes=int(duration))
            except Exception:
                end_dt = start_dt
            if start_dt <= now <= (end_dt + timedelta(seconds=GRACE_SECONDS)):
                can_start = True
            else:
                # keep True to allow starting anytime; set False to block
                can_start = True

    if not can_start:
        flash('Quiz is not currently available (scheduled or ended).', 'warning')
        return redirect(url_for('list_quizzes'))

    # --- load questions for the quiz ---
    qrows = query_db('SELECT * FROM questions WHERE quiz_id = ? ORDER BY id', (quiz_id,))
    questions = [dict(q) for q in qrows] if qrows else []

    # --- POST: grade, save score, redirect to result ---
    if request.method == 'POST':
        # make sure user logged in
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to submit the quiz.', 'warning')
            return redirect(url_for('login'))

        total = len(questions)
        correct_count = 0

        for q in questions:
            qid = str(q['id'])

            # support either naming scheme:
            # 1) name="{{ q.id }}"  OR  2) name="question_{{ q.id }}"
            user_ans = request.form.get(qid)
            if user_ans is None:
                user_ans = request.form.get(f'question_{qid}')

            # find the correct answer column (try a few common names)
            correct = None
            for key in ('correct_option','correct_answer','answer','correct','key'):
                if key in q and q.get(key) not in (None, ''):
                    correct = q.get(key)
                    break

            # compare as strings (strip whitespace). If correct is None, treat as wrong.
            try:
                if user_ans is not None and correct is not None and str(user_ans).strip() == str(correct).strip():
                    correct_count += 1
            except Exception:
                # be defensive: don't crash on weird types
                app.logger.debug("Compare failed for qid %s: user=%r correct=%r", qid, user_ans, correct)

        # save score into DB
        try:
            con = sqlite3.connect('exam_prep.db')
            cur = con.cursor()
            cur.execute('''
                INSERT INTO scores (user_id, quiz_id, score, total, taken_on)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, quiz['id'], correct_count, total, datetime.now().isoformat()))
            con.commit()
            score_id = cur.lastrowid
            con.close()
        except Exception as e:
            app.logger.exception("Failed to save quiz score: %s", e)
            flash('Failed to save your score. Please try again.', 'danger')
            return redirect(url_for('list_quizzes'))

        # redirect to result page (make sure you have quiz_result route/template)
        return redirect(url_for('quiz_result', score_id=score_id))

    # --- GET: render page with quiz and questions ---
    server_end_ts = None
    if start_raw and 'end_dt' in locals():
        server_end_ts = end_dt.isoformat()

    return render_template('take_quiz.html',
                           quiz=quiz,
                           questions=questions,
                           server_end_ts=server_end_ts)



# --- User attempts history ---
@app.route('/my_attempts')
@login_required
def my_attempts():
    rows = query_db('''
      SELECT s.*, q.title as quiz_title, ch.name as chapter_name, sub.name as subject_name
      FROM scores s
      JOIN quizzes q ON s.quiz_id = q.id
      JOIN chapters ch ON q.chapter_id = ch.id
      JOIN subjects sub ON ch.subject_id = sub.id
      WHERE s.user_id = ? ORDER BY s.taken_on DESC
    ''', (session['user_id'],))
    return render_template('my_attempts.html', rows=rows)

# --- JSON API helpers (paste near top with other helpers) ---
from flask import jsonify, make_response

def row_to_dict(row):
    """Convert sqlite3.Row to dict"""
    if row is None:
        return None
    return {k: row[k] for k in row.keys()}

def rows_to_list(rows):
    return [row_to_dict(r) for r in rows]

def api_response(data=None, status=200, error=None):
    payload = {"ok": error is None}
    if error is None:
        payload["data"] = data
    else:
        payload["error"] = error
    return make_response(jsonify(payload), status)


# -----------------------
# Public API endpoints
# -----------------------

# GET /api/subjects
@app.route('/api/subjects', methods=['GET'])
def api_get_subjects():
    rows = query_db('SELECT id, name, description, created_on FROM subjects ORDER BY name')
    return api_response(rows_to_list(rows))

# GET /api/subjects/<subject_id>/chapters
@app.route('/api/subjects/<int:subject_id>/chapters', methods=['GET'])
def api_get_chapters(subject_id):
    subject = query_db('SELECT id FROM subjects WHERE id = ?', (subject_id,), one=True)
    if not subject:
        return api_response(error="Subject not found", status=404)
    rows = query_db('SELECT id, name, description, created_on FROM chapters WHERE subject_id = ? ORDER BY name', (subject_id,))
    return api_response(rows_to_list(rows))

# GET /api/chapters/<chapter_id>/quizzes
@app.route('/api/chapters/<int:chapter_id>/quizzes', methods=['GET'])
def api_get_quizzes_by_chapter(chapter_id):
    chapter = query_db('SELECT id FROM chapters WHERE id = ?', (chapter_id,), one=True)
    if not chapter:
        return api_response(error="Chapter not found", status=404)
    rows = query_db('''
        SELECT q.id, q.title, q.description, q.start_datetime, q.duration_minutes, q.is_active, q.created_on
        FROM quizzes q WHERE q.chapter_id = ? ORDER BY q.created_on DESC
    ''', (chapter_id,))
    return api_response(rows_to_list(rows))

# GET /api/quizzes  (optional filters ?subject_id= & ?chapter_id= & ?active=1)
@app.route('/api/quizzes', methods=['GET'])
def api_list_quizzes():
    subject_id = request.args.get('subject_id', type=int)
    chapter_id = request.args.get('chapter_id', type=int)
    active = request.args.get('active')  # '1' or '0' or None

    query = '''
      SELECT q.id, q.title, q.description, q.start_datetime, q.duration_minutes, q.is_active,
             ch.id as chapter_id, ch.name as chapter_name, sub.id as subject_id, sub.name as subject_name
      FROM quizzes q
      JOIN chapters ch ON q.chapter_id = ch.id
      JOIN subjects sub ON ch.subject_id = sub.id
      WHERE 1=1
    '''
    args = []
    if subject_id:
        query += ' AND sub.id = ?'
        args.append(subject_id)
    if chapter_id:
        query += ' AND ch.id = ?'
        args.append(chapter_id)
    if active is not None:
        try:
            v = int(active)
            query += ' AND q.is_active = ?'
            args.append(v)
        except:
            pass
    query += ' ORDER BY q.created_on DESC'
    rows = query_db(query, tuple(args))
    return api_response(rows_to_list(rows))


# GET /api/quiz/<quiz_id>  (includes questions)
@app.route('/api/quiz/<int:quiz_id>', methods=['GET'])
def api_get_quiz(quiz_id):
    quiz = query_db('''
        SELECT q.id, q.title, q.description, q.start_datetime, q.duration_minutes, q.is_active,
               ch.id as chapter_id, ch.name as chapter_name, sub.id as subject_id, sub.name as subject_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects sub ON ch.subject_id = sub.id
        WHERE q.id = ?
    ''', (quiz_id,), one=True)
    if not quiz:
        return api_response(error="Quiz not found", status=404)
    # questions - do NOT reveal correct_option in public endpoint
    questions = query_db('SELECT id, question_text, option_a, option_b, option_c, option_d FROM questions WHERE quiz_id = ? ORDER BY id', (quiz_id,))
    quiz_d = row_to_dict(quiz)
    quiz_d['questions'] = rows_to_list(questions)
    return api_response(quiz_d)


# -----------------------
# Protected API endpoints (scores)
# -----------------------

# GET /api/me/scores  -> requires login (session)
@app.route('/api/me/scores', methods=['GET'])
@login_required
def api_my_scores():
    uid = session['user_id']
    rows = query_db('''
        SELECT s.id, s.quiz_id, s.score, s.total, s.taken_on, q.title as quiz_title,
               ch.name as chapter_name, sub.name as subject_name
        FROM scores s
        JOIN quizzes q ON s.quiz_id = q.id
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects sub ON ch.subject_id = sub.id
        WHERE s.user_id = ? ORDER BY s.taken_on DESC
    ''', (uid,))
    return api_response(rows_to_list(rows))

# GET /api/users/<user_id>/scores -> admin only
@app.route('/api/users/<int:user_id>/scores', methods=['GET'])
@admin_required
def api_user_scores(user_id):
    user = query_db('SELECT id, email, full_name FROM users WHERE id = ?', (user_id,), one=True)
    if not user:
        return api_response(error="User not found", status=404)
    rows = query_db('''
        SELECT s.id, s.quiz_id, s.score, s.total, s.taken_on, q.title as quiz_title,
               ch.name as chapter_name, sub.name as subject_name
        FROM scores s
        JOIN quizzes q ON s.quiz_id = q.id
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects sub ON ch.subject_id = sub.id
        WHERE s.user_id = ? ORDER BY s.taken_on DESC
    ''', (user_id,))
    return api_response({"user": row_to_dict(user), "attempts": rows_to_list(rows)})

# --- Charts & Stats routes ---


@app.route('/stats')
@login_required
def user_stats():
    uid = session['user_id']
    # get user's attempts over time
    rows = query_db('''
        SELECT s.taken_on, s.score, s.total, q.title as quiz_title, q.id as quiz_id
        FROM scores s
        JOIN quizzes q ON s.quiz_id = q.id
        WHERE s.user_id = ?
        ORDER BY s.taken_on ASC
    ''', (uid,))
    # prepare data for line chart: labels (dates) and values (percent)
    timeline_labels = []
    timeline_vals = []
    best_per_quiz = {}  # quiz_id -> best percent and title
    for r in rows:
        # r['taken_on'] stored as ISO; show readable short date
        ts = r['taken_on']
        try:
            # trim seconds if present
            nice = ts.replace('T', ' ')[:16]
        except Exception:
            nice = ts
        percent = round((r['score'] / r['total'])*100, 2) if r['total'] else 0
        timeline_labels.append(nice)
        timeline_vals.append(percent)
        qid = r['quiz_id']
        if qid not in best_per_quiz or percent > best_per_quiz[qid]['percent']:
            best_per_quiz[qid] = {'percent': percent, 'title': r['quiz_title']}

    # prepare best-per-quiz arrays
    bpq_labels = [v['title'] for v in best_per_quiz.values()]
    bpq_vals = [v['percent'] for v in best_per_quiz.values()]

    return render_template('user_stats.html',
                           timeline_labels=json.dumps(timeline_labels),
                           timeline_vals=json.dumps(timeline_vals),
                           bpq_labels=json.dumps(bpq_labels),
                           bpq_vals=json.dumps(bpq_vals)
                           )

@app.route('/admin/stats')
@admin_required
def admin_stats():
    # Average score per quiz
    avg_rows = query_db('''
        SELECT q.id, q.title, AVG( (1.0 * s.score) / s.total * 100 ) as avg_percent, COUNT(s.id) as attempts
        FROM quizzes q
        LEFT JOIN scores s ON s.quiz_id = q.id
        GROUP BY q.id
        ORDER BY avg_percent DESC
    ''')
    quiz_labels = [r['title'] for r in avg_rows]
    quiz_avgs = [round(r['avg_percent'] or 0,2) for r in avg_rows]
    quiz_attempts = [r['attempts'] for r in avg_rows]

    # Users count by role
    role_rows = query_db('SELECT role, COUNT(*) as cnt FROM users GROUP BY role')
    roles = [r['role'] for r in role_rows]
    role_counts = [r['cnt'] for r in role_rows]

    # Top users by average percent
    top_users = query_db('''
        SELECT u.id, u.email, u.full_name, AVG( (1.0*s.score)/s.total*100 ) as avg_percent, COUNT(s.id) as attempts
        FROM users u
        JOIN scores s ON s.user_id = u.id
        GROUP BY u.id
        HAVING attempts > 0
        ORDER BY avg_percent DESC
        LIMIT 10
    ''')

    return render_template('admin_stats.html',
                           quiz_labels=json.dumps(quiz_labels),
                           quiz_avgs=json.dumps(quiz_avgs),
                           quiz_attempts=json.dumps(quiz_attempts),
                           roles=json.dumps(roles),
                           role_counts=json.dumps(role_counts),
                           top_users=top_users
                           )

# debug route — paste into app.py
import json
from flask import jsonify

@app.route('/debug_quizzes')
@login_required
def debug_quizzes():
    # reuse the same logic you have in list_quizzes to compute processed
    from datetime import datetime, timedelta
    rows = query_db('''
        SELECT q.*, ch.name AS chapter_name, s.name AS subject_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects s ON ch.subject_id = s.id
        ORDER BY q.start_datetime IS NULL, q.start_datetime DESC
    ''')

    now = datetime.now()
    GRACE_SECONDS = 60
    processed = []
    for q in rows:
        q['is_active'] = False
        q['server_end_ts'] = None
        start_raw = q.get('start_datetime')
        duration = q.get('duration_minutes') or 0
        if start_raw:
            try:
                start_dt = datetime.fromisoformat(start_raw)
            except Exception:
                try:
                    start_dt = datetime.strptime(start_raw, '%Y-%m-%dT%H:%M')
                except Exception:
                    start_dt = None
            if start_dt:
                try:
                    end_dt = start_dt + timedelta(minutes=int(duration))
                except Exception:
                    end_dt = start_dt
                if start_dt <= now <= (end_dt + timedelta(seconds=GRACE_SECONDS)):
                    q['is_active'] = True
                    q['server_end_ts'] = end_dt.isoformat()
        else:
            q['is_active'] = True
        if q['is_active']:
            processed.append(q)
    # return both original rows and processed for comparison
    return jsonify({
        'now': now.isoformat(),
        'all_quizzes_count': len(rows),
        'active_quizzes_count': len(processed),
        'processed': processed,
        'all_rows_sample': rows[:6]
    })

@app.route('/debug_quizzes_json')
def debug_quizzes_json():
    import json
    from datetime import datetime
    rows = query_db('''
        SELECT q.*, ch.name AS chapter_name, s.name AS subject_name
        FROM quizzes q
        JOIN chapters ch ON q.chapter_id = ch.id
        JOIN subjects s ON ch.subject_id = s.id
        ORDER BY q.start_datetime IS NULL, q.start_datetime DESC
    ''')
    # convert sqlite row objects to JSON-serializable (default=str for dates)
    return json.dumps(rows, indent=4, default=str)

@app.route('/quiz/result/<int:score_id>')
@login_required
def quiz_result(score_id):
    import sqlite3
    con = sqlite3.connect('exam_prep.db')
    con.row_factory = sqlite3.Row
    cur = con.cursor()

    cur.execute('''
        SELECT s.*, 
               q.title AS quiz_title,
               ch.name AS chapter_name,
               sub.name AS subject_name
        FROM scores s
        LEFT JOIN quizzes q ON s.quiz_id = q.id
        LEFT JOIN chapters ch ON q.chapter_id = ch.id
        LEFT JOIN subjects sub ON ch.subject_id = sub.id
        WHERE s.id = ?
    ''', (score_id,))

    row = cur.fetchone()
    con.close()

    if not row:
        flash("Result not found.", "danger")
        return redirect(url_for('list_quizzes'))

    result = dict(row)
    return render_template("quiz_result.html", result=result)



if __name__ == '__main__':
    app.run(host="0.0.0.0",port=5000 )
