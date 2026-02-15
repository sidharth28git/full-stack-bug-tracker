from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from datetime import datetime
import os

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = 'login'

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='reporter')  # reporter, developer, admin

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

@login.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Bug(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='Open')  # Open, In Progress, Resolved, Closed
    severity = db.Column(db.String(20), default='Medium')  # Low, Medium, High, Critical
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    assignee_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    reporter = db.relationship('User', foreign_keys=[reporter_id], backref='reported_bugs', lazy=True)
    assignee = db.relationship('User', foreign_keys=[assignee_id], backref='assigned_bugs', lazy=True)

# --- Helpers ---
def role_required(*roles):
    def decorator(fn):
        def wrapper(*a, **kw):
            if not current_user.is_authenticated:
                return login.login_view
            if current_user.role not in roles:
                flash('Not authorized.', 'danger')
                return redirect(url_for('index'))
            return fn(*a, **kw)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator

# --- Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        role = request.form.get('role', 'reporter')
        if User.query.filter_by(username=username).first():
            flash('Username taken', 'danger')
            return redirect(url_for('register'))
        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Registered. Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    # quick counts and recent items
    total = Bug.query.count()
    open_count = Bug.query.filter_by(status='Open').count()
    assigned_to_me = Bug.query.filter_by(assignee_id=current_user.id).count()
    recent = Bug.query.order_by(Bug.created_at.desc()).limit(5).all()
    return render_template('dashboard.html', total=total, open_count=open_count,
                           assigned_to_me=assigned_to_me, recent=recent)

@app.route('/bugs')
@login_required
def bug_list():
    # query params: status, severity, assigned
    q = Bug.query
    s = request.args.get('status')
    sev = request.args.get('severity')
    mine = request.args.get('mine')
    if s:
        q = q.filter_by(status=s)
    if sev:
        q = q.filter_by(severity=sev)
    if mine == '1':
        q = q.filter_by(assignee_id=current_user.id)
    bugs = q.order_by(Bug.updated_at.desc()).all()
    users = User.query.all()
    return render_template('bug_list.html', bugs=bugs, users=users)

@app.route('/bugs/new', methods=['GET','POST'])
@login_required
def bug_create():
    if request.method == 'POST':
        title = request.form['title'].strip()
        desc = request.form['description']
        severity = request.form.get('severity','Medium')
        bug = Bug(title=title, description=desc, severity=severity, reporter_id=current_user.id)
        db.session.add(bug)
        db.session.commit()
        flash('Bug reported', 'success')
        return redirect(url_for('bug_list'))
    return render_template('bug_form.html', action='Create')

@app.route('/bugs/<int:bug_id>')
@login_required
def bug_detail(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    users = User.query.all()
    return render_template('bug_detail.html', bug=bug, users=users)

@app.route('/bugs/<int:bug_id>/edit', methods=['GET','POST'])
@login_required
def bug_edit(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    # reporters can edit their own bug while Open. dev/admin can edit any.
    if request.method == 'POST':
        if current_user.role == 'reporter' and bug.reporter_id != current_user.id:
            flash('Not allowed', 'danger')
            return redirect(url_for('bug_detail', bug_id=bug.id))
        bug.title = request.form['title'].strip()
        bug.description = request.form['description']
        bug.severity = request.form.get('severity','Medium')
        bug.status = request.form.get('status', bug.status)
        assignee = request.form.get('assignee')
        bug.assignee_id = int(assignee) if assignee and assignee != 'None' else None
        db.session.commit()
        flash('Bug updated', 'success')
        return redirect(url_for('bug_detail', bug_id=bug.id))
    users = User.query.all()
    return render_template('bug_form.html', action='Edit', bug=bug, users=users)

@app.route('/bugs/<int:bug_id>/delete', methods=['POST'])
@login_required
@role_required('admin')
def bug_delete(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    db.session.delete(bug)
    db.session.commit()
    flash('Bug deleted', 'info')
    return redirect(url_for('bug_list'))

@app.route('/bugs/<int:bug_id>/change_status', methods=['POST'])
@login_required
def change_status(bug_id):
    bug = Bug.query.get_or_404(bug_id)
    new_status = request.form.get('status')
    # simple policy: developer or admin can move to In Progress or Resolved. Reporter can mark Closed only if admin allows. Keep simple:
    if new_status == 'In Progress' and current_user.role not in ('developer','admin'):
        flash('Only developers/admin can start progress', 'danger')
        return redirect(url_for('bug_detail', bug_id=bug.id))
    if new_status == 'Resolved' and current_user.role not in ('developer','admin'):
        flash('Only developers/admin can resolve', 'danger')
        return redirect(url_for('bug_detail', bug_id=bug.id))
    bug.status = new_status
    db.session.commit()
    flash('Status changed', 'success')
    return redirect(url_for('bug_detail', bug_id=bug.id))

@app.route('/users')
@login_required
@role_required('admin')
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)

# Error handlers can be added

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

