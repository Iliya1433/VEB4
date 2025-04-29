from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_password(password):
    if len(password) < 8 or len(password) > 128:
        return False, "Password must be between 8 and 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if re.search(r'\s', password):
        return False, "Password cannot contain spaces"
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'\.,:;]+$', password):
        return False, "Password contains invalid characters"
    return True, ""

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        user = User.query.filter_by(login=login).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid login or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/user/new', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        if not login or not password or not first_name:
            flash('Required fields cannot be empty')
            return render_template('user_form.html', roles=Role.query.all())

        if not re.match(r'^[a-zA-Z0-9]{5,}$', login):
            flash('Login must be at least 5 characters long and contain only Latin letters and numbers')
            return render_template('user_form.html', roles=Role.query.all())

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message)
            return render_template('user_form.html', roles=Role.query.all())

        user = User(
            login=login,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            role_id=role_id if role_id else None
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user')
            return render_template('user_form.html', roles=Role.query.all())

    return render_template('user_form.html', roles=Role.query.all())

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        if not first_name:
            flash('First name cannot be empty')
            return render_template('user_form.html', user=user, roles=Role.query.all())

        user.first_name = first_name
        user.last_name = last_name
        user.middle_name = middle_name
        user.role_id = role_id if role_id else None

        try:
            db.session.commit()
            flash('User updated successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user')
            return render_template('user_form.html', user=user, roles=Role.query.all())

    return render_template('user_form.html', user=user, roles=Role.query.all())

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(old_password):
            flash('Current password is incorrect')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match')
            return render_template('change_password.html')

        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message)
            return render_template('change_password.html')

        current_user.set_password(new_password)
        try:
            db.session.commit()
            flash('Password changed successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error changing password')
            return render_template('change_password.html')

    return render_template('change_password.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 