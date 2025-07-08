from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField
from wtforms.validators import InputRequired, Length, ValidationError
from werkzeug.security import generate_password_hash, check_password_hash
import os

# --- Setup ---
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')  # safer fallback
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# CSRF enabled by default

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)  # hash is long

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(100), nullable=False)
    food_type = db.Column(db.String(50), nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    contact_info = db.Column(db.String(100), nullable=False)

# --- Login Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Forms ---
class RegisterUserForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Username already exists.")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8, max=100)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    event_name = StringField('Event Name', validators=[InputRequired(), Length(min=3, max=100)])
    food_type = StringField('Food Type', validators=[InputRequired(), Length(min=3, max=50)])
    event_date = DateField('Event Date', validators=[InputRequired()])
    location = StringField('Location', validators=[InputRequired(), Length(min=3, max=100)])
    contact_info = StringField('Contact Info', validators=[InputRequired(), Length(min=10, max=100)])
    submit = SubmitField('Submit')

# --- Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash("Invalid username or password.", "error")
    return render_template('login.html', form=form)

@app.route('/register-user', methods=['GET', 'POST'])
def register_user():
    form = RegisterUserForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register_user.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    events = Event.query.all()
    return render_template('dashboard.html', events=events)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_event = Event(
            event_name=form.event_name.data,
            food_type=form.food_type.data,
            event_date=form.event_date.data,
            location=form.location.data,
            contact_info=form.contact_info.data
        )
        db.session.add(new_event)
        db.session.commit()
        flash("Food donation registered!", "success")
        return redirect(url_for('dashboard'))
    return render_template('register.html', form=form)

# --- Run ---
if __name__ == '__main__':
    app.run(debug=True)
