# imports for file
from flask import Flask, render_template, redirect, request, url_for, flash, session
import os

# imports for forms
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
from wtforms import StringField, SubmitField, PasswordField, BooleanField

# imports for SQLAlchemy
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import Engine
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

# imports for login manager
from flask_login import LoginManager, login_user, current_user, logout_user, login_required, UserMixin
from flask_bcrypt import Bcrypt

# init app
app = Flask("Oulu Web Portal 2")

# set random secret key for development
SECRET_KEY = os.urandom(32)

# App config
app.config['SECRET_KEY'] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# init db, bcrypt, login_manager
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user

# db classes, move to models.py file
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(256), nullable=True)
    username = db.Column(db.String(256), unique=True, nullable=False)
    email = db.Column(db.String(256), nullable=False)
    pw_hash = db.Column(db.String(256), nullable=False)
    admin = db.Column(db.Boolean, default=False)

    slices = db.relationship("Slice", back_populates="user")

class Slice(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(256), unique=True, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"))
    slice_info = db.Column(db.LargeBinary, nullable=True)

    user = db.relationship("User", back_populates="slices")

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(256), nullable=False)
    username = db.Column(db.String(256), unique=True, nullable=False)
    email = db.Column(db.String(256), nullable=False)
    organization = db.Column(db.String(256), nullable=True)
    message = db.Column(db.String(256), nullable=True)


# support foreign keys
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

# create user database
db.create_all()

# Create default user (admin). Remove from use on deployment!
try:
    hashed_pw = bcrypt.generate_password_hash("admin").decode('utf-8')
    default_user = User(username='admin',email='test@email.com',pw_hash=hashed_pw,admin=True)
    db.session.add(default_user)
    db.session.commit()
except IntegrityError:
    pass

# form classes, move to forms.py file
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    name = StringField('Full name', validators=[Length(min=1, max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username taken')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('An account with that email already exists')

class ContactForm(FlaskForm):
    name = StringField('Full name', validators=[DataRequired(), Length(min=1, max=100)])
    username = StringField('Requested username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    organization = StringField('Organization', validators=[DataRequired(), Length(min=1, max=100)])
    message = StringField('Message', validators=[DataRequired(), Length(min=1, max=255)])

    submit = SubmitField('Request access')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username taken')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('An account with that email already exists')

class PwForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])

    submit = SubmitField('Change password')

# Home / Base URL
@app.route("/", methods=["GET", "POST"])
@app.route("/home", methods=["GET", "POST"])
def home():
    return render_template('index.html')

# Login / Register
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.pw_hash, form.password.data):
            login_user(user)
            session["user"] = user.id
            return redirect(url_for('slices'))
        else:
            flash('Login Failed. Please Check Username and Password', 'error')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    if current_user.is_authenticated:
        logout_user()
        flash('You have successfully logged yourself out.')
    return redirect(url_for('home'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if not current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegisterForm()
    if form.validate_on_submit():
        # Hash the password and insert the user in SQLAlchemy db
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, username=form.username.data, email=form.email.data, pw_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Account created!', 'success')
        return redirect(url_for('access_requests'))
    return render_template('register.html', form=form)

@app.route("/slices")
def slices():
    if current_user.is_authenticated:
        return render_template('slices.html')
    return redirect(url_for('login'))

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = ContactForm()
    if form.validate_on_submit():
        # Hash the password and insert the user in SQLAlchemy db
        contact_request = Contact(name=form.name.data,
                               username=form.username.data,
                               email=form.email.data,
                               organization=form.organization.data,
                               )
        db.session.add(contact_request)
        db.session.commit()
        flash('Access request sent!', 'success')
        return redirect(url_for('home'))
    return render_template('contact.html', form=form)

@app.route("/newslice")
def newslice():
    if current_user.is_authenticated:
        return render_template('newslice.html')
    return redirect(url_for('login'))

@app.route("/profile")
def profile():
    if current_user.is_authenticated:
        return render_template('profile.html', user=current_user)
    return redirect(url_for('login'))

@app.route("/users")
def users():
    if current_user.is_authenticated:
        if current_user.admin:
            users = User.query.all()
            return render_template('users.html', users=users)
        flash('You need admin privileges to access this page!', 'danger')
        return redirect(url_for('slices'))
    return redirect(url_for('login'))

@app.route("/accessrequests")
def access_requests():
    if current_user.is_authenticated:
        if current_user.admin:
            requests = Contact.query.all()
            return render_template('accessrequests.html', requests=requests)
        flash('You need admin privileges to access this page!', 'danger')
        return redirect(url_for('slices'))
    return redirect(url_for('login'))

@app.route("/deleteuser/<user_id>", methods=["GET", "POST"])
def delete_user(user_id):
    if current_user.is_authenticated:
        if current_user.admin or str(current_user.id) == str(user_id):
            user = User.query.filter_by(id=user_id).first()
            db.session.delete(user)
            db.session.commit()
            flash('User deleted!', 'success')
            return redirect(url_for('home'))
        flash('You lack the credentials to access this page!', 'danger')
        return redirect(url_for('slices'))
    return redirect(url_for('login'))

@app.route("/pwchange/<user_id>", methods=["GET", "POST"])
def change_pw(user_id):
    if current_user.is_authenticated:
        if current_user.admin or str(current_user.id) == str(user_id):
            form = PwForm()
            user = User.query.filter_by(id=user_id).first()
            if form.validate_on_submit():
                # Hash the password and insert the user in SQLAlchemy db
                hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
                user.pw_hash = hashed_pw
                db.session.commit()
                flash('Password changed!', 'success')
                return redirect(url_for('home'))
            return render_template('pwchange.html', form=form, user=user)
        flash('You lack the credentials to access this page!', 'danger')
        return redirect(url_for('slices'))
    return redirect(url_for('login'))

@app.route("/toggleadmin/<user_id>", methods=["GET", "POST"])
def toggle_admin(user_id):
    if current_user.is_authenticated:
        if current_user.admin:
            user = User.query.filter_by(id=user_id).first()
            user.admin = not user.admin
            db.session.commit()
            return redirect(url_for('users'))
        flash('You lack the credentials to access this page!', 'danger')
        return redirect(url_for('slices'))
    return redirect(url_for('login'))

# Toggle debug mode (run as "python3 app.py")
if __name__ == "__main__":
    app.run(debug=True)
