from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, Post
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField, IntegerField, FileField
from wtforms.validators import DataRequired, Email, EqualTo
import os

main = Blueprint('main', __name__)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[('sponsor', 'Sponsor'), ('organization', 'Organization'), ('individual', 'Individual'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')

class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    image = FileField('Image Upload')
    priority = SelectField('Priority', choices=[('High', 'High'), ('Medium', 'Medium'), ('Low', 'Low')], validators=[DataRequired()])
    days_left = IntegerField('Days Left', validators=[DataRequired()])
    submit = SubmitField('Submit Request')

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('main.register'))
        user = User(username=form.username.data, email=form.email.data, password_hash=generate_password_hash(form.password.data, method='pbkdf2:sha256'), role=form.role.data, name=form.username.data, verification_status='approved')
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            return redirect(url_for('main.discovery'))
        flash('Invalid email or password.', 'danger')
    return render_template('login.html', form=form)

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))

@main.route('/discovery')
@login_required
def discovery():
    print(f"Current user role: {current_user.role}")
    return render_template('discovery.html', current_user=current_user)

@main.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if current_user.role not in ['organization', 'individual', 'admin']:
        flash('You do not have permission to create a post.', 'danger')
        return redirect(url_for('main.discovery'))
    if form.validate_on_submit():
        image_binary = None
        if form.image.data:
            image_file = form.image.data
            image_binary = image_file.read()
        post = Post(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            image_binary=image_binary,
            priority=form.priority.data,
            days_left=form.days_left.data,
            status='pending'
        )
        db.session.add(post)
        db.session.commit()
        flash('Post submitted for approval!', 'success')
        return redirect(url_for('main.discovery'))
    return render_template('post.html', form=form, current_user=current_user)

@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.discovery'))
    posts = Post.query.filter_by(status='pending').all()
    return render_template('admin_dashboard.html', posts=posts, current_user=current_user)

@main.route('/approve_post/<int:post_id>')
@login_required
def approve_post(post_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.discovery'))
    post = Post.query.get_or_404(post_id)
    post.status = 'approved'
    db.session.commit()
    flash('Post approved!', 'success')
    return redirect(url_for('main.admin_dashboard'))

@main.route('/reject_post/<int:post_id>')
@login_required
def reject_post(post_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.discovery'))
    post = Post.query.get_or_404(post_id)
    db.session.delete(post)
    db.session.commit()
    flash('Post rejected!', 'success')
    return redirect(url_for('main.admin_dashboard'))