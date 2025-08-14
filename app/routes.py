from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, session
from flask_login import login_user, logout_user, login_required, current_user
from .models import User, Post
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField, TextAreaField, IntegerField, FileField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length
import os
from io import BytesIO
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

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

    def validate_days_left(self, field):
        if field.data < 1 or field.data > 365:
            raise ValidationError('Days Left must be between 1 and 365.')

    def validate_image(self, field):
        if field.data:
            file = field.data
            if file and file.content_type not in ['image/jpeg', 'image/png']:
                raise ValidationError('Only JPEG and PNG images are allowed.')
            if file and len(file.read()) > 5 * 1024 * 1024:  # 5MB limit
                raise ValidationError('Image size must not exceed 5MB.')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=100)])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    profile_image = FileField('Profile Image (Optional)')
    document = FileField('Upload Verification Document (Optional)')
    submit = SubmitField('Save Changes')

    def validate_profile_image(self, field):
        if field.data:
            file = field.data
            if file and file.content_type not in ['image/jpeg', 'image/png']:
                raise ValidationError('Only JPEG and PNG images are allowed.')
            if file and len(file.read()) > 5 * 1024 * 1024:  # 5MB limit
                raise ValidationError('Image size must not exceed 5MB.')

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
        user = User(username=form.username.data, email=form.email.data, password_hash=generate_password_hash(form.password.data, method='pbkdf2:sha256'), role=form.role.data, name=form.username.data, verification_status='pending')
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Log in to access your dashboard.', 'success')
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
    logger.debug(f"Current user role: {current_user.role}")
    posts = Post.query.filter_by(status='approved').all()
    return render_template('discovery.html', posts=posts, current_user=current_user)

@main.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    form = PostForm()
    if current_user.role in ['organization', 'individual'] and current_user.verification_status != 'approved':
        session['show_alert'] = 'post_restriction'
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

@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm()
    logger.debug(f"Profile route - Verification status: {current_user.verification_status}, Validators: {form.document.validators}")
    # Dynamically set document validator based on verification status
    if current_user.verification_status in ['pending', 'rejected']:
        form.document.validators = [DataRequired()]
    else:
        form.document.validators = []

    if form.validate_on_submit():
        logger.debug(f"Form validated: Username={form.username.data}, Bio={form.bio.data}, Document={form.document.data is not None}")
        current_user.username = form.username.data
        current_user.bio = form.bio.data
        if form.profile_image.data:
            current_user.profile_image = form.profile_image.data.read()
        if form.document.data and current_user.verification_status == 'pending':
            current_user.verification_documents = form.document.data.read()
            current_user.verification_status = 'pending'  # Reset for review
            session['show_alert'] = 'doc_submitted'
        try:
            db.session.commit()
            logger.debug("Database commit successful")
            flash('Profile updated successfully!', 'success')
        except Exception as e:
            logger.error(f"Database commit failed: {str(e)}")
            flash('Error updating profile. Please try again.', 'danger')
        return redirect(url_for('main.profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.bio.data = current_user.bio
    return render_template('profile.html', form=form, current_user=current_user)

@main.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('main.discovery'))
    posts = Post.query.filter_by(status='pending').all()
    users = User.query.filter(User.verification_status == 'pending', User.role.in_(['organization', 'individual'])).all()
    return render_template('admin_dashboard.html', posts=posts, users=users, current_user=current_user)

@main.route('/approve_user/<int:user_id>')
@login_required
def approve_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.discovery'))
    user = User.query.get_or_404(user_id)
    user.verification_status = 'approved'
    db.session.commit()
    flash('User verified and approved!', 'success')
    return redirect(url_for('main.admin_dashboard'))

@main.route('/reject_user/<int:user_id>')
@login_required
def reject_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.discovery'))
    user = User.query.get_or_404(user_id)
    user.verification_status = 'rejected'
    db.session.commit()
    flash('User verification rejected.', 'success')
    return redirect(url_for('main.admin_dashboard'))

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

@main.route('/download_document/<int:user_id>')
@login_required
def download_document(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to perform this action.', 'danger')
        return redirect(url_for('main.discovery'))
    user = User.query.get_or_404(user_id)
    if user.verification_documents:
        return send_file(
            BytesIO(user.verification_documents),
            as_attachment=True,
            download_name=f'verification_{user.username}.pdf',
            mimetype='application/pdf'
        )
    flash('No document available for this user.', 'warning')
    return redirect(url_for('main.admin_dashboard'))