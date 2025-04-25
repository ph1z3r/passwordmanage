from flask import render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

from app import app, db
from models import User, Password
from forms import (
    RegistrationForm, LoginForm, AddPasswordForm, ViewPasswordForm,
    GeneratePasswordForm, EditPasswordForm, DeletePasswordForm
)
from generator import PasswordGenerator
from encryption import EncryptionManager

# Initialize components
password_generator = PasswordGenerator()
encryption_manager = EncryptionManager()

@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration route."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Generate salt for master key
        salt = encryption_manager.generate_salt().hex()
        
        # Create new user
        user = User(
            username=form.username.data,
            password_hash=generate_password_hash(form.password.data),
            salt=salt
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Login successful!', 'success')
            
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                next_page = url_for('dashboard')
            
            return redirect(next_page)
        else:
            flash('Login failed. Please check your username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout route."""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard showing all saved passwords."""
    passwords = Password.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', passwords=passwords)

@app.route('/password/add', methods=['GET', 'POST'])
@login_required
def add_password():
    """Add a new password entry."""
    form = AddPasswordForm()
    
    if form.validate_on_submit():
        # Generate password if requested
        if form.generate_password.data:
            try:
                form.password.data = password_generator.generate_password(
                    length=form.password_length.data,
                    use_uppercase=form.include_uppercase.data,
                    use_digits=form.include_digits.data,
                    use_symbols=form.include_symbols.data
                )
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(url_for('add_password'))
        
        # Derive encryption key
        salt_bytes = bytes.fromhex(current_user.salt)
        key = encryption_manager.derive_key(current_user.password_hash, salt_bytes)
        
        # Encrypt password
        encrypted_password, iv = encryption_manager.encrypt(form.password.data, key)
        
        # Save password
        new_password = Password(
            url=form.url.data,
            username=form.username.data,
            encrypted_password=encrypted_password,
            iv=iv,
            notes=form.notes.data,
            user_id=current_user.id
        )
        
        db.session.add(new_password)
        db.session.commit()
        
        flash('Password added successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_password.html', form=form)

@app.route('/password/view/<int:id>', methods=['GET', 'POST'])
@login_required
def view_password(id):
    """View a specific password."""
    password_entry = Password.query.get_or_404(id)
    
    # Ensure user owns this password
    if password_entry.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    form = ViewPasswordForm()
    decrypted_password = None
    
    if form.validate_on_submit() or request.method == 'GET':
        # Derive encryption key
        salt_bytes = bytes.fromhex(current_user.salt)
        key = encryption_manager.derive_key(current_user.password_hash, salt_bytes)
        
        # Decrypt password
        try:
            decrypted_password = encryption_manager.decrypt(
                password_entry.encrypted_password,
                password_entry.iv,
                key
            )
        except Exception as e:
            flash(f'Error decrypting password: {e}', 'danger')
            return redirect(url_for('dashboard'))
    
    return render_template('view_password.html', 
                          password=password_entry, 
                          decrypted_password=decrypted_password,
                          form=form)

@app.route('/password/generate', methods=['GET', 'POST'])
@login_required
def generate_password():
    """Generate a secure password."""
    form = GeneratePasswordForm()
    generated_password = None
    password_strength = None
    
    if form.validate_on_submit():
        try:
            generated_password = password_generator.generate_password(
                length=form.length.data,
                use_uppercase=form.uppercase.data,
                use_digits=form.digits.data,
                use_symbols=form.symbols.data
            )
            
            password_strength = password_generator.evaluate_strength(generated_password)
        except ValueError as e:
            flash(str(e), 'danger')
    
    return render_template('generate_password.html', 
                          form=form,
                          generated_password=generated_password, 
                          password_strength=password_strength)

@app.route('/password/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_password(id):
    """Edit an existing password."""
    password_entry = Password.query.get_or_404(id)
    
    # Ensure user owns this password
    if password_entry.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    form = EditPasswordForm()
    
    if request.method == 'GET':
        form.url.data = password_entry.url
        form.username.data = password_entry.username
        if password_entry.notes:
            form.notes.data = password_entry.notes
    
    if form.validate_on_submit():
        # Generate password if requested
        if form.generate_password.data:
            try:
                form.password.data = password_generator.generate_password(
                    length=form.password_length.data,
                    use_uppercase=form.include_uppercase.data,
                    use_digits=form.include_digits.data,
                    use_symbols=form.include_symbols.data
                )
            except ValueError as e:
                flash(str(e), 'danger')
                return redirect(url_for('edit_password', id=id))
        
        # Derive encryption key
        salt_bytes = bytes.fromhex(current_user.salt)
        key = encryption_manager.derive_key(current_user.password_hash, salt_bytes)
        
        # Encrypt new password
        encrypted_password, iv = encryption_manager.encrypt(form.password.data, key)
        
        # Update password
        password_entry.url = form.url.data
        password_entry.username = form.username.data
        password_entry.encrypted_password = encrypted_password
        password_entry.iv = iv
        password_entry.notes = form.notes.data
        
        db.session.commit()
        
        flash('Password updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_password.html', form=form, password=password_entry)

@app.route('/password/delete/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_password(id):
    """Delete a password entry."""
    password_entry = Password.query.get_or_404(id)
    
    # Ensure user owns this password
    if password_entry.user_id != current_user.id:
        flash('Access denied', 'danger')
        return redirect(url_for('dashboard'))
    
    form = DeletePasswordForm()
    
    if form.validate_on_submit():
        if form.confirm_delete.data:
            db.session.delete(password_entry)
            db.session.commit()
            
            flash('Password deleted successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Please confirm deletion by checking the confirmation box', 'warning')
    
    return render_template('view_password.html', 
                          password=password_entry, 
                          form=form, 
                          delete_mode=True)
