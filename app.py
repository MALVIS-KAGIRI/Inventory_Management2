from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, BooleanField
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
import urllib
from dotenv import load_dotenv
from config import Config
from database import db, init_app

# Initialize Flask application
app = Flask(__name__)

# Load configuration
app.config.from_object(Config)

# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Models
# Association table for many-to-many relationship between roles and permissions
role_permissions = db.Table('role_permissions',
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'), primary_key=True),
    db.Column('permission_id', db.Integer, db.ForeignKey('permission.id'), primary_key=True)
)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role', lazy=True)
    permissions = db.relationship('Permission', secondary=role_permissions, 
                                  lazy='subquery', backref=db.backref('roles', lazy=True))

class Permission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = SelectField('Role', coerce=int)
    is_active = BooleanField('Active')
    submit = SubmitField('Add User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already taken.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered.')

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.is_active and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check username, password, and account status.', 'danger')
    
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Check if user has permission to view dashboard
    if not has_permission('dashboard.view'):
        abort(403)
    return render_template('dashboard.html', title='Dashboard', has_permission=has_permission)

@app.route('/inventory')
@login_required
def inventory():
    # Check if user has permission to view inventory
    if not has_permission('inventory.view'):
        abort(403)
    return render_template('inventory.html', title='Inventory Management', has_permission=has_permission)

@app.route('/customers')
@login_required
def customers():
    # Check if user has permission to view customers
    if not has_permission('customers.view'):
        abort(403)
    return render_template('customers.html', title='Customer Management', has_permission=has_permission)

@app.route('/operations')
@login_required
def operations():
    # Check if user has permission to perform basic operations
    if not has_permission('operations.basic'):
        abort(403)
    return render_template('operations.html', title='Basic Operations', has_permission=has_permission)

@app.route('/users')
@login_required
def users():
    # Check if user has permission to view users
    if not has_permission('users.view'):
        abort(403)
        
    users_list = User.query.all()
    return render_template('users.html', title='User Management', users=users_list, has_permission=has_permission)

@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    # Check if user has permission to create users
    if not has_permission('users.create'):
        abort(403)
        
    form = UserForm()
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]
    
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(
            username=form.username.data,
            email=form.email.data,
            password_hash=hashed_password,
            role_id=form.role.data,
            is_active=form.is_active.data
        )
        db.session.add(user)
        db.session.commit()
        flash(f'User {form.username.data} has been created!', 'success')
        return redirect(url_for('users'))
    
    return render_template('add_user.html', title='Add User', form=form, has_permission=has_permission)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Check if user has permission to edit users
    if not has_permission('users.edit'):
        abort(403)
        
    user = User.query.get_or_404(user_id)
    form = UserForm()
    form.role.choices = [(role.id, role.name) for role in Role.query.all()]
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.role_id = form.role.data
        user.is_active = form.is_active.data
        
        if form.password.data:
            user.password_hash = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
        db.session.commit()
        flash('User has been updated!', 'success')
        return redirect(url_for('users'))
    
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.role.data = user.role_id
        form.is_active.data = user.is_active
    
    return render_template('edit_user.html', title='Edit User', form=form, user=user, has_permission=has_permission)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    # Check if user has permission to delete users
    if not has_permission('users.delete'):
        abort(403)
        
    user = User.query.get_or_404(user_id)
    
    # Prevent deletion of own account
    if user.id == current_user.id:
        flash('You cannot delete your own account!', 'danger')
        return redirect(url_for('users'))
    
    db.session.delete(user)
    db.session.commit()
    flash('User has been deleted!', 'success')
    return redirect(url_for('users'))

@app.route('/roles')
@login_required
def roles():
    # Check if user has permission to manage roles
    if not has_permission('roles.manage'):
        abort(403)
        
    roles_list = Role.query.all()
    permissions = Permission.query.all()
    return render_template('roles.html', title='Role Management', roles=roles_list, permissions=permissions, has_permission=has_permission)

@app.route('/roles/<int:role_id>/permissions', methods=['GET', 'POST'])
@login_required
def role_permissions(role_id):
    # Check if user has permission to manage roles
    if not has_permission('roles.manage'):
        abort(403)
        
    role = Role.query.get_or_404(role_id)
    permissions = Permission.query.all()
    
    if request.method == 'POST':
        # Update permissions for the role
        role_permissions = []
        for permission in permissions:
            if str(permission.id) in request.form.getlist('permissions'):
                role_permissions.append(permission)
        
        role.permissions = role_permissions
        db.session.commit()
        flash(f'Permissions for {role.name} role have been updated!', 'success')
        return redirect(url_for('roles'))
    
    return render_template('role_permissions.html', title='Role Permissions', role=role, permissions=permissions, has_permission=has_permission)

# Helper function to check user permissions
def has_permission(permission_name):
    if not current_user.is_authenticated:
        return False
    
    # Fetch the user's role and its permissions
    role = Role.query.get(current_user.role_id)
    if not role:
        return False
    
    # Admin role has all permissions
    if role.name == 'Admin':
        return True
    
    permission = Permission.query.filter_by(name=permission_name).first()
    if not permission:
        return False
    
    return permission in role.permissions

# Initialize the database with default data
def init_db():
    db.create_all()
    
    # Create default roles if they don't exist
    admin_role = Role.query.filter_by(name='Admin').first()
    if not admin_role:
        admin_role = Role(name='Admin', description='Full system access')
        db.session.add(admin_role)
    
    manager_role = Role.query.filter_by(name='Manager').first()
    if not manager_role:
        manager_role = Role(name='Manager', description='Access to inventory and customer management')
        db.session.add(manager_role)
    
    operator_role = Role.query.filter_by(name='Operator').first()
    if not operator_role:
        operator_role = Role(name='Operator', description='Access to basic operations')
        db.session.add(operator_role)
    
    viewer_role = Role.query.filter_by(name='Viewer').first()
    if not viewer_role:
        viewer_role = Role(name='Viewer', description='Read-only access to the system')
        db.session.add(viewer_role)
    
    # Create permissions if they don't exist
    permissions_data = [
        ('users.view', 'View Users'),
        ('users.create', 'Create Users'),
        ('users.edit', 'Edit Users'),
        ('users.delete', 'Delete Users'),
        ('roles.manage', 'Manage Roles'),
        ('dashboard.view', 'View Dashboard'),
        ('settings.edit', 'Edit Settings'),
        ('inventory.view', 'View Inventory'),
        ('inventory.edit', 'Edit Inventory'),
        ('customers.view', 'View Customers'),
        ('customers.edit', 'Edit Customers'),
        ('operations.basic', 'Perform Basic Operations')
    ]
    
    for name, description in permissions_data:
        permission = Permission.query.filter_by(name=name).first()
        if not permission:
            permission = Permission(name=name, description=description)
            db.session.add(permission)
    
    db.session.commit()
    
    # Assign permissions to roles
    admin_role = Role.query.filter_by(name='Admin').first()
    manager_role = Role.query.filter_by(name='Manager').first()
    operator_role = Role.query.filter_by(name='Operator').first()
    viewer_role = Role.query.filter_by(name='Viewer').first()
    
    # Get all permissions
    all_permissions = Permission.query.all()
    dashboard_view = Permission.query.filter_by(name='dashboard.view').first()
    users_view = Permission.query.filter_by(name='users.view').first()
    users_create = Permission.query.filter_by(name='users.create').first()
    users_edit = Permission.query.filter_by(name='users.edit').first()
    users_delete = Permission.query.filter_by(name='users.delete').first()
    roles_manage = Permission.query.filter_by(name='roles.manage').first()
    settings_edit = Permission.query.filter_by(name='settings.edit').first()
    inventory_view = Permission.query.filter_by(name='inventory.view').first()
    inventory_edit = Permission.query.filter_by(name='inventory.edit').first()
    customers_view = Permission.query.filter_by(name='customers.view').first()
    customers_edit = Permission.query.filter_by(name='customers.edit').first()
    operations_basic = Permission.query.filter_by(name='operations.basic').first()
    
    # Admin gets all permissions
    admin_role.permissions = all_permissions
    
    # Manager gets inventory and customer management permissions
    manager_role.permissions = [
        dashboard_view, 
        inventory_view, 
        inventory_edit, 
        customers_view, 
        customers_edit,
        operations_basic
    ]
    
    # Operator gets basic operation permissions
    operator_role.permissions = [
        dashboard_view, 
        operations_basic, 
        inventory_view, 
        customers_view
    ]
    
    # Viewer gets view-only permissions
    viewer_role.permissions = [
        dashboard_view, 
        inventory_view, 
        customers_view
    ]
    
    db.session.commit()
    
    # Create default admin user if no users exist
    if User.query.count() == 0:
        admin_password = bcrypt.generate_password_hash('admin').decode('utf-8')
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password_hash=admin_password,
            role_id=admin_role.id,
            is_active=True
        )
        db.session.add(admin_user)
        db.session.commit()

# Copy environment file from uploads if it exists
def copy_env_from_uploads():
    uploads_env_path = '/workspace/uploads/.env'
    local_env_path = '.env'
    
    if os.path.exists(uploads_env_path) and not os.path.exists(local_env_path):
        try:
            import shutil
            shutil.copy(uploads_env_path, local_env_path)
            print(f"Copied environment file from {uploads_env_path}")
        except Exception as e:
            print(f"Error copying environment file: {e}")

if __name__ == '__main__':
    try:
        # Copy environment file from uploads directory if available
        copy_env_from_uploads()
        
        # Initialize database with app
        if init_app(app):
            with app.app_context():
                # Initialize database with default data after tables are created
                init_db()
            print("Database initialized successfully with all tables and default data")
            app.run(debug=True, port=5000, host='0.0.0.0')
        else:
            print("Database initialization failed. Please check your configuration.")
    except Exception as e:
        print(f"Application initialization error: {e}")
        print("Please check configuration and try again.")