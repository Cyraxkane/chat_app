from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_socketio import SocketIO, emit, join_room
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from uuid import uuid4
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

db = SQLAlchemy(app)
socketio = SocketIO(app, async_mode='threading')
login_manager = LoginManager(app)
login_manager.login_view = 'login'

online_users = set()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    registered_on = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_banned = db.Column(db.Boolean, default=False)
    is_approved = db.Column(db.Boolean, default=False)
    last_login = db.Column(db.DateTime)
    avatar = db.Column(db.String(120), default='default.jpg')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for public messages
    content = db.Column(db.Text, nullable=True)  # Can be null if it's a file-only message
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    file_path = db.Column(db.String(255), nullable=True)  # Path to uploaded file
    file_type = db.Column(db.String(100), nullable=True)  # MIME type of the file
    
    # Define relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def update_last_seen():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

@app.route('/make_admin/<int:user_id>')
@login_required
def make_admin(user_id):
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            user.is_admin = True
            db.session.commit()
            flash(f"{user.username} is now an admin.")
    return redirect(url_for('dashboard'))

@app.route('/remove_admin/<int:user_id>')
@login_required
def remove_admin(user_id):
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user and user.id != current_user.id:  # Prevent removing yourself
            user.is_admin = False
            db.session.commit()
            flash(f"Admin privileges removed from {user.username}.")
    return redirect(url_for('dashboard'))

@app.route('/approve/<int:user_id>')
@login_required
def approve_user(user_id):
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            user.is_approved = True
            db.session.commit()
            flash(f"{user.username} has been approved.")
    return redirect(url_for('dashboard'))

@app.route('/upload_avatar', methods=['GET', 'POST'])
@login_required
def upload_avatar():
    if request.method == 'POST':
        if 'avatar' not in request.files:
            flash('No file part')
            return redirect(request.url)
            
        file = request.files['avatar']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
            
        if file:
            filename = secure_filename(file.filename)
            unique_filename = f"{uuid4().hex}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            current_user.avatar = unique_filename
            db.session.commit()
            flash('Avatar updated.')
            return redirect(url_for('profile'))
    return render_template('upload_avatar.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash("Username already exists.")
            return redirect(url_for('register'))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Awaiting admin approval.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            if not user.is_approved:
                flash("Account awaiting admin approval.")
                return redirect(url_for('login'))
            if user.is_banned:
                flash("Your account has been banned. Please contact an administrator.")
                return redirect(url_for('login'))
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user)
            return redirect(url_for('dashboard') if user.is_admin else url_for('chat'))
        flash("Invalid credentials.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    if current_user.is_authenticated:
        online_users.discard(current_user.username)
        socketio.emit('update_users', list(online_users))
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    # Get public messages with sender relationship
    messages = Message.query.filter_by(receiver_id=None).order_by(Message.timestamp).all()
    
    # Get all approved and non-banned users
    all_users = User.query.filter_by(is_approved=True, is_banned=False).all()
    
    return render_template('chat.html', 
                          messages=messages, 
                          all_users=all_users, 
                          online_users=online_users)

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin:
        return redirect(url_for('chat'))
    users = User.query.all()
    return render_template('dashboard.html', users=users, online_users=online_users)

@app.route('/ban/<int:user_id>')
@login_required
def ban_user(user_id):
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user and user.id != current_user.id:  # Prevent banning yourself
            user.is_banned = True
            db.session.commit()
            flash(f"{user.username} has been banned.")
    return redirect(url_for('dashboard'))

@app.route('/unban/<int:user_id>')
@login_required
def unban_user(user_id):
    if current_user.is_admin:
        user = User.query.get(user_id)
        if user:
            user.is_banned = False
            db.session.commit()
            flash(f"{user.username} has been unbanned.")
    return redirect(url_for('dashboard'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/private_chat/<int:user_id>')
@login_required
def private_chat(user_id):
    recipient = User.query.get_or_404(user_id)
    
    # Check if recipient is approved and not banned
    if not recipient.is_approved or recipient.is_banned:
        flash("This user is not available for chat.")
        return redirect(url_for('chat'))
    
    # Get private messages between current user and recipient
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.receiver_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.receiver_id == current_user.id))
    ).order_by(Message.timestamp).all()
    
    return render_template('private_chat.html', 
                          recipient=recipient, 
                          messages=messages, 
                          online_users=online_users)

@app.route('/upload_file', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    
    file = request.files['file']
    recipient_id = request.form.get('recipient_id')
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    # Generate a unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid4().hex}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(file_path)
        
        # Save message to database
        recipient = User.query.get(recipient_id)
        if recipient:
            msg = Message(
                sender_id=current_user.id, 
                receiver_id=recipient.id,
                file_path=unique_filename,
                file_type=file.content_type
            )
            db.session.add(msg)
            db.session.commit()
            
            # Emit to recipient
            socketio.emit('private_file', {
                'user': current_user.username,
                'file_path': unique_filename,
                'file_type': file.content_type
            }, room=recipient.username)
            
            return jsonify({
                'success': True, 
                'file_path': unique_filename,
                'file_type': file.content_type
            })
        else:
            return jsonify({'success': False, 'error': 'Recipient not found'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/upload_public_file', methods=['POST'])
@login_required
def upload_public_file():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'})
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'})
    
    # Generate a unique filename
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid4().hex}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    try:
        file.save(file_path)
        
        # Save message to database
        msg = Message(
            sender_id=current_user.id,
            file_path=unique_filename,
            file_type=file.content_type
        )
        db.session.add(msg)
        db.session.commit()
        
        # Broadcast to all users
        socketio.emit('public_file', {
            'user': current_user.username,
            'file_path': unique_filename,
            'file_type': file.content_type
        }, broadcast=True)
        
        return jsonify({
            'success': True, 
            'file_path': unique_filename,
            'file_type': file.content_type
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@socketio.on('connect')
def on_connect():
    if current_user.is_authenticated:
        join_room(current_user.username)
        online_users.add(current_user.username)
        emit('update_users', list(online_users))

@socketio.on('disconnect')
def on_disconnect():
    if current_user.is_authenticated:
        online_users.discard(current_user.username)
        emit('update_users', list(online_users))

@socketio.on('message')
def handle_message(data):
    if current_user.is_authenticated:
        msg = Message(sender_id=current_user.id, content=data['msg'])
        db.session.add(msg)
        db.session.commit()
        emit('message', {'user': current_user.username, 'msg': data['msg']})

@socketio.on('private_message')
def handle_private_message(data):
    if current_user.is_authenticated:
        recipient = User.query.filter_by(username=data['recipient']).first()
        if recipient:
            msg = Message(sender_id=current_user.id, receiver_id=recipient.id, content=data['msg'])
            db.session.add(msg)
            db.session.commit()
            
            # Send to recipient
            emit('private_message', {
                'user': current_user.username, 
                'msg': data['msg']
            }, room=recipient.username)
            
            # Also send back to sender to confirm delivery
            emit('private_message_sent', {
                'recipient': recipient.username,
                'msg': data['msg']
            })

# Create a separate script to initialize the admin user
def create_admin_user():
    with app.app_context():
        db.create_all()
        # Check if admin user exists, if not create one
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully.")
        else:
            print("Admin user already exists.")        # Check if admin user exists, if not

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Check if admin user exists, if not create one
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                password_hash=generate_password_hash('admin123'),
                is_admin=True,
                is_approved=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user created successfully.")
    socketio.run(app,host='0.0.0.0', debug=True)
