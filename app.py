from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from forms import LoginForm, SignupForm, MessageForm, LogoutForm
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from flask_socketio import SocketIO
import base64
import os
import logging
from flask_migrate import Migrate
from PIL import Image
import io

# Setup logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

UPLOAD_FOLDER = 'static/uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
socketio = SocketIO(app, cors_allowed_origins="*")

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    iv = db.Column(db.Text, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(256))
    content = db.Column(db.Text, nullable=True)  # Add content field for message text

    sender = db.relationship('User', foreign_keys=[sender_id])
    receiver = db.relationship('User', foreign_keys=[receiver_id])

def rsa_encrypt(public_key_str, data):
    try:
        # Load public key from string
        public_key = serialization.load_ssh_public_key(
            public_key_str.encode(),
            backend=default_backend()
        )

        encrypted_data = public_key.encrypt(
            data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_base64 = base64.b64encode(encrypted_data).decode('utf-8')
        logging.debug(f"Encrypted data (RSA): {encrypted_base64}")
        return encrypted_base64
    except Exception as e:
        logging.error(f"Error encrypting data with RSA: {e}")
        raise

def rsa_decrypt(private_key, enc_data):
    try:
        decoded_data = base64.b64decode(enc_data)
        decrypted_data = private_key.decrypt(
            decoded_data,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        logging.debug(f"Decrypted data (RSA): {decrypted_data}")
        return decrypted_data
    except Exception as e:
        logging.error(f"Error decrypting data with RSA: {e}")
        raise

def aes_encrypt(key, message):
    try:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ct).decode('utf-8')
    except Exception as e:
        logging.error(f"Error encrypting data with AES: {e}")
        raise

def aes_decrypt(key, iv, ciphertext):
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        return message.decode('utf-8')
    except Exception as e:
        logging.error(f"Error decrypting data with AES: {e}")
        raise

def generate_rsa_key_pair():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    ).decode('utf-8')
    return private_key, public_key

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('signup.html', form=form)

        try:
            private_key, public_key = generate_rsa_key_pair()
            new_user = User(username=username, password=password, public_key=public_key, private_key=private_key)
            db.session.add(new_user)
            db.session.commit()
            flash('Signup successful, please login!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Error during signup: {e}")
            flash('Error during signup. Please try again.', 'danger')
    
    return render_template('signup.html', form=form)

@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('chat'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/chat', defaults={'selected_user_id': None})
@app.route('/chat/<int:selected_user_id>', methods=['GET', 'POST'])
@login_required
def chat(selected_user_id):
    try:
        users = User.query.all()
        if request.method == 'POST':
            message_content = request.form['message']
            receiver_id = request.form['receiver_id']
            new_message = Message(
                sender_id=current_user.id,
                receiver_id=receiver_id,
                content=message_content
            )
            db.session.add(new_message)
            db.session.commit()
            socketio.emit('message', {
                'sender_id': current_user.id,
                'receiver_id': receiver_id,
                'content': message_content
            })
            return jsonify({'status': 'Message sent successfully'})

        messages = []
        selected_chat = None
        if selected_user_id:
            messages = Message.query.filter(
                ((Message.sender_id == current_user.id) & (Message.receiver_id == selected_user_id)) |
                ((Message.sender_id == selected_user_id) & (Message.receiver_id == current_user.id))
            ).all()
            selected_chat = User.query.get(selected_user_id)

        form = LogoutForm() 
        return render_template('chat.html', users=users, messages=messages, selected_chat=selected_chat, form=form)

    except Exception as e:
        logging.error(f"Error retrieving chat data: {e}")
        flash('Error retrieving chat data. Please try again later.', 'danger')
        return redirect(url_for('login'))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    content = request.form.get('message')
    image_file = request.files.get('image')

    # Initialize image_filename
    image_filename = None

    try:
        # Handle image file if provided
        if image_file and allowed_file(image_file.filename):
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)
            print(f"Image file saved to {image_path}") 
            # Store only the filename, not the full path
            # This will be stored in the database
        else:
            # If no image file is uploaded, you can set it to None
            image_filename = None

        # Generate AES key for encryption
        aes_key = os.urandom(32)  # AES-256 key
        iv, encrypted_message = aes_encrypt(aes_key, content.encode())

        # Encrypt AES key with receiver's RSA public key
        receiver = User.query.get(receiver_id)
        encrypted_aes_key = rsa_encrypt(receiver.public_key, aes_key)

        # Store message with encrypted data
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            iv=iv,
            ciphertext=encrypted_message,
            encrypted_aes_key=encrypted_aes_key,
            image=image_filename,  # Store only the filename
            content=content
        )
        db.session.add(message)
        db.session.commit()

        # Emit message event via SocketIO
        socketio.emit('message', {
            'sender_id': current_user.id,
            'receiver_id': receiver_id,
            'content': content,
            'image_url': image_filename  # Send the filename to the frontend
        })

        return jsonify({'status': 'Message sent successfully', 'image_url': image_filename})

    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return jsonify({'status': 'Error sending message. Please try again.'}), 500

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    socketio.run(app, debug=True)
