#source massanger/bin/activate

#   User Name   Password
#   om          om@123
#   sam         sam@123


from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from forms import LoginForm, SignupForm, MessageForm  # Ensure forms.py is correctly defined

from cryptography.hazmat.primitives.asymmetric import rsa

# from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives import padding

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend

from cryptography.exceptions import InvalidSignature

import base64

import os
import logging
from flask_migrate import Migrate
from werkzeug.utils import secure_filename

from flask_socketio import SocketIO



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


socketio = SocketIO(app)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    iv = db.Column(db.Text, nullable=False)
    ciphertext = db.Column(db.Text, nullable=False)
    encrypted_aes_key = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(256))


def rsa_encrypt(public_key, data):

    try:

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

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return render_template('DesignSignup.html', form=form)
        
        # Generate RSA key pair for the user using the cryptography library
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
    
    return render_template('DesignSignup.html', form=form)



@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('inbox'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('DesignLogin.html', form=form)

@app.route('/inbox')
@login_required
def inbox():
    received_messages = Message.query.filter_by(receiver_id=current_user.id).all()
    return render_template('inbox.html', messages=received_messages)

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    message = Message.query.get_or_404(message_id)
    
    if message.receiver_id != current_user.id:
        abort(403)  # Forbidden if the user does not own the message
    
    db.session.delete(message)
    db.session.commit()
    flash('Message deleted successfully!', 'success')
    return redirect(url_for('inbox'))

@app.route('/send_message', methods=['GET', 'POST'])
@login_required
def send_message():
    form = MessageForm()
    form.receiver_id.choices = [(user.id, user.username) for user in User.query.all()]
    if form.validate_on_submit():
        receiver = User.query.get(form.receiver_id.data)
        aes_key = get_random_bytes(16)  # Generate AES key
        encrypted_aes_key = rsa_encrypt(RSA.import_key(receiver.public_key), aes_key)
        
        image_filename = None
        if 'image' in request.files and allowed_file(request.files['image'].filename):
            image_file = request.files['image']
            image_filename = secure_filename(image_file.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image_file.save(image_path)

        iv, ciphertext = aes_encrypt(aes_key, form.message.data)
        
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver.id,
            iv=iv,
            ciphertext=ciphertext,
            encrypted_aes_key=encrypted_aes_key,
            image=image_filename
        )
        
        db.session.add(message)
        db.session.commit()
        flash('Message sent successfully!', 'success')
        return redirect(url_for('inbox'))
    
    return render_template('send_message.html', form=form)

@app.route('/view_message/<int:message_id>', methods=['GET'])
@login_required
def view_message(message_id):
    message = Message.query.get_or_404(message_id)

    if message.receiver_id != current_user.id:
        abort(403)

    aes_key = rsa_decrypt(RSA.import_key(current_user.private_key), message.encrypted_aes_key)
    plaintext_message = aes_decrypt(aes_key, message.iv, message.ciphertext)

    return render_template('receive_message.html', message=plaintext_message, image_path=message.image)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
        # Ensure database migrations are applied
    from flask_migrate import upgrade
    with app.app_context():
        upgrade()
    socketio.run(app, debug=True)

