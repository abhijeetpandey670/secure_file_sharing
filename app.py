from flask_jwt_extended import decode_token
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from flask_mail import Mail, Message
import itsdangerous
from dotenv import load_dotenv
load_dotenv()

from extensions import db  # Use db from extensions.py

app = Flask(__name__)
app.config.from_pyfile('config.py')  # Load all config from config.py
mail = Mail(app)
s = itsdangerous.URLSafeTimedSerializer(app.config['SECRET_KEY'])

db.init_app(app)  # Initialize db with app
jwt = JWTManager(app)

from models import User

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered')
            return redirect(url_for('register'))
        hashed_pw = generate_password_hash(password)
        user = User(username=username, email=email, password=hashed_pw, is_verified=False)
        db.session.add(user)
        db.session.commit()

        # Generate token
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        # Send email
        msg = Message('Confirm your Email', recipients=[email])
        msg.body = f'Click the link to verify your email: {link}'
        try:
            mail.send(msg)
            print(f"Email sent: verify your mail to {email}")
        except Exception as e:
            print("MAIL ERROR:", e)
            flash('Could not send verification email. Please contact support.', 'danger')
            return redirect(url_for('register'))

        flash('Registration successful! Please check your email to verify your account.')
        return redirect(url_for('login'))
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            access_token = create_access_token(identity=username)
            return render_template('dashboard.html', token=access_token, username=username)
        flash('Incorrect username or password')  
        
    return render_template('login.html')
@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)  # 1 hour expiry
    except itsdangerous.SignatureExpired:
        flash('The confirmation link has expired.', 'danger')
        return redirect(url_for('login'))
    except itsdangerous.BadSignature:
        flash('Invalid confirmation token.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user:
        user.is_verified = True
        db.session.commit()
        flash('Email verified! You can now log in.', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('login'))

@app.route('/upload', methods=['POST'])
def upload():
    token = request.args.get('token')
    if not token:
        flash('Missing token')
        return redirect(url_for('login'))
    try:
        decoded = decode_token(token)
        username = decoded['sub']
    except Exception as e:
        flash('Invalid token')
        return redirect(url_for('login'))
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('dashboard', token=token))
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('dashboard', token=token))
    filename = secure_filename(file.filename)
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username.strip())
    os.makedirs(user_folder, exist_ok=True)
    file.save(os.path.join(user_folder, filename))
    flash('File uploaded successfully')
    return redirect(url_for('dashboard', token=token))

@app.route('/dashboard')
def dashboard():
    token = request.args.get('token')
    if not token:
        flash('Missing token')
        return redirect(url_for('login'))
    try:
        decoded = decode_token(token)
        username = decoded['sub']
    except Exception as e:
        flash('Invalid token')
        return redirect(url_for('login'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username.strip())
    files = os.listdir(user_folder) if os.path.exists(user_folder) else []
    return render_template('dashboard.html', username=username, files=files, token=token)

@app.route('/download/<filename>')
def download(filename):
    token = request.args.get('token')
    if not token:
        flash('Missing token')
        return redirect(url_for('login'))
    try:
        decoded = decode_token(token)
        username = decoded['sub']
    except Exception as e:
        flash('Invalid token')
        return redirect(url_for('login'))
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username.strip())
    return send_from_directory(user_folder, filename, as_attachment=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)