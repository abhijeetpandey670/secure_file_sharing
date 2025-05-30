from flask import Flask
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)
app.config.from_pyfile('config.py')
mail = Mail(app)

with app.app_context():
    msg = Message('Test Email', recipients=['abhijeetpandey669@gmail.com'])
    msg.body = 'This is a test email from Flask-Mail.'
    try:
        mail.send(msg)
        print("Test email sent!")
    except Exception as e:
        print("MAIL ERROR:", e)