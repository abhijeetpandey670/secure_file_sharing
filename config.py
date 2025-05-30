SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:abhijeet%402003@localhost/file_sharing'
SECRET_KEY = 'your-secret-key'
JWT_SECRET_KEY = 'your-jwt-secret-key'
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024 
import os

MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')