import os


class Config():
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'secretkey'
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'SQLALCHEMY_DATABASE_URI') or 'sqlite:///app.db'
    FLASK_ADMIN_SWATCH = 'cerulean'
    # SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:rootroot@localhost:3307/db_test'
    SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY') or 'your_api_key'
    SENDGRID_DEFAULT_FROM = os.environ.get(
        'SENDGRID_DEFAULT_FROM') or 'marketing@gscditu.com'
