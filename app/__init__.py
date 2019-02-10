from flask import Flask
from config import Config
from flask_restful import Api
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_admin import Admin
from flask_migrate import Migrate
# from flask_apidoc import ApiDoc


app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
# doc = ApiDoc(app=app)
api = Api(app)
migrate = Migrate(app, db)
admin = Admin(app, name='Helping Hands', template_mode='bootstrap3')
CORS(app)

from app import routes