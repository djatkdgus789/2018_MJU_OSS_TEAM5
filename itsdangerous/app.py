from flask import Flask
from flask_security import Security, login_required, \
    SQLAlchemySessionUserDatastore, roles_required, utils
from database import db_session, init_db
from models import User, Role
import os

#Create app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'superdupersecret'

app.config['SECURITY_PASSWORD_SALT'] = os.urandom(32)

#setup Flask-security
user_datastore = SQLAlchemySessionUserDatastore(db_session,User,Role)
security = Security(app,user_datastore)


@app.before_first_request
def create_user():
    init_db()

    user_datastore.find_or_create_role(name='root',description='supercow powers')
    user_datastore.find_or_create_role(name='operator',description='normal operator')
    
    #NEVER STORE PLAIN-TEXT PASSWORDS
    secure_password = utils.hash_password('password')

    if not user_datastore.get_user('root@test.net'):
        user_datastore.create_user(email='root@test.net',password=secure_password)
    if not user_datastore.get_user('operator@test.net'):
        user_datastore.create_user(email='operator@test.net',password=secure_password)

    
    db_session.commit()

    user_datastore.add_role_to_user('root@test.net','root')
    user_datastore.add_role_to_user('operator@test.net','operator')

    db_session.commit()

#Views
@app.route('/')
@login_required
def home():
    return 'test'

@app.route('/admin')
@roles_required('root')
def admin_view():
    return "Hello there qt"

if __name__ == '__main__':
    app.run()