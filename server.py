from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask import Flask, render_template, g, render_template, flash, request, redirect, url_for, session
from forms import LoginForm, RegisterForm
import sqlite3
import hashlib
import os

from flask_sqlalchemy import SQLAlchemy

########################
#     Flask Set Up     #
########################

# Flask App Creation
app = Flask(__name__)
app.config.from_object('config')
port = int(os.getenv('PORT',8000))

########################
#    Database Setup    #
########################

db = SQLAlchemy(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password = db.Column(db.String(120))

    def __init__(self, username, password):
        self.username = username
        self.password = password 

    def __repr__(self):
        return '<User %r>' % self.username

########################
#      User Login      #
########################

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# User callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# User Registration
@app.route('/register', methods=('GET', 'POST'))
def register():

    form = RegisterForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            
            # Check is a user already exists within the db
            if Users.query.filter_by(username=form.username.data).first() != None:
                flash('User "%s" already exists' % form.username.data)

            else:
                # Rudimentary password hashing, can be replaced later if desired
                hash_pass = hashlib.sha256(form.password.data).hexdigest()

                # Insert new user into the db
                new_user = Users(form.username.data, hash_pass)
                db.session.add(new_user)
                db.session.commit()

                flash('Registration successful.')
                return redirect(url_for('landing'))

        else:
            flash('Registration unsucessful, please check your inputs and try again.')

    return render_template('register.html', form=form)
             

# User Login
@app.route('/login', methods=('GET', 'POST'))
def login():
    check_user_exists = ('SELECT password FROM users WHERE username="%s"')
    retrieve_user_id  = ('SELECT id FROM users WHERE username="%s"')

    form = LoginForm()
    if request.method == 'POST':
        if form.validate_on_submit():

            # Check if the user exists within the db
            check_user = Users.query.filter_by(username=form.username.data).first()
            if check_user != None:

                # Check is password hashes match 
                if check_user.password == hashlib.sha256(form.password.data).hexdigest():
                    
                    # Grab the user's id
                    session['user_id'] = check_user.id 

                    # Log in the user
                    user = User(session['user_id'])
                    login_user(user)

                    flash('Login successful.') 
                    return redirect(url_for('landing'))

                else:
                    flash('Username or password was incorrect.') 
            else:
                flash('Username or password was incorrect.') 
        else:
            flash('Login unsuccessful, missing fields.') 

    return render_template('login.html', form=form)

# User Log Out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('login'))

########################
#        Routes        #
########################

# localhost:8000/example_route
@app.route("/example_route")
def example():

    # Render the "example_template.html" template from templates/
    return render_template('example_template.html')

@app.route("/")
@login_required
def landing():
    return render_template('landing.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
