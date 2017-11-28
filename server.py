from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask import Flask, render_template, g, render_template, flash, request, redirect, url_for, session, jsonify
from forms import LoginForm, RegisterForm, PasswordForm
from flask_sqlalchemy import SQLAlchemy
import requests
import sqlite3
import hashlib
import base64
import json
import os


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
                hash_pass = hashlib.sha256(form.password.data.encode('utf-8')).hexdigest()

                # Insert new user into the db
                new_user = Users(form.username.data, hash_pass)
                db.session.add(new_user)
                db.session.commit()

                flash('Registration successful.')
                return redirect(url_for('index'))

        else:
            flash('Registration unsucessful, please check your inputs and try again.')

    return render_template('register.html', form=form)

@app.route('/changePassword', methods=('GET', 'POST'))
def password():

        
        
    return redirect(url_for('profile'))



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
                if check_user.password == hashlib.sha256(form.password.data.encode('utf-8')).hexdigest():

                    # Grab the user's id
                    session['user_id'] = check_user.id
                    session['user_username'] = check_user.username

                    # Log in the user
                    user = User(session['user_id'])
                    login_user(user)

                    flash('Login successful.')
                    return redirect(url_for('index'))

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
#    Spotify OAuth     #
########################

@app.route('/spotify-request-auth', methods=('GET', 'POST'))
def spotifyRequestAuth():

    # Step 1: Request Authorization
    client_id = 'a5e0fc20e60c4bf18e051c669a9c7c77'
    redirect_uri = 'http://localhost:8000/callback'
    scope = 'user-library-read'

    auth_url = (('https://accounts.spotify.com/authorize/?client_id=%s' +
                                                      '&response_type=code' +
                                                      '&redirect_uri=%s' +
                                                      '&scope=%s') % (client_id,redirect_uri, scope))

    return redirect(auth_url)

@app.route('/callback', methods=('GET', 'POST'))
def spotifyCallback():

    # Step 3: User is redirected back to specified URI
    token_url = 'https://accounts.spotify.com/api/token'

    # These should be kept secret and stored securely! In future versions, we will
    # regenerate a new client secret. This is currently very bad practice.
    client_id = 'a5e0fc20e60c4bf18e051c669a9c7c77'
    client_secret = 'dfe55edaa2e540b89505d5d930c99f4d'

    # Encode client_id and client_secret
    base64encoded = base64.b64encode("%s:%s" % (client_id, client_secret))
    headers = {"Authorization": "Basic %s" % (base64encoded)}

    data = {
        'grant_type': 'authorization_code',
        'code': str(request.args['code']),
        'redirect_uri': 'http://localhost:8000/callback'
    }

    # Step 4: Request refresh and access tokens
    post_request = requests.post(token_url, data=data, headers=headers)

    # Step 5: Tokens are returned to application
    response_data = json.loads(post_request.text)

    access_token  = response_data['access_token']
    refresh_token = response_data['refresh_token']
    token_type    = response_data['token_type']
    expires_in    = response_data['expires_in']

    # Step 6: Use the access token to access the Spotify Web API
    authorization_header = {'Authorization': 'Bearer %s' % access_token}

    # END AUTHORIZTION PROCESS

    # Spotify API example
    # Get a list of the songs saved in the current Spotify user's "Your Music" library
    get_tracks_endpoint = 'https://api.spotify.com/v1/me/tracks'

    get_tracks_response = requests.get(get_tracks_endpoint, headers=authorization_header)
    get_tracks_data = json.loads(get_tracks_response.text)

    return jsonify(**get_tracks_data)

########################
#        Routes        #
########################

# localhost:8000/example_route
@app.route('/example_route')
def example():

    # Render the "example_template.html" template from templates/
    return render_template('example_template.html')

@app.route('/', methods=('GET','POST'))
@login_required
def index():
    user_username = session['user_username']
    return render_template('index.html', user_username=user_username)

@app.route('/profile', methods=('GET','POST'))
@login_required
def profile():
    change = PasswordForm()
    user_username = session['user_username']
    return render_template('profile.html', user_username=user_username, change = change)

@app.route('/users', methods=('GET','POST'))
@login_required
def users():
    user_username = session['user_username']
    return render_template('users.html', user_username=user_username)

@app.route('/rating', methods=('GET', 'POST'))
def rating():
    if request.method == 'POST':
        print(request.data)

    return redirect(url_for('index'))

# @app.route('/rating_two')
# def rating_two():
#     print("Song 2 rated.")
#     return redirect(url_for('index'))
#
# @app.route('/rating_three')
# def rating_three():
#     print("Song 3 rated.")
#     return redirect(url_for('index'))
#
# @app.route('/rating_four')
# def rating_four():
#     print("Song 4 rated.")
#     return redirect(url_for('index'))
#
# @app.route('/rating_five')
# def rating_five():
#     print("Song 5 rated.")
#     return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
