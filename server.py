from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask import Flask, render_template, g, render_template, flash, request, redirect, url_for, session, jsonify
from forms import LoginForm, RegisterForm, PasswordForm, UpdateProfileForm
from flask_sqlalchemy import SQLAlchemy
import requests
import sqlite3
import hashlib
import base64
import json
import csv
import os
import random

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
    name = db.Column(db.String(120))
    email = db.Column(db.String(120), unique=True)

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User %r>' % self.username

class Songs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    band = db.Column(db.String(120))
    song = db.Column(db.String(120))
    album = db.Column(db.String(120))

    def __init__(self, band, song, album):
        self.band = band
        self.song = song
        self.album = album

class Ratings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sid = db.Column(db.Integer, db.ForeignKey('songs.id'), nullable=False)
    rating = db.Column(db.Integer)

    def __init__(self, uid, sid, rating):
        self.uid = uid
        self.sid = sid
        self.rating = rating


class RatedSongs(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20))
    band = db.Column(db.String(120))
    song = db.Column(db.String(120))
    album = db.Column(db.String(120))
    rating = db.Column(db.Integer)

    def __init__(self, username, band, song, album, rating):
        self.username = username
        self.band = band
        self.song = song
        self.album = album
        self.rating = rating

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

                flash('Registration Successful')
                return redirect(url_for('login'))

        else:
            if form.password.data != form.confirm.data:
                flash('Password fields do not match')
            else:
                flash('Registration unsucessful, please check your inputs and try again')

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
                if check_user.password == hashlib.sha256(form.password.data.encode('utf-8')).hexdigest():

                    # Grab the user's id
                    session['user_id'] = check_user.id
                    session['user_username'] = check_user.username

                    # Log in the user
                    user = User(session['user_id'])
                    login_user(user)

                    return redirect(url_for('index'))

                else:
                    flash('Username or password was incorrect')
            else:
                flash('Username or password was incorrect')
        else:
            flash('Login unsuccessful, missing fields')

    return render_template('login.html', form=form)

# User Log Out
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()

    return redirect(url_for('login'))

# Delete User Account
@app.route('/delete-account', methods=('GET','POST'))
@login_required
def deleteAccount():

    if request.method == 'POST':
        user = Users.query.filter_by(username=session['user_username']).first()
        db.session.delete(user)
        db.session.commit()

    return redirect(url_for('logout'))

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

    # If no session['song-x'] exists, initialize defaults
    if 'song-1' not in session:
        # Pull highest rated suggestion for current user
        user_id = Users.query.filter_by(username=session['user_username']).first()
        rating_data = Ratings.query.filter_by(uid=user_id.id).order_by(Ratings.rating)

        count = 1
        for rating in rating_data:
            new_song_data = Songs.query.filter_by(id=rating.sid).first()
            print('song-%s' % count)
            session[('song-%s' % count)] = {'id': new_song_data.id,
                                            'band': new_song_data.band,
                                            'song': new_song_data.song,
                                            'album': new_song_data.album}
            count +=1
            db.session.delete(rating)
            if count > 5:
                break
        db.session.commit()

    return render_template('index.html', user_username=user_username,
                           song_1=session['song-1'], song_2=session['song-2'],
                           song_3=session['song-3'], song_4=session['song-4'],
                           song_5=session['song-5'])

@app.route('/profile', methods=('GET','POST'))
@login_required
def profile():
    change = PasswordForm()
    update_profile = UpdateProfileForm()

    # Change Password form
    if request.method == 'POST' and request.form['form-check'] == 'Change Password':
        if change.password.data == change.confirm.data:

            temp = Users.query.filter_by(username=session['user_username']).first()
            hash_pass = hashlib.sha256(change.password.data.encode('utf-8')).hexdigest()
            temp.password = hash_pass
            db.session.commit()
            return redirect(url_for('logout'))

    # Update Profile form
    if request.method == 'POST' and request.form['form-check'] == 'Update Profile':
        name = update_profile.name.data
        email = update_profile.email.data

        user = Users.query.filter_by(username=session['user_username']).first()
        user.name = name
        user.email = email
        db.session.commit()
        return redirect(url_for('profile'))

    user = Users.query.filter_by(username=session['user_username']).first()
    user_username = session['user_username']
    name = user.name
    email = user.email

    return render_template('profile.html', user_username=user_username, change=change,
                           update_profile=update_profile, name=name, email=email)

@app.route('/rating', methods=('GET', 'POST'))
def rating():
    if request.method == 'POST':
        # request.data is in the form {'song':'song-1','rating':'4'}
        rating_data = json.loads(request.data)
        song_data = session[rating_data['song']]

        # Insert into user's rated songs
        rated_song = RatedSongs(session['user_username'], song_data['band'],
                                song_data['song'], song_data['album'],
                                rating_data['rating'])
        db.session.add(rated_song)
        db.session.commit()

    return redirect(url_for('index'))

@app.route('/new_song', methods=('GET', 'POST'))
def newSong():

    # Pull highest rated suggestion for current user
    user_id = Users.query.filter_by(username=session['user_username']).first()
    rating_data = Ratings.query.filter_by(uid=user_id.id).order_by(Ratings.rating).first()
    new_song_data = Songs.query.filter_by(id=rating_data.sid).first()

    # Retrieve new song to be rated from ML algorithm
    # Build a string json out of the data
    song_json = {}
    song_json['id'] = (new_song_data.id)
    song_json['band'] = (str(new_song_data.band))
    song_json['song'] = (new_song_data.song)
    song_json['album'] = (str(new_song_data.album))

    # Store song to session
    song_num = request.args['song_num']
    session['song-%s' % song_num] = song_json

    # Convert to json object for axios request
    song_json = json.dumps(song_json)

    db.session.delete(rating_data)
    db.session.commit()

    return song_json

@app.route('/rated-songs', methods=('GET','POST'))
@login_required
def ratedSongs():
    user_username = session['user_username']

    rated_songs_data = RatedSongs.query.filter_by(username=session['user_username'])
    rated_songs = []
    for song in rated_songs_data:
        rated_songs.append(song)

    return render_template('rated_songs.html', user_username=user_username,
                           rated_songs=rated_songs)

@app.route('/users', methods=('GET','POST'))
@login_required
def users():
    user_username = session['user_username']
    return render_template('users.html', user_username=user_username)

@app.route('/populate_db', methods=('GET', 'POST'))
def populateDb():
    # User Creation
    for i in range(1,21):
        hash_pass = hashlib.sha256('password'.encode('utf-8')).hexdigest()
        new_user = Users(('user_%s' % i), hash_pass)
        db.session.add(new_user)
        print('user_%s' % i)
    db.session.commit()

    # Artist Array Creation
    artists = []
    albums = []
    with open('artist.csv') as f:
        reader = csv.reader(f)
        artists = list(reader)
    with open('albums.csv') as j:
        reader2 = csv.reader(j)
        albums = list(reader2)
        
    # Song Creation
    for i in range(1,300001):
        place = random.randint(0,99)
        new_song = Songs(artists[place][0], ('song_%s' % i), albums[place][0])
        db.session.add(new_song)
        print('song_%s' % i)
    db.session.commit()

    # Read in algorithm output
    for line in open("top_25_ratings_for_20_users.csv"):
        csv_row = line.split() #returns a list ["1","50","60"]
        new_suggestion = Ratings(csv_row[0], csv_row[1], csv_row[2])
        db.session.add(new_suggestion)
        print(csv_row)
    db.session.commit()



    return "dasf"

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
