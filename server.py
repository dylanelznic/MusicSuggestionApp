from flask import Flask, render_template, g
import sqlite3
import os

########################
#     Flask Set Up     #
########################

# Flask App Creation
app = Flask(__name__)
app.config.from_object('config')
port = int(os.getenv('PORT',8000))

########################
#    SQLite Set Up     #
########################

# Path to database file
DATABASE = 'temp_db.db'

# Open database connection
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

# Close database connection
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

########################
#        Routes        #
########################

# localhost:8000/example_route
@app.route("/example_route")
def example():

    # Render the "example_template.html" template from templates/
    return render_template('example_template.html')

@app.route("/")
def landing():
    return render_template('landing.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port)
