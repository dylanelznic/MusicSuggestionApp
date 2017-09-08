from flask import Flask, render_template
import os

########################
#     Flask Set Up     #
########################

# Flask App Creation
app = Flask(__name__)
app.config.from_object('config')
port = int(os.getenv('PORT',8000))

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
