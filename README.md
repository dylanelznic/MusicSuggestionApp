# MusicSuggestionApp
Web application that utilizes machine learning in order to make new music suggestions for users based on their personal song preferences.

## Update 12/3
## Important! Before running the app for the first time, you must initialize your db:
1. Open a terminal to your `/MusicSuggestionApp/` directory
2. Run the command `python` to open up a Python shell
3. While in the shell, run the command `from server import db`
4. While in the shell, run the command `db.drop_all()` to drop your db
5. While in the shell, run the command `db.create_all()` to initialize your db
6. You should now have the file `temp_db.db` within your `/MusicSuggestionApp/` directory. This is your db.
7. Run the app
8. Visit the route `localhost:8000/populate_db` to load the demo data into your db
9. Sign in to a demo user with the username `user_x` where x is a number 1-20, and the password `password`

## To Run the App:
1. Run the command `python server.py` in your terminal to start the server
2. In your web browser, navigate to `localhost:8000` to view the web app
