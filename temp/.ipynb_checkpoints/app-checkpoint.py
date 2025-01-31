from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Change this to a strong secret key

# Set up Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect("news.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return User(user[0], user[1]) if user else None

# Function to fetch news
def get_news():
    conn = sqlite3.connect("news.db")
    cursor = conn.cursor()
    cursor.execute("SELECT title, source, date_scraped FROM headlines ORDER BY date_scraped DESC")
    news = cursor.fetchall()
    conn.close()
    return news

# Route: Home (Requires Login)
@app.route("/")
@login_required
def home():
    news_data = get_news()
    return render_template("index.html", news=news_data, username=current_user.username)

# Route: Register New User
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Hash password
        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        try:
            conn = sqlite3.connect("news.db")
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash("✅ Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except:
            flash("⚠️ Username already exists. Try a different one.", "danger")

    return render_template("register.html")

# Route: User Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("news.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            login_user(User(user[0], user[1]))
            flash("✅ Logged in successfully!", "success")
            return redirect(url_for("home"))
        else:
            flash("⚠️ Invalid username or password.", "danger")

    return render_template("login.html")

# Route: Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("✅ Logged out successfully!", "info")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
