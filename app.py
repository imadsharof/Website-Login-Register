from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import sqlite3, os, re

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")

# --- DB path (local) ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", os.path.join(BASE_DIR, "app.db"))
# Crée le dossier uniquement si DB_PATH contient un dossier
db_dir = os.path.dirname(DB_PATH)
if db_dir:
    os.makedirs(db_dir, exist_ok=True)

# --- OAuth Google (facultatif en local) ---
app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.getenv("GOOGLE_CLIENT_SECRET")
oauth = OAuth(app)
if app.config["GOOGLE_CLIENT_ID"] and app.config["GOOGLE_CLIENT_SECRET"]:
    oauth.register(
        name="google",
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_id=app.config["GOOGLE_CLIENT_ID"],
        client_secret=app.config["GOOGLE_CLIENT_SECRET"],
        client_kwargs={"scope": "openid email profile"},
    )

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      google_sub TEXT,
      name TEXT,
      avatar TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub);

    CREATE TABLE IF NOT EXISTS reviews(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author_email TEXT,
      rating INTEGER CHECK(rating BETWEEN 1 AND 5) NOT NULL,
      comment TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS contacts(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

# ------------- ROUTES -------------
@app.get("/")
def home():
    # 3 derniers avis pour la page d'accueil
    conn = get_db()
    rows = conn.execute("""
      SELECT author_email, rating, comment, created_at
      FROM reviews ORDER BY created_at DESC LIMIT 3
    """).fetchall()
    conn.close()
    return render_template("home.html", last_reviews=rows)

@app.get("/auth")
def auth():
    return render_template("auth.html")

# ----- Register/Login -----
@app.post("/register")
def register():
    email = request.form.get("email","").strip().lower()
    pw = request.form.get("password","")
    confirm = request.form.get("confirm","")

    if not EMAIL_RE.match(email):
        flash("Email invalide.", "error"); return redirect(url_for("auth")+"#signup")
    if pw != confirm:
        flash("Les mots de passe ne correspondent pas.", "error"); return redirect(url_for("auth")+"#signup")
    if len(pw) < 8:
        flash("Mot de passe trop court (min 8).", "error"); return redirect(url_for("auth")+"#signup")

    try:
        conn = get_db()
        conn.execute("INSERT INTO users(email, password_hash) VALUES (?,?)",
                     (email, generate_password_hash(pw)))
        conn.commit(); conn.close()
        flash("Inscription réussie, vous pouvez vous connecter.", "success")
        return redirect(url_for("auth")+"#login")
    except sqlite3.IntegrityError:
        flash("Cet email est déjà enregistré.", "error"); return redirect(url_for("auth")+"#signup")

@app.post("/login")
def login():
    email = request.form.get("email","").strip().lower()
    pw = request.form.get("password","")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    if not user or not user["password_hash"] or not check_password_hash(user["password_hash"], pw):
        flash("Identifiants invalides.", "error"); return redirect(url_for("auth")+"#login")
    session["user_id"], session["email"] = user["id"], user["email"]
    flash("Connexion réussie.", "success")
    return redirect(url_for("home"))

@app.get("/logout")
def logout():
    session.clear()
    flash("Déconnecté.", "success")
    return redirect(url_for("home"))

# ----- Google OAuth (si configuré) -----
@app.get("/login/google")
def login_google():
    if "google" not in oauth:
        flash("Login Google non configuré en local.", "error"); return redirect(url_for("auth")+"#login")
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.get("/auth/google/callback")
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
        info = token.get("userinfo") or oauth.google.parse_id_token(token)
    except Exception:
        flash("Échec Google OAuth.", "error"); return redirect(url_for("auth")+"#login")
    sub, email = info.get("sub"), info.get("email").lower()
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE google_sub=? OR email=?", (sub,email)).fetchone()
    if user and not user["google_sub"]:
        conn.execute("UPDATE users SET google_sub=? WHERE id=?", (sub, user["id"])); conn.commit()
    if not user:
        conn.execute("INSERT INTO users(email, google_sub, name, avatar) VALUES (?,?,?,?)",
                     (email, sub, info.get("name"), info.get("picture")))
        conn.commit()
    conn.close()
    session["email"] = email
    flash("Connecté avec Google.", "success")
    return redirect(url_for("home"))

# ----- Avis -----
@app.route("/avis", methods=["GET","POST"])
def avis():
    if request.method == "POST":
        rating = int(request.form.get("rating","5"))
        comment = (request.form.get("comment") or "").strip()
        author = session.get("email")
        if not comment:
            flash("Votre avis est vide.", "error"); return redirect(url_for("avis"))
        conn = get_db()
        conn.execute(
            "INSERT INTO reviews(author_email, rating, comment) VALUES (?,?,?)",
            (author, rating, comment)
        )
        conn.commit(); conn.close()
        flash("Merci pour votre avis !", "success")
        return redirect(url_for("avis"))

    conn = get_db()
    rows = conn.execute(
        "SELECT author_email, rating, comment, created_at FROM reviews ORDER BY created_at DESC"
    ).fetchall()
    stats = conn.execute(
        "SELECT COUNT(*) AS n, ROUND(AVG(rating),1) AS avg FROM reviews"
    ).fetchone()
    conn.close()
    return render_template("avis.html", reviews=rows, stats=stats)

# ----- Contact -----
@app.route("/contact", methods=["GET","POST"])
def contact():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip()
        message = request.form.get("message","").strip()
        if not name or not EMAIL_RE.match(email) or not message:
            flash("Merci de remplir correctement le formulaire.", "error"); return redirect(url_for("contact"))
        conn = get_db()
        conn.execute("INSERT INTO contacts(name,email,message) VALUES (?,?,?)",(name,email,message))
        conn.commit(); conn.close()
        flash("Message envoyé, on revient vers vous rapidement.", "success")
        return redirect(url_for("contact"))
    return render_template("contact.html")

# ------------- RUN -------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
