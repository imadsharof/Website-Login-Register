from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import sqlite3, os, re
from dotenv import load_dotenv
load_dotenv()
import os
print("GOOGLE_CLIENT_ID loaded?:", bool(os.getenv("GOOGLE_CLIENT_ID")))
print("GOOGLE_CLIENT_SECRET loaded?:", bool(os.getenv("GOOGLE_CLIENT_SECRET")))

app = Flask(__name__)
# --- Où stocker la base ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(BASE_DIR, "app.db")

DB_PATH = os.getenv("DB_PATH", DEFAULT_DB)

# Si DB_PATH contient un dossier, on s'assure qu'il existe
db_dir = os.path.dirname(DB_PATH)
if db_dir and not os.path.exists(db_dir):
    os.makedirs(db_dir, exist_ok=True)

print("DB_PATH =", DB_PATH)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-change-me")
#DB_PATH = "app.db" avant
DB_PATH = os.getenv("DB_PATH", "app.db")

# --- OAuth Google ---
app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")
app.config["GOOGLE_CLIENT_SECRET"] = os.getenv("GOOGLE_CLIENT_SECRET")
oauth = OAuth(app)
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    client_kwargs={"scope": "openid email profile"},
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
COMMON_WEAK = {
    "password","123456","12345678","123456789","admin","qwerty","azerty",
    "motdepasse","welcome","passw0rd","abc123","iloveyou","000000","111111",
    "letmein","monkey","dragon","football","qwertyuiop","naruto"
}

def validate_password(pw: str, email: str) -> list[str]:
    issues = []
    if len(pw) < 8: issues.append("Au moins 8 caractères.")
    if not re.search(r"[a-z]", pw): issues.append("Au moins 1 lettre minuscule.")
    if not re.search(r"[A-Z]", pw): issues.append("Au moins 1 lettre majuscule.")
    if not re.search(r"\d", pw): issues.append("Au moins 1 chiffre.")
    if not re.search(r"[^\w\s]", pw): issues.append("Au moins 1 caractère spécial (ex: ! @ # $ % & * ?).")
    if re.search(r"\s", pw): issues.append("Pas d’espace.")
    if re.search(r"(.)\1{2,}", pw): issues.append("Évitez les répétitions (aaa, 111).")
    low = pw.lower()
    for seq in ("abcdefghijklmnopqrstuvwxyz", "0123456789"):
        if any(seq[i:i+4] in low for i in range(len(seq)-3)):
            issues.append("Évitez les suites évidentes (abcd, 1234)."); break
    if low in COMMON_WEAK: issues.append("Mot de passe trop commun.")
    local = (email.split("@")[0] if email else "").lower()
    if local and local in low: issues.append("N’utilisez pas votre email dans le mot de passe.")
    return issues

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()

    # Schéma pour une nouvelle base (si app.db n'existe pas encore)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT,                 -- NULL pour comptes Google
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      google_sub TEXT,                    -- ID Google (peut être NULL)
      name TEXT,
      avatar TEXT
    );
    """)
    conn.commit()

    # Migration douce si la table existait déjà
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)")}
    if "google_sub" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
        # index UNIQUE (les valeurs NULL sont autorisées en multiple)
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub)")
    if "name" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN name TEXT")
    if "avatar" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT")

    conn.commit()
    conn.close()


@app.route("/")
def home():
    return render_template("auth.html")

# ---------- Local signup/login ----------
@app.post("/register")
def register():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    confirm = request.form.get("confirm","")

    if not EMAIL_RE.match(email):
        flash("Email invalide.", "error"); return redirect(url_for("home")+"#signup")
    if password != confirm:
        flash("Les mots de passe ne correspondent pas.", "error"); return redirect(url_for("home")+"#signup")

    issues = validate_password(password, email)
    if issues:
        for msg in issues: flash(msg, "signup_pw")
        return redirect(url_for("home")+"#signup")

    try:
        pwd_hash = generate_password_hash(password)
        conn = get_db()
        conn.execute("INSERT INTO users(email, password_hash) VALUES (?,?)", (email, pwd_hash))
        conn.commit(); conn.close()
        flash("Inscription réussie, vous pouvez vous connecter.", "success")
        return redirect(url_for("home")+"#login")
    except sqlite3.IntegrityError:
        flash("Cet email est déjà enregistré.", "error")
        return redirect(url_for("home")+"#signup")

@app.post("/login")
def login():
    email = request.form.get("email","").strip().lower()
    password = request.form.get("password","")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    if not user or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        flash("Identifiants invalides.", "error"); return redirect(url_for("home")+"#login")
    session["user_id"], session["email"] = user["id"], user["email"]
    flash("Connexion réussie.", "success"); return redirect(url_for("profile"))

# ---------- Google OAuth ----------
@app.get("/login/google")
def login_google():
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.get("/auth/google/callback")
def auth_google_callback():
    try:
        token = oauth.google.authorize_access_token()
    except Exception:
        flash("Échec de l’authentification Google.", "error")
        return redirect(url_for("home")+"#login")

    # Essaye d'obtenir l'ID token / userinfo
    info = token.get("userinfo")
    if not info:
        try:
            info = oauth.google.parse_id_token(token)
        except Exception:
            # Dernier recours: endpoint userinfo
            resp = oauth.google.get("userinfo")
            info = resp.json() if resp else None

    if not info or not info.get("email"):
        flash("Impossible de récupérer votre profil Google.", "error")
        return redirect(url_for("home")+"#login")

    sub = info.get("sub")
    email = info.get("email").lower()
    name = info.get("name")
    avatar = info.get("picture")

    conn = get_db()
    # s'il existe par sub -> ok, sinon par email (on associe)
    user = conn.execute("SELECT * FROM users WHERE google_sub = ? OR email = ?", (sub, email)).fetchone()
    if user:
        if not user["google_sub"]:
            conn.execute("UPDATE users SET google_sub=?, name=?, avatar=? WHERE id=?",
                         (sub, name, avatar, user["id"]))
            conn.commit()
    else:
        conn.execute("INSERT INTO users(email, google_sub, name, avatar) VALUES (?,?,?,?)",
                     (email, sub, name, avatar))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE google_sub = ?", (sub,)).fetchone()
    conn.close()

    session["user_id"], session["email"] = user["id"], user["email"]
    flash("Connecté avec Google.", "success")
    return redirect(url_for("profile"))

# ---------- Logout / Profile ----------
@app.get("/logout")
def logout():
    session.clear()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for("home")+"#login")

@app.get("/profile")
def profile():
    if "user_id" not in session:
        flash("Veuillez vous connecter.", "error"); return redirect(url_for("home")+"#login")
    return f"<h1>Bonjour {session.get('email')}</h1><p>Page protégée.</p><p><a href='/logout'>Se déconnecter</a></p>"

# ---------- Admin: liste des utilisateurs ----------
@app.get("/admin/users")
def admin_users():
    conn = get_db()
    rows = conn.execute("""
      SELECT id, email, created_at, name, avatar,
             CASE WHEN google_sub IS NOT NULL THEN 'google' ELSE 'local' END AS provider
      FROM users
      ORDER BY created_at DESC
    """).fetchall()
    conn.close()
    return render_template("users.html", rows=rows)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
