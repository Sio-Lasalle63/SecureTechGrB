from flask import Flask, request, render_template, redirect, session, g
import sqlite3 , hashlib

app = Flask(__name__)
app.secret_key = "secret_key_dev" 
DB_NAME = "users.db"


# -----------------------------------
# Outils de gestion des mots de passe
# -----------------------------------
def hacherUnMotDePasse(motDePasseEnClair):
    mdpHashe = hashlib.sha256(motDePasseEnClair.encode()).hexdigest()
    return mdpHashe

def isLongueurMdpOk(motDePasseEnClair):
    return len(motDePasseEnClair) >= 8

def containsUppercase( mot ) :
    # entre 65 et 90 -> Maj
    for lettre in mot :
        codeAscii = ord( lettre )
        if 65 < codeAscii  and codeAscii < 90 :
            return True
    return False

def containsDigit( mot ) :
    # entre 48 et 57
    for lettre in mot :
        codeAscii = ord( lettre )
        if 48 < codeAscii  and codeAscii < 57 :
            return True
    return False


# -----------------------------
# Gestion de la base de données
# -----------------------------
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
    return db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# -----------------------------
# Initialisation de la base
# -----------------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            nom TEXT,
            prenom TEXT,
            email TEXT,
            avatar TEXT) """)
    cursor.execute("""
        INSERT OR IGNORE INTO users 
        (username, password, nom, prenom, email, avatar)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "admin",
            hacherUnMotDePasse("Totototo1"),
            "Dupont",
            "Alice",
            "alice.dupont@example.com",
            "https://api.dicebear.com/9.x/adventurer/svg?seed=admin"))
    cursor.execute("""
        INSERT OR IGNORE INTO users 
        (username, password, nom, prenom, email, avatar)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "thekerry78",
            hacherUnMotDePasse("Totototo2"),
            "Jawed",
            "Kerry",
            "TheKerry78@grosbouffon.com",
            "https://api.dicebear.com/9.x/adventurer/svg?seed=thekerry78"))
    conn.commit()
    conn.close()

# -----------------------------
# Connexion
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?",(username, hacherUnMotDePasse(password)))
        user = cursor.fetchone()
        if user:
            session["username"] = username
            return redirect("/home")
        else:
            message = "Identifiants incorrects."
    return render_template("login.html", message=message)

# -----------------------------
# Home
# -----------------------------
@app.route("/home")
def home():
    if "username" not in session:
        return redirect("/")
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT nom, prenom, email, avatar
        FROM users
        WHERE username = ?
        """, (session["username"],))
    user = cursor.fetchone()
    return render_template(
        "home.html",
        username=session["username"],
        nom=user[0],
        prenom=user[1],
        email=user[2],
        avatar=user[3])

# -----------------------------
# Changement de mot de passe
# -----------------------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if "username" not in session:
        return redirect("/")
    message = ""
    username = session["username"]
    status = "fail"
    if request.method == "POST":
        old_password = request.form["old_password"]
        new_password1 = request.form["new_password1"]
        new_password2 = request.form["new_password2"]
        if new_password1==new_password2 :
            if isLongueurMdpOk(new_password1):
                db = get_db()
                cursor = db.cursor()
                cursor.execute("Select password from users WHERE username = ?", (username,))
                oldPassBD = cursor.fetchone()[0]
                if oldPassBD == hacherUnMotDePasse(old_password) :
                    if containsUppercase(new_password1) :
                        if containsDigit( new_password1 ):
                            cursor.execute("UPDATE users SET password = ? WHERE username = ?",(hacherUnMotDePasse(new_password1), username))
                            db.commit()
                            message = "Mot de passe modifié."
                            status = "success"
                        else:
                            message = "Le mot de passe doit contenir au moins 1 chiffre"        
                    else: 
                        message = "Le mot de passe doit contenir au moins 1 majuscule"    
                else:
                    message = "L'ancien mot de passe ne correspond pas"
            else:
                message = "Le mot de passe doit avoir une longueur de 8 caractères minimum"
        else:
            message = "Les 2 mots de passe ne sont pas identiques."
    return render_template("change_password.html",  username=username, message=message , status=status)

# -----------------------------
# Déconnexion
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# -----------------------------
# Lancement
# -----------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
