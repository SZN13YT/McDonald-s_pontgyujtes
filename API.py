"""
pip install flask bcrypt pyjwt flask_limiter dotenv
Vue a frontend hez
"""
from flask import Flask, request, jsonify, make_response
import os, sqlite3, bcrypt, uuid, jwt, datetime, re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from dotenv import load_dotenv

app = Flask(__name__)
limiter = Limiter(key_func=get_remote_address)

load_dotenv()
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY")
if not app.config['SECRET_KEY']:
    raise ValueError("A SECRET_KEY környezeti változó nincs megadva!")

secret_key = app.config["SECRET_KEY"]

def get_db_connection():
    conn = sqlite3.connect("koki.db")
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON;")
    return conn

def log_event(event_type, user_id, details, result="success", admin_id=None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("INSERT INTO logs (timestamp, event_type, user_id, admin_id, details, result) VALUES (?, ?, ?, ?, ?, ?)", 
                        (datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"), event_type, user_id, admin_id, details, ("success","failed")[result]))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Adatbázishiba: {e}")
        raise
    finally:
        conn.close()

def check_pw(pw):
    if not re.search(r"\s", pw):
        if pw.lower() not in ["password1", "password123", "admin123", "12345678"]:
            if len(pw) >= 8:
                if re.search(r"[a-zA-Z]", pw):
                    if re.search(r"[0-9]", pw):
                        if not re.match(r"^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d!@#$%^&*]{8,}$", pw):
                            return (True, None)
                        return (False, "A jelszó nem kívánt karaktereket tartalmaz.")
                    return (False, "A jelszó tartalmazzon legalább 1 számot!")
                return (False, "A jelszó tartalmazzon legalább 1 betűt!")
            return (False, "A jelszó tartalmazzon legalább 8 karaktert!")
        return (False, "A jelszó túl gyenge, válassz erősebbet!")
    return (False, "A jelszó nem tartalmazhat szóközt!")

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            points INTEGER DEFAULT 0,
            admin BOOLEAN DEFAULT 0
        )
        """)

        cursor.execute("SELECT * FROM users WHERE username = 'admin';")
        if not cursor.fetchone():
            hash = bcrypt.hashpw("admin".encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
            cursor.execute("INSERT INTO users (name, username, password, admin) VALUES (?, ?, ?, ?)", ("admin", "admin", hash, True))
        
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS blacklist (
            token TEXT PRIMARY KEY
        )
        """)

        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            user_id INTEGER,
            admin_id INTEGER,
            details TEXT,
            result TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
            FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
        )
        """)

        cursor.execute("""
        CREATE INDEX idx_timestamp ON logs(timestamp)
        """)
        
        conn.commit()
    except sqlite3.Error as e:
        print(f"Adatbázis hiba: {e}")
        raise
    finally:
        conn.close()

def token_szukseges(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        if token:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM blacklist WHERE token = ?", (token, ))
            if not cursor.fetchone():
                try: decoded = jwt.decode(token, secret_key, algorithms = ["HS256"])
                except jwt.ExpiredSignatureError:
                    try:
                        refresh_token = request.cookies.get("refresh_token")
                        decoded_rf = jwt.decode(refresh_token, secret_key, algorithms = ["HS256"])
                        username = decoded_rf.get("username")

                        cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
                        felh = cursor.fetchone()
                        conn.close()

                        token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, secret_key, algorithm="HS256")
                        decoded = jwt.decode(token, secret_key, algorithms = ["HS256"])
                        response = make_response(f(decoded, *args, **kwargs))

                        response.set_cookie("access_token", token, httponly=True, secure=False, samesite="Lax")
                        response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="Lax")
                        return response
                    except jwt.ExpiredSignatureError:
                        return jsonify({"message": "A folytatáshoz újboli bejelentkezés szükséges!"}), 401
                    except jwt.InvalidTokenError:
                        return jsonify({"message": "Érvénytelen token!"}), 401
                except jwt.InvalidTokenError:
                    return jsonify({"message": "Érvénytelen token!"}), 401
                return f(decoded, *args, **kwargs)
            return jsonify({"message": "A folytatáshoz bejelentkezés szükséges!"}), 401
        return jsonify({"message": "A folytatáshoz bejelentkezés szükséges!"}), 401
    return decorated

@app.errorhandler(429)
def rate_limit_error(e):
    return jsonify({"error": "Túl sok hibás próbálkozás. Kérlek próbáld meg később!"}), 429

@app.route('/felh_logs', methods=["GET"])
@token_szukseges
def felh_logs(decoded_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs WHERE user_id = ?", (decoded_token.get("id"), ))
    logs = cursor.fetchall()

    conn.close()
    if logs: return jsonify({"message": logs}), 200
    else: return jsonify({"message": "A felhasználó nem létezik!"}), 404

@app.route('/logs', methods=["GET"])
@token_szukseges
def logs(decoded_token):
    if decoded_token.get("admin"):
        conn = get_db_connection()
        cursor  = conn.cursor()
        cursor.execute("SELECT * FROM logs")
        logs = cursor.fetchall()
        conn.close()
        if logs:
            return jsonify({"message": logs}), 200
    return jsonify({"message": "Nincs jogosultságod hozzá!!"}), 403

@app.route('/create-user', methods=["POST"])
@token_szukseges
def create_user(decoded_token):
    conn = get_db_connection()
    cursor = conn.cursor()
    if decoded_token.get("admin"):
        data = request.get_json()
        name = data.get("name")
        passw = data.get("password")
        username = data.get("username")
        admin = bool(data.get("admin"))
        if all([username, passw, name]):
            chp = check_pw(passw)
            if chp[1]:
                cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
                if not cursor.fetchone():
                    hash = bcrypt.hashpw(passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8")
                    cursor.execute("INSERT INTO users (name, username, password, admin) VALUES (?, ?, ?, ?)", (name, username, hash, admin))
                    log_event("create_user", name, "Create new user: " + name if name else "Ismeretlen", "success", decoded_token.get("id") if decoded_token.get("id") else "Ismeretlen")

                    conn.commit()
                    conn.close()
                    return jsonify({"message": "A felhasználó sikeresen létre hozva!"}), 201
                log_event("create_user", name, "Create new user: Létező felhasználó", "failed", decoded_token.get("id") if decoded_token.get("id") else "Ismeretlen")
                return jsonify({"message": "Ez a felhasználó már szerepel!!"}), 400
            log_event("create_user", None, f"Create new user: {chp[0]}", "failed", decoded_token.get("id"))
            return jsonify({"message": chp[0]}), 400
        log_event("create_user", None, "Create new user: Hiányzó adatok", "failed", decoded_token.get("id"))
        return jsonify({"message": "Hiányzó adatok"}), 400
    log_event("create_user", None, "Create new user: Jogosultság hiánya", "failed")
    return jsonify({"message": "Nincs jogosultságodhozzá!"}), 403

@app.route('/login', methods=["POST"])
@limiter.limit("3 per minutes")
def login():
    data = request.get_json()
    username = data.get("username")
    passw = data.get("password")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
    felh = cursor.fetchone()
    conn.close()

    if all([username, passw]):
        if felh:
            felh_user = felh["username"]
            felh_pass = felh["password"]
            if bcrypt.checkpw(passw.encode("UTF-8"), felh_pass.encode("utf-8")) and felh_user == username:
                token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, secret_key, algorithm="HS256")
                refresh_token = jwt.encode({"id": felh["id"], "admin": felh["admin"],"exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)}, secret_key, algorithm="HS256")
                response = make_response(jsonify({"message": "Sikeres bejelentkezés! Üdvözöljük!"}))

                response.set_cookie("access_token", token, httponly=True, secure=False, samesite="Lax")
                response.set_cookie("refresh_token", refresh_token, httponly=True, secure=False, samesite="Lax")          
                log_event("login", felh["name"], "Bejelentkezés: " + felh["name"] if felh["name"] else "Ismeretlen", "success")      
                return response, 200
            log_event("login", felh["name"], "Bejelentkezés: Hibás Felhasználónév vagy Jelszó", "failed")
            return jsonify({"message": "Hibás felhasználónév vagy jelszó."}), 400
        log_event("login", None, "Bejelentkezés: Nem létező felhasználó", "failed")
        return jsonify({"message": "Ez a felhasználó nem létezik..."}), 404
    log_event("login", None, "Bejelentkezés: Hiányzó adatok", "failed")
    return jsonify({"message": "Hiányzó adatok!!"}), 400

@app.route('/logout', methods=["POST"])
@token_szukseges
def logout(decoded_token):
    token = request.cookies.get("access_token")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE id = ?", (decoded_token.get("id"), ))
    name = cursor.fetchone()
    log_event("logout", name["name"], f"Kijelentkezés: " + name["name"] if name["name"] else "Ismeretlen", "success")

    cursor.execute("INSERT INTO blacklist (token) VALUES (?)", (token, ))
    conn.commit()
    conn.close()


    return jsonify({"message": "Sikeres kijelentkezés!"}), 200

@app.route('/available-users', methods=["GET"])
def available_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name, points FROM users ORDER BY name ASC")
    adatok = cursor.fetchall()
    conn.close()
    return jsonify([dict(i) for i in adatok]), 200

@app.route("/admin/change-password/<int:id>", methods=["PUT"])
@token_szukseges
def ad_pass_ch(decoded_token):
    if decoded_token.get("admin"):
        conn = get_db_connection()
        cursor = conn.cursor()
        data = request.get_json()
        username = data.get("username")
        
        new_passw = data.get("new_password")

        cursor.execute("SELECT name FROM users WHERE  id = ?", (decoded_token.get("id"), ))
        admin_name = cursor.fetchone()
        if all([username, new_passw]):
            cursor.execute("SELECT * FROM users WHERE username = ?", (username, ))
            felh = cursor.fetchone()
            chp = check_pw(new_passw)
            if chp[1]:
                if felh:
                    if not bcrypt.checkpw(new_passw.encode("utf-8"), felh["password"].encode("utf-8")):
                        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (bcrypt.hashpw(new_passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"), username))
                    
                        log_event("password_change", felh["name"], "Password change (admin): " + felh["name"] if felh["name"] else "Ismeretlen", "success", admin_name["name"])

                        conn.commit()
                        conn.close()
                        return jsonify({"message": "Sikeres jelszó módosítás!"}), 200 
                    log_event("password_change", felh["name"], "Password change (admin): Jelszó egyezés", "failed", admin_name["name"])
                    return jsonify({"message": "Az új jelszó nem egyezhet az előzővel!"}), 400
                log_event("password_change", felh["name"], "Password change (admin): Nem létező felhasználó", "failed", admin_name["name"])
                return jsonify({"message": "Nics ilyen felhasználó"}), 404
            log_event("password_change", felh["name"], f"Password change (admin): {chp[1]}", "failed", admin_name["name"])
            return jsonify({"message": chp[1]}), 403
        log_event("password_change", felh["name"], "Passwword change (admin): Hiányzó adatok", "failed", admin_name["name"])
        return jsonify({"message": "Hiányzó adatok!"}), 400
    log_event("password_change", None, "Password change (admin): Jogosultság hiánya", "failed")
    return jsonify({"message": "Nincs jogosultságod hozzá!"}), 403

@app.route("/change-password", methods=["PUT"])
@token_szukseges
def self_pass_ch(decoded_token):
    data = request.get_json()
    passw = data.get("password")
    new_passw = data.get("new_password")
    token = request.cookies.get("access_token")
    if all([new_passw, passw]):
        chp = check_pw(new_passw)
        if chp[1]:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (decoded_token.get("id"), ))
            felh = cursor.fetchone()
            if felh:
                if bcrypt.checkpw(passw.encode("utf-8"), felh["password"].encode("utf-8")):
                    if not bcrypt.checkpw(new_passw.encode("utf-8"), felh["password"].encode("utf-8")):
                        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (bcrypt.hashpw(new_passw.encode("UTF-8"), bcrypt.gensalt()).decode("UTF-8"), decoded_token.get("id")))
                        cursor.execute("INSERT INTO blacklist (token) VALUES (?)", (token, ))

                        log_event("password_change", felh["name"], "Password change (self): Sikeres", "success")

                        conn.commit()
                        conn.close()
                        return jsonify({"message": "Sikeres jelszó változtatás!\nKilettél jelentkeztetve!"}), 200
                    log_event("password_change", felh["name"], "Password change (self): Jelszó egyezés", "failed")
                    return jsonify({"message": "Az új jelszó nem lehet egyenlő az eddigivel!"}), 400
                log_event("password_change", felh["name"], "Password change (self): Hibás jelszó", "failed")
                return jsonify({"message": "Hibás jelszó!"}), 403
            log_event("password_change", felh["name"], f"Password change (self): {chp[1]}", "failed")
            return jsonify({"message": chp[1]})
        log_event("password_change", None, "Password change (self): Nem létező felhasználó", "failed")
        return jsonify({"message": "A felhasználó nem található!"}), 404
    log_event("password_change", None, "Password change (self): Hiányzó adatok", "failed")
    return jsonify({"message": "Hiányzó adatok!"}), 400

@app.route("/main/<int:id>", methods=["DELETE"])
@token_szukseges
def delete_user(decoded_token, id):
    if decoded_token.get("admin"):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (id, ))
        felh = cursor.fetchone()
        if felh:
            log_event("delete_user", felh["name"], f"Delete: " + {felh["name"]} if felh["name"] else "Ismeretlen", "success", )
            cursor.execute("DELETE FROM users WHERE id = ?", (id, ))
            conn.commit()
            conn.close()
            return jsonify({"message": "Sikeres törlés."}), 200
        return jsonify({"message": "A felhasználó nem létezik."}), 404
    return jsonify({"message": "Nincs jogosultságod hozzá!"}), 403

if __name__ == '__main__':
    if not os.path.exists("koki.db"):
        init_db()
    app.run(debug=True, port=5001)