import os
from functools import wraps

import bcrypt
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for

from database import get_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-in-env")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("home"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password or not confirm_password:
            flash("Completa todos los campos.", "danger")
            return render_template("register.html")

        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Las contraseñas no coinciden.", "danger")
            return render_template("register.html")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Ya existe una cuenta con ese correo.", "warning")
                return render_template("register.html")

            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=12),
            ).decode("utf-8")

            cursor.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (name, email, password_hash),
            )
            conn.commit()

            flash("Usuario registrado correctamente. Ahora inicia sesión.", "success")
            return redirect(url_for("login"))
        finally:
            cursor.close()
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Ingresa correo y contraseña.", "danger")
            return render_template("login.html")

        conn = get_connection()
        cursor = conn.cursor(dictionary=True)

        try:
            cursor.execute(
                """
                SELECT id, name, email, password_hash, google_sub
                FROM users
                WHERE email = %s
                """,
                (email,),
            )
            user = cursor.fetchone()
        finally:
            cursor.close()
            conn.close()

        if not user:
            flash("Credenciales incorrectas.", "danger")
            return render_template("login.html")

        if not user["password_hash"]:
            flash("Esta cuenta fue creada con Google. Usa 'Continuar con Google'.", "warning")
            return render_template("login.html")

        valid = bcrypt.checkpw(
            password.encode("utf-8"),
            user["password_hash"].encode("utf-8"),
        )

        if not valid:
            flash("Credenciales incorrectas.", "danger")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        session["auth_method"] = "bcrypt"

        return redirect(url_for("home"))

    return render_template("login.html")


@app.route("/login/google")
def login_google():
    if not os.getenv("GOOGLE_CLIENT_ID") or not os.getenv("GOOGLE_CLIENT_SECRET"):
        flash("Google OAuth todavía no está configurado en el archivo .env.", "warning")
        return redirect(url_for("login"))

    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/auth/callback")
def google_callback():
    try:
        google.authorize_access_token()
        userinfo = google.get("https://openidconnect.googleapis.com/v1/userinfo").json()
    except Exception:
        flash("No fue posible completar el inicio de sesión con Google.", "danger")
        return redirect(url_for("login"))

    email = (userinfo.get("email") or "").strip().lower()
    name = (userinfo.get("name") or email.split("@")[0]).strip()
    google_sub = userinfo.get("sub")
    email_verified = bool(userinfo.get("email_verified"))

    if not email or not google_sub or not email_verified:
        flash("Google no devolvió un correo verificado.", "danger")
        return redirect(url_for("login"))

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT id, name, email, password_hash, google_sub
            FROM users
            WHERE email = %s
            """,
            (email,),
        )
        user = cursor.fetchone()

        if user is None:
            cursor.execute(
                """
                INSERT INTO users (name, email, google_sub)
                VALUES (%s, %s, %s)
                """,
                (name, email, google_sub),
            )
            conn.commit()
            user_id = cursor.lastrowid
            user_name = name
        else:
            if user["google_sub"] is None:
                cursor.execute(
                    """
                    UPDATE users
                    SET google_sub = %s
                    WHERE id = %s
                    """,
                    (google_sub, user["id"]),
                )
                conn.commit()
            elif user["google_sub"] != google_sub:
                flash("La cuenta de Google no coincide con la vinculada a este correo.", "danger")
                return redirect(url_for("login"))

            user_id = user["id"]
            user_name = user["name"]
    finally:
        cursor.close()
        conn.close()

    session.clear()
    session["user_id"] = user_id
    session["user_name"] = user_name
    session["user_email"] = email
    session["auth_method"] = "Google OAuth"

    return redirect(url_for("home"))


@app.route("/home")
@login_required
def home():
    return render_template(
        "home.html",
        name=session.get("user_name"),
        email=session.get("user_email"),
        auth_method=session.get("auth_method"),
    )


@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
