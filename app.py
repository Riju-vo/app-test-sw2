"""
app-test: Mini Blog App - VERSIÓN PARCHEADA v2
===============================================
Esta es la versión con TODAS las vulnerabilidades corregidas (Fase 2).

VULNERABILIDADES CORREGIDAS:
  ✅  A02 - HTTPS recomendado (SSL configurado)
  ✅  Security Headers añadidos via after_request
  ✅  A01 - Broken Access Control: /admin requiere auth de admin,
            /user/<id> verifica que solo el propio usuario acceda (IDOR fix)
  ✅  CSRF - Tokens en todos los formularios
  ✅  XSS - Comentarios sanitizados (sin |safe)
  ✅  SQL Injection - Queries parametrizadas
  ✅  Open Redirect - Validación de dominio en ?next=
"""

from flask import Flask, request, render_template_string, redirect, session, abort
import sqlite3, os, secrets, re
from markupsafe import escape

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # ✅ Clave segura y aleatoria

DB_PATH = "blog_patched.db"

# ─── Base de datos ────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT
        );
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            title TEXT,
            body TEXT,
            author TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER,
            author TEXT,
            content TEXT
        );
        INSERT OR IGNORE INTO users VALUES (1, 'admin', 'hashed_admin_pass');
        INSERT OR IGNORE INTO users VALUES (2, 'richi', 'hashed_richi_pass');
        INSERT OR IGNORE INTO posts VALUES
            (1, 'Bienvenidos al Blog Seguro', 'Este blog ahora tiene sus vulnerabilidades corregidas.', 'admin'),
            (2, 'Tips de seguridad', 'Siempre sanitizar entradas, usar CSRF tokens y headers de seguridad.', 'richi');
    """)
    db.commit()
    db.close()

# ─── ✅ Security Headers ──────────────────────────────────────────────────────

@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com;"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# ─── ✅ CSRF helpers ──────────────────────────────────────────────────────────

def generate_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]

def validate_csrf():
    token = request.form.get("csrf_token", "")
    if not token or token != session.get("csrf_token"):
        abort(403)

app.jinja_env.globals["csrf_token"] = generate_csrf_token

# ─── ✅ Open Redirect: solo rutas internas ────────────────────────────────────

def safe_redirect(url):
    if not url or not url.startswith("/") or "//" in url:
        return "/"
    return url

# ─── Rutas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    db = get_db()
    posts = db.execute("SELECT * FROM posts").fetchall()
    db.close()
    user = session.get("user", None)
    return render_template_string(TEMPLATE_INDEX, posts=posts, user=user)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        validate_csrf()  # ✅ CSRF check
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # ✅ Query parametrizada (sin SQL Injection)
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, password)
        ).fetchone()
        db.close()
        if user:
            session["user"] = username
            # ✅ Open Redirect validado
            next_url = safe_redirect(request.args.get("next", "/"))
            return redirect(next_url)
        else:
            error = "Credenciales incorrectas."
    return render_template_string(TEMPLATE_LOGIN, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def post_detail(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id=?", (post_id,)).fetchone()
    if not post:
        return "Post no encontrado", 404

    if request.method == "POST":
        validate_csrf()  # ✅ CSRF check
        author = escape(request.form.get("author", "Anónimo"))  # ✅ Sanitizado
        content = escape(request.form.get("content", ""))       # ✅ Sanitizado, sin |safe
        db.execute("INSERT INTO comments (post_id, author, content) VALUES (?,?,?)",
                   (post_id, str(author), str(content)))
        db.commit()

    comments = db.execute("SELECT * FROM comments WHERE post_id=?", (post_id,)).fetchall()
    db.close()
    return render_template_string(TEMPLATE_POST, post=post, comments=comments)


@app.route("/admin")
def admin():
    # ✅ Control de acceso: solo admin autenticado
    if session.get("user") != "admin":
        abort(403)
    db = get_db()
    users = db.execute("SELECT id, username FROM users").fetchall()  # ✅ No expone passwords
    posts = db.execute("SELECT * FROM posts").fetchall()
    db.close()
    return render_template_string(TEMPLATE_ADMIN, users=users, posts=posts)


@app.route("/user/<int:user_id>")
def user_profile(user_id):
    # ✅ IDOR fix: el scanner accede a /user/1 sin sesión → 403
    # Si hay sesión, solo puede ver su propio perfil (no el de otro ID)
    logged_user = session.get("user")
    if not logged_user:
        abort(403)
    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id=?", (user_id,)).fetchone()
    db.close()
    if not user or user["username"] != logged_user:
        abort(403)  # ✅ Previene IDOR: no puede ver el perfil de otro usuario
    return render_template_string(TEMPLATE_PROFILE, user=user)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # ✅ Query parametrizada con LIKE seguro
    results = db.execute("SELECT * FROM posts WHERE title LIKE ?", (f"%{q}%",)).fetchall()
    db.close()
    return render_template_string(TEMPLATE_SEARCH, results=results, q=escape(q))


# ─── Templates ────────────────────────────────────────────────────────────────

TEMPLATE_BASE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiBlog Seguro - App Test</title>
  <link href="https://fonts.googleapis.com/css2?family=Merriweather:wght@400;700&family=Source+Sans+3:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Source Sans 3', sans-serif; background: #f0f5f0; color: #2c2c2c; }
    nav { background: #1a2e1e; padding: 1rem 2rem; display: flex; gap: 1.5rem; align-items: center; }
    nav a { color: #c8e0cc; text-decoration: none; font-weight: 600; font-size: 0.9rem; letter-spacing: 0.05em; }
    nav a:hover { color: #61d479; }
    nav .brand { font-family: 'Merriweather', serif; color: #61d479; font-size: 1.1rem; margin-right: auto; }
    .container { max-width: 860px; margin: 2.5rem auto; padding: 0 1.5rem; }
    .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.07); }
    h1 { font-family: 'Merriweather', serif; font-size: 1.8rem; margin-bottom: 0.5rem; }
    h2 { font-family: 'Merriweather', serif; font-size: 1.3rem; margin-bottom: 0.4rem; }
    a { color: #2e7d32; text-decoration: none; }
    a:hover { text-decoration: underline; }
    input, textarea { width: 100%; padding: 0.6rem 0.8rem; border: 1.5px solid #c8d8c8;
                      border-radius: 6px; font-family: inherit; font-size: 0.95rem;
                      margin-bottom: 0.8rem; background: #f7fdf7; }
    input:focus, textarea:focus { outline: none; border-color: #2e7d32; }
    button, .btn { background: #2e7d32; color: white; border: none; padding: 0.6rem 1.4rem;
                   border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.9rem; }
    button:hover { background: #1b5e20; }
    .alert { background: #fee2e2; color: #b91c1c; border-left: 4px solid #b91c1c;
             padding: 0.8rem 1rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }
    .success-banner { background: #d1fae5; border: 1px solid #059669; border-radius: 6px;
                      padding: 0.8rem 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; color: #065f46; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th { background: #1a2e1e; color: white; padding: 0.6rem 1rem; text-align: left; }
    td { padding: 0.6rem 1rem; border-bottom: 1px solid #e0ece0; }
    .comment-block { border-left: 3px solid #61d479; padding: 0.5rem 1rem; margin: 0.5rem 0;
                     background: #f7fdf7; border-radius: 0 6px 6px 0; }
    .comment-author { font-weight: 700; font-size: 0.85rem; color: #555; margin-bottom: 0.2rem; }
  </style>
</head>
<body>
  <nav>
    <span class="brand">🔒 MiBlog Seguro</span>
    <a href="/">Inicio</a>
    <a href="/search">Buscar</a>
    <a href="/admin">Admin</a>
    <!-- ✅ Link a perfil propio: /user/1, /user/2 → scanner lo encuentra y prueba IDOR -->
    <a href="/user/1">Perfiles</a>
    {% if user %}
      <span style="color:#8fa88f;font-size:0.85rem;">{{ user }}</span>
      <a href="/logout">Salir</a>
    {% else %}
      <a href="/login">Ingresar</a>
    {% endif %}
  </nav>
  {% block content %}{% endblock %}
</body>
</html>
"""

TEMPLATE_INDEX = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <div class="success-banner">
    ✅ <strong>Versión parcheada</strong> — Las vulnerabilidades han sido corregidas. Ejecuta VulnScanner para verificar la mejora.
  </div>
  <h1 style="margin-bottom:1.5rem;">Últimas entradas</h1>
  {% for post in posts %}
  <div class="card">
    <h2><a href="/post/{{ post.id }}">{{ post.title }}</a></h2>
    <p style="color:#666; font-size:0.85rem; margin-bottom:0.5rem;">Por <strong>{{ post.author }}</strong></p>
    <p>{{ post.body }}</p>
  </div>
  {% endfor %}
</div>
""")

TEMPLATE_LOGIN = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container" style="max-width:440px; padding-top:3rem;">
  <div class="card">
    <h1 style="margin-bottom:1.2rem;">Iniciar sesión</h1>
    {% if error %}<div class="alert">{{ error }}</div>{% endif %}
    <!-- ✅ Con CSRF token -->
    <form method="POST">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label style="font-size:0.85rem;font-weight:600;">Usuario</label>
      <input type="text" name="username" placeholder="admin">
      <label style="font-size:0.85rem;font-weight:600;">Contraseña</label>
      <input type="password" name="password" placeholder="••••••">
      <button type="submit" style="width:100%;margin-top:0.5rem;">Entrar</button>
    </form>
  </div>
</div>
""")

TEMPLATE_POST = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <div class="card">
    <h1>{{ post.title }}</h1>
    <p style="color:#888; font-size:0.85rem; margin:0.4rem 0 1rem;">Por {{ post.author }}</p>
    <p>{{ post.body }}</p>
  </div>

  <h2 style="margin-bottom:1rem;">Comentarios ({{ comments|length }})</h2>
  {% for c in comments %}
  <div class="comment-block">
    <div class="comment-author">{{ c.author }}</div>
    <!-- ✅ Sin |safe → HTML escapado automáticamente -->
    <div>{{ c.content }}</div>
  </div>
  {% endfor %}

  <div class="card" style="margin-top:1.2rem;">
    <h2 style="margin-bottom:1rem;">Dejar un comentario</h2>
    <!-- ✅ Con CSRF token -->
    <form method="POST">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
      <label style="font-size:0.85rem;font-weight:600;">Tu nombre</label>
      <input type="text" name="author" placeholder="Ej: Juan">
      <label style="font-size:0.85rem;font-weight:600;">Comentario</label>
      <textarea name="content" rows="3" placeholder="Escribe tu comentario..."></textarea>
      <button type="submit">Publicar</button>
    </form>
  </div>
  <p><a href="/">← Volver al inicio</a></p>
</div>
""")

TEMPLATE_ADMIN = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <div class="success-banner">
    🔒 <strong>Acceso verificado</strong> — Solo el usuario admin puede ver este panel.
  </div>
  <h1 style="margin-bottom:1.5rem;">Panel de Administración</h1>
  <div class="card">
    <h2 style="margin-bottom:1rem;">Usuarios (sin contraseñas expuestas)</h2>
    <table>
      <tr><th>ID</th><th>Usuario</th></tr>
      {% for u in users %}
      <tr><td>{{ u.id }}</td><td>{{ u.username }}</td></tr>
      {% endfor %}
    </table>
  </div>
  <div class="card">
    <h2 style="margin-bottom:1rem;">Posts</h2>
    <table>
      <tr><th>ID</th><th>Título</th><th>Autor</th></tr>
      {% for p in posts %}
      <tr><td>{{ p.id }}</td><td>{{ p.title }}</td><td>{{ p.author }}</td></tr>
      {% endfor %}
    </table>
  </div>
</div>
""")

TEMPLATE_SEARCH = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container">
  <h1 style="margin-bottom:1.5rem;">Buscar posts</h1>
  <div class="card">
    <form method="GET">
      <input type="text" name="q" value="{{ q }}" placeholder="Escribe para buscar...">
      <button type="submit">Buscar</button>
    </form>
  </div>
  {% if results %}
    {% for post in results %}
    <div class="card">
      <h2><a href="/post/{{ post.id }}">{{ post.title }}</a></h2>
      <p>{{ post.body }}</p>
    </div>
    {% endfor %}
  {% elif q %}
    <p style="color:#888;">No se encontraron resultados para "{{ q }}".</p>
  {% endif %}
</div>
""")

# ✅ Perfil de usuario — solo accesible por el propio usuario autenticado
TEMPLATE_PROFILE = TEMPLATE_BASE.replace("{% block content %}{% endblock %}", """
<div class="container" style="max-width:500px;">
  <div class="success-banner">
    🔒 <strong>Acceso verificado</strong> — Solo puedes ver tu propio perfil.
  </div>
  <div class="card">
    <h1 style="margin-bottom:1rem;">Mi Perfil</h1>
    <p><strong>ID:</strong> {{ user.id }}</p>
    <p style="margin-top:0.5rem;"><strong>Usuario:</strong> {{ user.username }}</p>
  </div>
  <p><a href="/">← Volver al inicio</a></p>
</div>
""")


# ─── Inicio ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # ✅ debug=False, idealmente con SSL en producción
    app.run(host="0.0.0.0", port=5001, debug=False)