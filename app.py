"""
app-test: Mini Blog App con vulnerabilidades INTENCIONALES
==========================================================
Esta app fue creada para probar la herramienta VulnScanner.

VULNERABILIDADES PRESENTES (FASE 1 - Sin parchear):
  [CRÍTICO]  A02 - Sin HTTPS / certificado SSL
  [MEDIO]    Security Headers ausentes (CSP, HSTS, X-Content-Type, etc.)
  [MEDIO]    A01 - Sin control de acceso en rutas admin
  [MEDIO]    CSRF - Sin tokens CSRF en formularios
  [BAJO]     XSS - Renderizado de HTML sin sanitizar en comentarios
  [BAJO]     SQL Injection (simulado con parámetro directo en query)
  [BAJO]     Open Redirect - Parámetro ?next= sin validar
"""

from flask import Flask, request, render_template_string, redirect, session, g
import sqlite3, os

app = Flask(__name__)
app.secret_key = "supersecret123"  # ❌ Clave débil hardcodeada

DB_PATH = "blog.db"

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
        INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123');
        INSERT OR IGNORE INTO users VALUES (2, 'richi', '1234');
        INSERT OR IGNORE INTO posts VALUES
            (1, 'Bienvenidos al Blog', 'Este es el primer post del sistema.', 'admin'),
            (2, 'Tips de programacion', 'Usar siempre buenas practicas de codigo limpio.', 'richi');
    """)
    db.commit()
    db.close()

# ─── Sin HTTPS forzado, sin headers de seguridad ─────────────────────────────
# ❌ No hay @app.after_request que añada:
#    Content-Security-Policy, Strict-Transport-Security,
#    X-Content-Type-Options, Referrer-Policy, Permissions-Policy

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
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        db = get_db()
        # ❌ SQL Injection: concatenación directa sin parámetros
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        user = db.execute(query).fetchone()
        db.close()
        if user:
            session["user"] = username
            # ❌ Open Redirect: redirige a ?next= sin validar el dominio
            next_url = request.args.get("next", "/")
            return redirect(next_url)
        else:
            error = "Credenciales incorrectas."
    # ❌ Sin token CSRF en el formulario
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
        author = request.form.get("author", "Anónimo")
        content = request.form.get("content", "")
        # ❌ Sin validación ni sanitización → XSS stored
        # ❌ Sin token CSRF
        db.execute("INSERT INTO comments (post_id, author, content) VALUES (?,?,?)",
                   (post_id, author, content))
        db.commit()

    comments = db.execute("SELECT * FROM comments WHERE post_id=?", (post_id,)).fetchall()
    db.close()
    # ❌ |safe en Jinja2 → permite HTML/JS en comentarios
    return render_template_string(TEMPLATE_POST, post=post, comments=comments)


@app.route("/admin")
def admin():
    # ❌ Sin verificar si el usuario es admin (Broken Access Control)
    db = get_db()
    users = db.execute("SELECT * FROM users").fetchall()
    posts = db.execute("SELECT * FROM posts").fetchall()
    db.close()
    return render_template_string(TEMPLATE_ADMIN, users=users, posts=posts)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    # ❌ SQL Injection via parámetro GET
    results = db.execute(f"SELECT * FROM posts WHERE title LIKE '%{q}%'").fetchall()
    db.close()
    return render_template_string(TEMPLATE_SEARCH, results=results, q=q)


# ─── Templates ────────────────────────────────────────────────────────────────

TEMPLATE_BASE = """
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>MiBlog - App Test</title>
  <link href="https://fonts.googleapis.com/css2?family=Merriweather:wght@400;700&family=Source+Sans+3:wght@400;600&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Source Sans 3', sans-serif; background: #f5f0eb; color: #2c2c2c; }
    nav { background: #1a1a2e; padding: 1rem 2rem; display: flex; gap: 1.5rem; align-items: center; }
    nav a { color: #e0d6c8; text-decoration: none; font-weight: 600; font-size: 0.9rem; letter-spacing: 0.05em; }
    nav a:hover { color: #f4a261; }
    nav .brand { font-family: 'Merriweather', serif; color: #f4a261; font-size: 1.1rem; margin-right: auto; }
    .container { max-width: 860px; margin: 2.5rem auto; padding: 0 1.5rem; }
    .card { background: white; border-radius: 8px; padding: 1.5rem; margin-bottom: 1.2rem;
            box-shadow: 0 2px 8px rgba(0,0,0,0.07); }
    h1 { font-family: 'Merriweather', serif; font-size: 1.8rem; margin-bottom: 0.5rem; }
    h2 { font-family: 'Merriweather', serif; font-size: 1.3rem; margin-bottom: 0.4rem; }
    a { color: #e76f51; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .badge { display: inline-block; padding: 0.2em 0.7em; border-radius: 99px; font-size: 0.75rem;
             font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
    .badge-danger { background: #fee2e2; color: #b91c1c; }
    .badge-warning { background: #fef3c7; color: #92400e; }
    input, textarea { width: 100%; padding: 0.6rem 0.8rem; border: 1.5px solid #d1ccc4;
                      border-radius: 6px; font-family: inherit; font-size: 0.95rem;
                      margin-bottom: 0.8rem; background: #fdfaf7; }
    input:focus, textarea:focus { outline: none; border-color: #e76f51; }
    button, .btn { background: #e76f51; color: white; border: none; padding: 0.6rem 1.4rem;
                   border-radius: 6px; cursor: pointer; font-weight: 600; font-size: 0.9rem; }
    button:hover, .btn:hover { background: #cf5a3d; }
    .alert { background: #fee2e2; color: #b91c1c; border-left: 4px solid #b91c1c;
             padding: 0.8rem 1rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.9rem; }
    table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
    th { background: #1a1a2e; color: white; padding: 0.6rem 1rem; text-align: left; }
    td { padding: 0.6rem 1rem; border-bottom: 1px solid #ece8e1; }
    tr:hover td { background: #fdf8f3; }
    .vuln-banner { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px;
                   padding: 0.8rem 1rem; margin-bottom: 1.5rem; font-size: 0.85rem; color: #856404; }
    .comment-block { border-left: 3px solid #f4a261; padding: 0.5rem 1rem; margin: 0.5rem 0;
                     background: #fdf8f3; border-radius: 0 6px 6px 0; }
    .comment-author { font-weight: 700; font-size: 0.85rem; color: #555; margin-bottom: 0.2rem; }
  </style>
</head>
<body>
  <nav>
    <span class="brand">✍ MiBlog</span>
    <a href="/">Inicio</a>
    <a href="/search">Buscar</a>
    <a href="/admin">Admin</a>
    {% if user %}
      <span style="color:#a0a0b0;font-size:0.85rem;">{{ user }}</span>
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
  <div class="vuln-banner">
    ⚠️ <strong>App de prueba</strong> — Esta aplicación contiene vulnerabilidades intencionales para demostración con VulnScanner.
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
    <!-- ❌ Sin CSRF token -->
    <form method="POST">
      <label style="font-size:0.85rem;font-weight:600;">Usuario</label>
      <input type="text" name="username" placeholder="admin">
      <label style="font-size:0.85rem;font-weight:600;">Contraseña</label>
      <input type="password" name="password" placeholder="••••••">
      <button type="submit" style="width:100%;margin-top:0.5rem;">Entrar</button>
    </form>
    <p style="margin-top:1rem;font-size:0.8rem;color:#888;">
      Prueba: admin / admin123
    </p>
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
    <!-- ❌ Renderiza HTML sin sanitizar → XSS stored -->
    <div>{{ c.content|safe }}</div>
  </div>
  {% endfor %}

  <div class="card" style="margin-top:1.2rem;">
    <h2 style="margin-bottom:1rem;">Dejar un comentario</h2>
    <!-- ❌ Sin CSRF token -->
    <form method="POST">
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
  <div class="alert">
    🔓 <strong>Panel Admin sin autenticación</strong> — Cualquier usuario puede acceder a /admin
  </div>
  <h1 style="margin-bottom:1.5rem;">Panel de Administración</h1>

  <div class="card">
    <h2 style="margin-bottom:1rem;">Usuarios registrados</h2>
    <table>
      <tr><th>ID</th><th>Usuario</th><th>Contraseña (plano)</th></tr>
      {% for u in users %}
      <tr><td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.password }}</td></tr>
      {% endfor %}
    </table>
  </div>

  <div class="card">
    <h2 style="margin-bottom:1rem;">Todos los posts</h2>
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
    <!-- ❌ Sin CSRF, sin rate limit -->
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


# ─── Inicio ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    # ❌ debug=True en producción expone el debugger interactivo
    # ❌ HTTP puro, sin SSL → Cryptographic Failures (A02)
    app.run(host="0.0.0.0", port=5000, debug=True)