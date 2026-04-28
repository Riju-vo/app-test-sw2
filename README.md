# 🧪 app-test — Mini Blog para VulnScanner

App web de prueba creada para el parcial de Ingeniería de Software 2.  
Contiene **vulnerabilidades intencionales** detectables con VulnScanner.

---

## 📁 Estructura

```
app-test/
├── app.py            ← Versión VULNERABLE (Fase 1 - primer escaneo)
├── app_patched.py    ← Versión PARCHEADA  (Fase 2 - segundo escaneo)
├── requirements.txt
└── README.md
```

---

## 🚀 Cómo ejecutar

```bash
# 1. Instalar dependencias
pip install -r requirements.txt

# 2. Fase 1: App con vulnerabilidades (puerto 5000)
python app.py

# 3. Fase 2: App parcheada (puerto 5001)
python app_patched.py
```

---

## 🔴 Vulnerabilidades en `app.py` (Fase 1)

| Vulnerabilidad | Riesgo | Detalle |
|---|---|---|
| **Cryptographic Failures (A02)** | Crítico | HTTP puro, sin SSL/TLS |
| **Security Headers ausentes** | Medio | Sin CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **CSRF** | Medio | Ningún formulario tiene token CSRF |
| **Broken Access Control (A01)** | Medio | `/admin` accesible sin autenticación |
| **SQL Injection** | Bajo | Login y búsqueda con queries concatenadas |
| **XSS (Stored)** | Bajo | Comentarios renderizados con `\|safe` en Jinja2 |
| **Open Redirect** | Bajo | Parámetro `?next=` sin validación de dominio |

### 🧪 Cómo probar cada vulnerabilidad manualmente

**SQL Injection en login:**
```
Usuario: ' OR '1'='1
Contraseña: cualquiera
```

**XSS en comentarios:**
```html
<script>alert('XSS!')</script>
```

**Broken Access Control:**
```
Ir directamente a http://localhost:5000/admin sin estar logueado
```

**Open Redirect:**
```
http://localhost:5000/login?next=https://evil.com
```

---

## ✅ Correcciones en `app_patched.py` (Fase 2)

| Vulnerabilidad | Corrección aplicada |
|---|---|
| **A02 / SSL** | `debug=False`, se recomienda usar HTTPS con certificado |
| **Security Headers** | `@app.after_request` añade CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| **CSRF** | Token generado con `secrets.token_hex(32)` en cada sesión, validado en todos los POST |
| **Broken Access Control** | `/admin` verifica `session["user"] == "admin"`, retorna 403 si no |
| **SQL Injection** | Queries parametrizadas con `?` en todos los lugares |
| **XSS** | Se elimina `\|safe`, se usa `markupsafe.escape()` al guardar |
| **Open Redirect** | Función `safe_redirect()` valida que la URL sea interna |

---

## 🎯 Flujo de demostración

```
1. Ejecutar app.py          → escanear con VulnScanner → guardar como Escaneo #1
2. Ejecutar app_patched.py  → escanear con VulnScanner → guardar como Escaneo #2
3. Comparar en VulnScanner  → mostrar mejora de seguridad
```

---

*Creado para el parcial de Ingeniería de Software 2 — VulnScanner demo*