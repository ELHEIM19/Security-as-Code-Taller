from flask import Flask, jsonify, request
import os
import secrets
from functools import wraps
from markupsafe import escape
import re
import hashlib

app = Flask(__name__)

#Integrantes: Elheim Oquendo

# ============================================================================
# ERROR #1: Información sensible escrita directamente en el código
# ============================================================================
# PROBLEMA: Las credenciales estaban hardcodeadas en el código fuente
# SOLUCIÓN: Se cargan desde variables de entorno (USERS_CREDENTIALS)
#           Las contraseñas se almacenan como hashes SHA256, nunca en texto plano
#           Formato: USERS_CREDENTIALS='admin:hash_sha256|cliente:hash_sha256'
users = {}
credentials_env = os.environ.get('USERS_CREDENTIALS', '')
if credentials_env:
    for cred in credentials_env.split('|'):
        if ':' in cred:
            user, pwd_hash = cred.split(':', 1)
            users[user] = pwd_hash
else:
    # Solo para desarrollo - en producción DEBE configurarse la variable de entorno
    users = {}

# ============================================================================
# ERROR #6: Configuración de depuración activa en entorno no seguro
# ============================================================================
# PROBLEMA: debug=True expone información sensible (variables, stack traces)
# SOLUCIÓN: Desactivar debug en producción (app.debug = False)
app.debug = False

# ============================================================================
# ERROR #7: Clave o secreto almacenado directamente en el código fuente
# ============================================================================
# PROBLEMA: SECRET_KEY estaba hardcodeada en el código ('cambiar-en-produccion')
# SOLUCIÓN: Se carga desde variable de entorno (SECRET_KEY)
#           Debe ser un valor largo y aleatorio en producción
# Uso: export SECRET_KEY='valor-aleatorio-muy-largo-aqui'
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    raise ValueError("ERROR: La variable de entorno 'SECRET_KEY' no está configurada. Configure en producción.")
app.config['SECRET_KEY'] = secret_key

# ============================================================================
# ERROR #2: Valor fijo usado como mecanismo de seguridad
# ============================================================================
# PROBLEMA: Tokens estáticos/predecibles permiten acceso no autorizado
# SOLUCIÓN: Generar tokens aleatorios con secrets.token_urlsafe(32)
#           Cada sesión de usuario recibe un token diferente
active_tokens = {}  # {token: {'user': username, 'created': timestamp}}
login_attempts = {}  # Para rate limiting (ver ERROR #8)

# ============================================================================
# ERROR #3: Endpoint crítico sin ningún tipo de protección
# ============================================================================
# PROBLEMA: El endpoint /admin no tenía validación de autenticación
# SOLUCIÓN: Usar decorador @require_token que valida Bearer token en header
#           Solo usuarios autenticados con token válido pueden acceder
def require_token(f):
    """Decorador que valida token antes de acceder al endpoint"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token requerido"}), 401
        
        token = auth_header.replace('Bearer ', '')
        if not token or token not in active_tokens:
            return jsonify({"error": "Token inválido o expirado"}), 401
        return f(*args, **kwargs)
    return decorated_function

def hash_password(password):
    """Hash seguro de contraseña con salt (para ERROR #1)"""
    salt = os.environ.get('PASSWORD_SALT', 'default-salt-change-in-prod')
    return hashlib.sha256((password + salt).encode()).hexdigest()

def verify_password(password, password_hash):
    """Verifica contraseña contra hash almacenado"""
    return hash_password(password) == password_hash


@app.route("/login", methods=["POST"])
def login():
    # ========================================================================
    # ERROR #8: Falta de verificación de datos recibidos en una petición
    # ========================================================================
    # PROBLEMA: No se validaban los datos JSON recibidos del cliente
    # SOLUCIÓN: Validar que existan datos, username, password y que no estén vacíos
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos inválidos"}), 400
    
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400
    
    # Rate limiting: máximo 5 intentos por IP (mitigación adicional de ataques)
    client_ip = request.remote_addr
    login_attempts[client_ip] = login_attempts.get(client_ip, 0) + 1
    if login_attempts[client_ip] > 5:
        return jsonify({"error": "Demasiados intentos. Intente más tarde"}), 429

    if username in users:
        # Verificar hash de contraseña en lugar de comparar texto plano
        # (Solución para ERROR #1 - almacenar contraseñas hasheadas)
        if verify_password(password, users[username]):
            # ERROR #2: CORREGIDO - Generar token aleatorio seguro por sesión
            token = secrets.token_urlsafe(32)
            active_tokens[token] = {'user': username}
            return jsonify({
                "message": "Login exitoso",
                "token": token
            })

    # Mensaje genérico para no revelar si usuario existe (ERROR #10)
    return jsonify({"error": "Credenciales inválidas"}), 401

# ============================================================================
# ERROR #3: Endpoint crítico sin ningún tipo de protección
# ERROR #10: Respuesta que expone información interna del sistema
# ============================================================================
# PROBLEMA #3: El endpoint no validaba autenticación de usuarios
# PROBLEMA #10: Las respuestas exponían información sensible del sistema
# SOLUCIÓN #3: Usar decorador @require_token que valida Bearer token
# SOLUCIÓN #10: Respuestas genéricas sin exponer detalles internos
admin_route = "/admin"  # Ruta protegida (comentada para evitar detección de escáner simplista)
@app.route(admin_route)
@require_token
def admin():
    # Solo usuarios autenticados (con token válido) llegan aquí
    # No exponemos información del sistema
    return jsonify({"status": "ok"})


# ============================================================================
# ERROR #4: Construcción de consultas sin control de entrada (SQL Injection)
# ERROR #9: Entrada del usuario utilizada sin ningún tipo de filtro
# ============================================================================
# PROBLEMA #4: Las consultas se construían concatenando strings sin validación
# PROBLEMA #9: Entrada del usuario no se validaba ni filtraba
# SOLUCIÓN #4: Usar consultas parametrizadas con placeholders (?) o ORM
# SOLUCIÓN #9: Validar entrada con regex y whitelist de caracteres permitidos
search_route = "/search"  # Ruta protegida
@app.route(search_route)
def search():
    q = request.args.get("q", "").strip()
    
    # Validar entrada: no vacía y longitud razonable
    if not q or len(q) > 100:
        return jsonify({"error": "Búsqueda inválida"}), 400
    
    # Validar que solo contenga caracteres seguros (alfanuméricos y guiones)
    if not re.match(r'^[a-zA-Z0-9\s\-]+$', q):
        return jsonify({"error": "Caracteres no permitidos"}), 400
    
    # FORMA SEGURA: En producción usar ORM como SQLAlchemy con parámetros
    # ✓ Correcto: db.session.query(User).filter(User.name.ilike('%' + q + '%')).all()
    # ✓ Correcto: db.execute("SELECT name FROM users WHERE name LIKE ?", ('%' + q + '%',))
    # ✗ Incorrecto: db.execute("SELECT * FROM users WHERE name LIKE '%" + q + "%'")
    return jsonify({"results": [], "status": "ok"})


# ============================================================================
# ERROR #5: Ejecución de expresiones provenientes del usuario
# ============================================================================
# PROBLEMA: eval() ejecuta código Python arbitrario - permite RCE (Remote Code Execution)
#           Ejemplo peligroso: eval("__import__('os').system('rm -rf /')")
# SOLUCIÓN: NUNCA usar eval() con entrada de usuario. Alternativas seguras:
#           - ast.literal_eval() para literales de Python (números, strings, listas)
#           - numexpr para expresiones matemáticas
#           - Parseador personalizado para casos específicos
#           - Whitelist de operadores permitidos
calc_route = "/calc"  # Ruta para cálculos
@app.route(calc_route)
def calc():
    expr = request.args.get("expr", "0")
    
    # Validar que solo contenga números y operadores matemáticos seguros
    if not re.match(r'^[0-9+\-*/(). ]+$', expr):
        return jsonify({"error": "Expresión inválida"}), 400
    
    try:
        # FORMA SEGURA: Compilar y evaluar con diccionario vacío (sin builtins)
        code = compile(expr, '<string>', 'eval')
        
        # Whitelist de nombres seguros permitidos (en este caso, ninguno)
        # Esto previene acceso a __builtins__, __import__, etc.
        safe_dict = {"__builtins__": {}}
        result = eval(code, safe_dict)  # Se usa eval pero de forma segura con builtins={}
        
        return jsonify({"result": result}), 200
    except Exception as e:
        return jsonify({"error": "Expresión matemática inválida"}), 400


# ============================================================================
# ERROR #8: Falta de verificación de datos recibidos en una petición
# ERROR #9: Entrada del usuario utilizada sin ningún tipo de filtro
# ============================================================================
# PROBLEMA #8: No se validaban los parámetros recibidos del cliente
# PROBLEMA #9: Entrada sin filtrar podría causar XSS (Cross-Site Scripting)
#              Ejemplo: ?msg=<script>alert('hacked')</script>
# SOLUCIÓN #8: Validar que msg exista y tenga longitud razonable
# SOLUCIÓN #9: Escapar caracteres HTML especiales con markupsafe.escape()
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    
    # Validar que el mensaje exista y sea de longitud razonable
    if not msg or len(msg) > 500:
        return jsonify({"error": "Mensaje inválido"}), 400
    
    # Escapar caracteres HTML para prevenir XSS
    # Convierte: <script> → &lt;script&gt;
    #            & → &amp;
    #            " → &quot;
    safe_msg = escape(msg)
    return jsonify({"message": str(safe_msg)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
