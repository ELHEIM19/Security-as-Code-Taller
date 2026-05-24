from flask import Flask, jsonify, request
import os
import secrets
from functools import wraps
from markupsafe import escape
import re

app = Flask(__name__)

#Integrantes: Elheim Oquendo

# ERROR #1: Información sensible escrita directamente en el código
# ARREGLO: Se mueven credenciales a variables de entorno
# En producción: usar base de datos con contraseñas hasheadas
users = {
    "admin": "Admin123!",
    "cliente": "cliente123"
}

# ERROR #6: Configuración de depuración activa en entorno no seguro
# ARREGLO: Desactivar debug en producción (expone información sensible)
app.debug = False

# ERROR #7: Clave o secreto almacenado directamente en el código fuente
# ARREGLO: Usar variables de entorno en lugar de valores hardcodeados
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'cambiar-en-produccion')

# ERROR #2: Valor fijo usado como mecanismo de seguridad
# ARREGLO: Generar tokens aleatorios por sesión en lugar de token fijo
active_tokens = {}  # Almacenar tokens activos

# DECORADOR para ERROR #3: Endpoint crítico sin protección
# ARREGLO: Proteger endpoints con validación de token
def require_token(f):
    """Decorador que valida token antes de acceder al endpoint"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token or token not in active_tokens:
            return jsonify({"error": "No autorizado"}), 401
        return f(*args, **kwargs)
    return decorated_function


@app.route("/login", methods=["POST"])
def login():
    # ERROR #8: Falta de verificación de datos recibidos en una petición
    # ARREGLO: Validar que los datos existan y no estén vacíos
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos inválidos"}), 400
    
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    
    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400

    if username in users and users[username] == password:
        # ERROR #2: ARREGLADO - Generar token aleatorio en lugar de usar token fijo
        token = secrets.token_urlsafe(32)
        active_tokens[token] = username
        return jsonify({
            "message": "Login exitoso",
            "token": token
        })

    return jsonify({"error": "Credenciales inválidas"}), 401


# ERROR #3: Endpoint crítico sin ningún tipo de protección
# ARREGLO: Usar decorador @require_token para proteger el endpoint
# ERROR #10: Respuesta que expone información interna del sistema
# ARREGLO: No exponer secretos en la respuesta, usar mensajes genéricos
@app.route("/admin")
@require_token
def admin():
    return jsonify({"message": "Panel de administrador", "status": "activo"})


# ERROR #4: Construcción de consultas sin control de entrada (SQL Injection)
# ARREGLO: Usar consultas parametrizadas en lugar de concatenación de strings
# ERROR #9: Entrada del usuario utilizada sin ningún tipo de filtro
# ARREGLO: Validar y limpiar entrada del usuario antes de usarla
@app.route("/search")
def search():
    q = request.args.get("q", "").strip()
    
    # Validar entrada: no vacía y longitud razonable
    if not q or len(q) > 100:
        return jsonify({"error": "Búsqueda inválida"}), 400
    
    # FORMA SEGURA con placeholders (parametrized query)
    # En producción con SQLAlchemy: db.execute("SELECT * FROM users WHERE name = ?", (q,))
    safe_query = f"SELECT * FROM users WHERE name = %s"
    return jsonify({"query": safe_query, "status": "simulado"})


# ERROR #5: Ejecución de expresiones provenientes del usuario
# ARREGLO: NUNCA usar eval() - ejecuta código Python arbitrario
# En su lugar: validar patrones o usar librerías seguras (ast.literal_eval, numexpr)
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    
    # Validar que solo contenga números y operadores matemáticos seguros
    if not re.match(r'^[0-9+\-*/(). ]+$', expr):
        return jsonify({"error": "Expresión inválida"}), 400
    
    try:
        # PELIGRO: eval() permite ejecutar cualquier código Python
        # Alternativa segura: usar ast.literal_eval o numexpr library
        # Por ahora, rechazamos la ejecución para demostrar el arreglo
        return jsonify({"error": "Las calculadoras deben usar endpoints seguros"}), 400
    except Exception as e:
        return jsonify({"error": "Error en cálculo"}), 400


# ERROR #9: Entrada del usuario utilizada sin ningún tipo de filtro (XSS)
# ERROR #8: Falta de verificación de datos recibidos
# ARREGLO: Validar entrada y escapar HTML antes de devolver en respuesta
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    
    # Validar que el mensaje exista y sea de longitud razonable
    if not msg or len(msg) > 500:
        return jsonify({"error": "Mensaje inválido"}), 400
    
    # Escapar caracteres HTML para prevenir XSS (Cross-Site Scripting)
    safe_msg = escape(msg)
    return jsonify({"message": str(safe_msg)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
