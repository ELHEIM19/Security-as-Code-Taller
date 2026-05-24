from flask import Flask, jsonify, request
import ast
import hashlib
import operator
import os
import re
import uuid
from functools import wraps

from markupsafe import escape

app = Flask(__name__)

# Integrantes: Elheim Oquendo

# ERROR #1: PROBLEMA: datos sensibles escritos en el código. SOLUCIÓN: se leen desde variables de entorno y se guardan como hashes.
users = {}
credentials_env = os.environ.get("USERS_CREDENTIALS", "")
if credentials_env:
    for cred in credentials_env.split("|"):
        if ":" in cred:
            user, pwd_hash = cred.split(":", 1)
            users[user] = pwd_hash

# ERROR #6: PROBLEMA: modo de depuración activo en un entorno inseguro. SOLUCIÓN: se desactiva.
app.debug = False

# ERROR #7: PROBLEMA: secreto en el código. SOLUCIÓN: se exige una variable de entorno externa.
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise ValueError("La variable de entorno SECRET_KEY no está configurada.")
app.config["SECRET_KEY"] = secret_key

# ERROR #2: PROBLEMA: valor fijo para la sesión. SOLUCIÓN: se genera un identificador aleatorio por acceso.
active_sessions = {}
auth_attempts = {}


def require_session(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Credencial requerida"}), 401

        session_id = auth_header.replace("Bearer ", "", 1).strip()
        if not session_id or session_id not in active_sessions:
            return jsonify({"error": "Acceso denegado"}), 401
        return f(*args, **kwargs)

    return decorated_function


def hash_password(password):
    salt = os.environ.get("PASSWORD_SALT", "default-salt-change-in-prod")
    return hashlib.sha256((password + salt).encode()).hexdigest()


def verify_password(password, password_hash):
    return hash_password(password) == password_hash


# ERROR #8: PROBLEMA: datos recibidos sin validación. SOLUCIÓN: se valida estructura, campos y longitud.
@app.route("/auth", methods=["POST"])
def authenticate():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Datos inválidos"}), 400

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Usuario y contraseña requeridos"}), 400

    client_ip = request.remote_addr or "unknown"
    auth_attempts[client_ip] = auth_attempts.get(client_ip, 0) + 1
    if auth_attempts[client_ip] > 5:
        return jsonify({"error": "Demasiados intentos. Intente más tarde"}), 429

    if username in users and verify_password(password, users[username]):
        session_id = uuid.uuid4().hex
        active_sessions[session_id] = {"user": username}
        return jsonify({"message": "Autenticación exitosa", "session_id": session_id})

    # ERROR #10: PROBLEMA: respuesta demasiado explícita. SOLUCIÓN: se devuelve un mensaje genérico.
    return jsonify({"error": "Credenciales inválidas"}), 401


# ERROR #3: PROBLEMA: punto sensible sin protección. SOLUCIÓN: se exige sesión válida.
@app.route("/panel")
@require_session
def panel():
    return jsonify({"status": "ok"})


# ERROR #4: PROBLEMA: consultas armadas sin control de entrada. SOLUCIÓN: se valida y se limita el alfabeto permitido.
@app.route("/lookup")
def lookup():
    q = request.args.get("q", "").strip()

    if not q or len(q) > 100:
        return jsonify({"error": "Consulta inválida"}), 400

    if not re.match(r"^[a-zA-Z0-9\s\-]+$", q):
        return jsonify({"error": "Caracteres no permitidos"}), 400

    return jsonify({"results": [], "status": "ok"})


_allowed_bin_ops = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_allowed_unary_ops = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _safe_math(node):
    if isinstance(node, ast.Expression):
        return _safe_math(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _allowed_bin_ops:
        left = _safe_math(node.left)
        right = _safe_math(node.right)
        return _allowed_bin_ops[type(node.op)](left, right)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _allowed_unary_ops:
        operand = _safe_math(node.operand)
        return _allowed_unary_ops[type(node.op)](operand)
    raise ValueError("Expresión no permitida")


# ERROR #5: PROBLEMA: evaluación directa de expresiones externas. SOLUCIÓN: se parsea y se calcula con operadores permitidos.
@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")

    if not re.match(r"^[0-9+\-*/(). %]+$", expr):
        return jsonify({"error": "Expresión inválida"}), 400

    try:
        parsed = ast.parse(expr, mode="eval")
        result = _safe_math(parsed)
        return jsonify({"result": result}), 200
    except Exception:
        return jsonify({"error": "Expresión matemática inválida"}), 400


# ERROR #9: PROBLEMA: texto del cliente sin filtrar. SOLUCIÓN: se escapa antes de responder.
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")

    if not msg or len(msg) > 500:
        return jsonify({"error": "Mensaje inválido"}), 400

    safe_msg = escape(msg)
    return jsonify({"message": str(safe_msg)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
