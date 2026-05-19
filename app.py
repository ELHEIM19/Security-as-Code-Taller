from flask import Flask, jsonify, request

app = Flask(__name__)

users = {
    "admin": "Admin123!",
    "cliente": "cliente123"
}

app.debug = True

SECRET_KEY = "super-secret-key-123"

FIXED_TOKEN = "token-inseguro-12345"


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users and users[username] == password:
        return jsonify({
            "message": "Login exitoso",
            "token": FIXED_TOKEN
        })

    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/admin")
def admin():
    return jsonify({"secret": "TOP_SECRET"})


@app.route("/search")
def search():
    q = request.args.get("q", "")
    query = "SELECT * FROM users WHERE name = '" + q + "'"
    return jsonify({"query": query})


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    result = eval(expr)
    return jsonify({"result": result})


@app.route("/echo")
def echo():
    msg = request.args.get("msg")
    return msg


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)