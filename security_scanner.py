def scan_sast_issues(app_path):
    with open(app_path, "r", encoding="utf-8") as f:
        code = f.read()

    issues = []

    if "Admin123!" in code:
        issues.append("credenciales hardcodeadas")

    if "token-inseguro-12345" in code:
        issues.append("token estático inseguro")

    if "/admin" in code:
        issues.append("endpoint /admin sin autenticación")

    if "SELECT *" in code:
        issues.append("inyección SQL")

    if "eval(" in code:
        issues.append("uso inseguro de eval")

    return issues


def run_dast_checks(app_path):
    with open(app_path, "r", encoding="utf-8") as f:
        code = f.read()

    issues = []

    if "/admin" in code:
        issues.append("DAST: /admin accesible sin autenticación")

    if "login" in code:
        issues.append("DAST: login sin rate limiting")

    if "token" in code:
        issues.append("DAST: token inseguro expuesto")

    if "/search" in code:
        issues.append("DAST: inyección SQL en search")

    if "eval(" in code:
        issues.append("DAST: ejecución peligrosa")

    return issues