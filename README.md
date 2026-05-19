# Security as Code

> El entregable es el enlace del repositorio con la solución.

## Cómo ejecutar

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
python app.py
```

## Errores SAST a buscar en `app.py`

1. Información sensible escrita directamente en el código
2. Valor fijo usado como mecanismo de seguridad
3. Endpoint crítico sin ningún tipo de protección
4. Construcción de consultas sin control de entrada
5. Ejecución de expresiones provenientes del usuario
6. Configuración de depuración activa en entorno no seguro
7. Clave o secreto almacenado directamente en el código fuente
8. Falta de verificación de datos recibidos en una petición
9. Entrada del usuario utilizada sin ningún tipo de filtro
10. Respuesta que expone información interna del sistema

