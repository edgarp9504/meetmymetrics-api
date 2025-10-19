# MeetMyMetrics - Backend (FastAPI)

Backend de **MeetMyMetrics**, una plataforma que centraliza el registro y autenticación de usuarios para posteriores módulos de análisis y automatización de datos.

## 🚀 Tecnologías principales
- [FastAPI](https://fastapi.tiangolo.com/) sobre Python 3.10 para la capa HTTP.
- PostgreSQL como base de datos transaccional.
- Azure Key Vault y `DefaultAzureCredential` para la gestión de secretos en entornos gestionados.
- Argon2 a través de `passlib` para el hashing seguro de contraseñas.

## 📂 Estructura del proyecto
```
app/
├── auth/              # Esquemas Pydantic y rutas de autenticación
├── core/              # Configuración y utilidades de seguridad
├── db/                # Conexión a PostgreSQL
├── utils/             # Funciones auxiliares (hashing)
└── main.py            # Punto de entrada de FastAPI
```

## ✅ Requisitos previos
1. Python 3.10+
2. PostgreSQL accesible con una base de datos y una tabla `users` que contenga al menos las columnas:
   - `email` (`UNIQUE`)
   - `hashed_password`
   - `name`
3. (Opcional) Acceso a Azure Key Vault para la resolución automática de secretos.

## ⚙️ Configuración del entorno

```bash
python -m venv .venv
source .venv/bin/activate  # En Windows: .venv\\Scripts\\activate
pip install -r requirements.txt
```

### Variables de entorno
Define las siguientes variables antes de iniciar la aplicación:

| Variable | Descripción |
| --- | --- |
| `ENV` | Nombre del entorno (por defecto `dev`). |
| `POSTGRES_CONNECTION_STRING` | Cadena de conexión a PostgreSQL en formato `postgresql://user:pass@host:port/db` cuando no se use Key Vault. |
| `JWT_SECRET` | Clave secreta para firmar tokens JWT cuando no se use Key Vault. |
| `KEY_VAULT_URI` | (Opcional) URI del Azure Key Vault que expone los secretos `POSTGRES-URI`. |

Si `KEY_VAULT_URI` está definida, la aplicación obtendrá `POSTGRES-URI` y automáticamente desde el Key Vault usando `DefaultAzureCredential`; en caso contrario se emplearán las variables locales `POSTGRES_CONNECTION_STRING` y `JWT_SECRET`.

## ▶️ Ejecución local

```bash
uvicorn app.main:app --reload
```

El servidor quedará disponible por defecto en `http://127.0.0.1:8000`. También podrás acceder a la documentación interactiva en `http://127.0.0.1:8000/docs`.

## 🧩 Endpoints disponibles

### `POST /auth/register`
Registra un nuevo usuario.

**Body (JSON):**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "Passw0rd!",
  "name": "Nombre Apellido"
}
```

**Validaciones principales**
- El correo debe tener formato válido y dominio entregable; se rechazan dominios desechables.
- La contraseña debe tener mínimo 8 caracteres, incluir mayúsculas, minúsculas, dígitos y símbolos.
- El nombre no puede estar vacío.

**Respuestas**
- `200 OK`: `{ "message": "User registered successfully" }`
- `400 Bad Request`: Detalle del error de validación (`Invalid email format`, `Disposable or fake email not allowed`, `Password does not meet security requirements`, `Email already registered`, etc.).
- `500 Internal Server Error`: Error inesperado durante el proceso.

### `POST /auth/login`
Valida las credenciales de un usuario registrado.

**Body (JSON):**
```json
{
  "email": "usuario@ejemplo.com",
  "password": "Passw0rd!"
}
```

**Respuestas**
- `200 OK`: `{ "message": "Login successful" }`
- `400 Bad Request`: `{ "error": "Invalid credentials" }`
- `500 Internal Server Error`: Error inesperado durante la verificación.

> ⚠️ Nota: actualmente el endpoint de login solo confirma las credenciales; si se requiere emitir un JWT, puede utilizarse la utilidad `create_access_token` disponible en `app/core/security.py`.

## 🔐 Seguridad
- Las contraseñas se almacenan mediante hashing Argon2 y nunca en texto plano.
- La comunicación con la base de datos se realiza usando conexiones directas definidas en `app/db/connection.py`.
- Se incluye una utilidad para generar tokens JWT (`HS256`) en `app/core/security.py` para futuras extensiones del flujo de autenticación.

## 🚀 Despliegue
La aplicación está preparada para ejecutarse en Azure App Service. En entornos gestionados, configure `KEY_VAULT_URI` y conceda permisos de acceso al servicio para que pueda resolver los secretos necesarios.

## 🤝 Contribución
1. Cree una rama a partir de `main`.
2. Realice los cambios deseados y añada pruebas si aplica.
3. Abra un Pull Request describiendo la motivación y pruebas realizadas.

---

¡Listo! Ahora tienes una guía actualizada para trabajar y consumir la API de MeetMyMetrics.
