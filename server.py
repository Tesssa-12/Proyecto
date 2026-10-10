import base64
import hashlib
import hmac
import io
import os
import secrets
import string
import time
import zipfile
from pathlib import Path

import pandas as pd
from PIL import Image, UnidentifiedImageError
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from google import genai
from google.genai import types

from database import (
    database_connection,
    make_password_hash,
    verify_password,
    verify_password_or_legacy,
)


app = FastAPI()
_cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS", "http://localhost:8000,http://127.0.0.1:8000"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

_PROJECT_DIR = Path(__file__).resolve().parent


@app.get("/", include_in_schema=False)
def serve_index():
    return FileResponse(_PROJECT_DIR / "index.html", media_type="text/html")


@app.get("/styles.css", include_in_schema=False)
def serve_stylesheet():
    return FileResponse(_PROJECT_DIR / "styles.css", media_type="text/css")


_genai_key = os.getenv("GOOGLE_API_KEY")
client = genai.Client(api_key=_genai_key) if _genai_key else None

SESSION_COOKIE = "peya_session"
SESSION_LIFETIME_SECONDS = 12 * 60 * 60
MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_CONVERSION_FILE_BYTES = 25 * 1024 * 1024
IMAGE_MIME_SIGNATURES = {
    "image/jpeg": lambda content: content.startswith(b"\xff\xd8\xff"),
    "image/png": lambda content: content.startswith(b"\x89PNG\r\n\x1a\n"),
    "image/gif": lambda content: content.startswith((b"GIF87a", b"GIF89a")),
    "image/webp": lambda content: (
        len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP"
    ),
}


def _session_secret():
    secret = os.getenv("SESSION_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise HTTPException(
            status_code=503, detail="La autenticación no está configurada."
        )
    return secret.encode("utf-8")


def _b64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _create_session_token(session_id, expires_at):
    payload = f"{session_id}.{expires_at}".encode("ascii")
    signature = hmac.new(_session_secret(), payload, hashlib.sha256).digest()
    return f"{_b64url_encode(payload)}.{_b64url_encode(signature)}"


def _read_session_token(token):
    try:
        encoded_payload, encoded_signature = token.split(".", 1)
        payload = _b64url_decode(encoded_payload)
        signature = _b64url_decode(encoded_signature)
        expected = hmac.new(_session_secret(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            return None
        session_id_text, expiry_text = payload.decode("ascii").split(".", 1)
        session_id, expires_at = int(session_id_text), int(expiry_text)
        if session_id <= 0:
            return None
        return session_id, expires_at
    except (ValueError, UnicodeError, HTTPException):
        return None


def _close_session(session_id):
    with database_connection() as connection:
        connection.cursor().execute(
            """
            UPDATE dbo.Historial_Sesiones
            SET Fecha_Cierre = GETDATE(),
                Duracion_Minutos = DATEDIFF(MINUTE, Fecha_Inicio, GETDATE())
            WHERE ID_Sesion = ? AND Fecha_Cierre IS NULL
            """,
            session_id,
        )


def _load_session_user(session_id):
    with database_connection() as connection:
        row = connection.cursor().execute(
            """
            SELECT u.ID_Usuario, u.Nombre_Usuario, u.Email, u.Rol,
                   a.ID_Agente, s.ID_Supervisor
            FROM dbo.Historial_Sesiones AS hs
            JOIN dbo.Usuarios AS u ON u.ID_Usuario = hs.ID_Usuario
            LEFT JOIN dbo.Agentes AS a
              ON a.ID_Usuario = u.ID_Usuario AND a.Estado = 1
            LEFT JOIN dbo.Supervisores AS s
              ON s.ID_Usuario = u.ID_Usuario AND s.Estado = 1
            WHERE hs.ID_Sesion = ? AND hs.Fecha_Cierre IS NULL AND u.Estado = 1
            """,
            session_id,
        ).fetchone()
    if not row:
        return None
    role = str(row.Rol)
    if role == "Agente" and row.ID_Agente is not None and row.ID_Supervisor is None:
        return {
            "user_id": int(row.ID_Usuario),
            "username": row.Nombre_Usuario,
            "email": row.Email,
            "role": role,
            "agent_id": int(row.ID_Agente),
        }
    if role == "Supervisor" and row.ID_Supervisor is not None and row.ID_Agente is None:
        return {
            "user_id": int(row.ID_Usuario),
            "username": row.Nombre_Usuario,
            "email": row.Email,
            "role": role,
            "supervisor_id": int(row.ID_Supervisor),
        }
    return None


def _optional_session_user(request):
    if not request.cookies.get(SESSION_COOKIE):
        return None
    _session_secret()
    token = request.cookies.get(SESSION_COOKIE)
    decoded = _read_session_token(token)
    if not decoded:
        return None
    session_id, expires_at = decoded
    if expires_at <= int(time.time()):
        try:
            _close_session(session_id)
        except Exception:
            raise HTTPException(status_code=503, detail="Servicio temporalmente no disponible.")
        return None
    try:
        user = _load_session_user(session_id)
    except Exception:
        raise HTTPException(status_code=503, detail="Servicio temporalmente no disponible.")
    return user


def require_session(request: Request):
    user = _optional_session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Autenticación requerida.")
    return user


def require_agent(user=Depends(require_session)):
    if user["role"] != "Agente":
        raise HTTPException(status_code=403, detail="Acceso no autorizado.")
    return user


def require_supervisor(user=Depends(require_session)):
    if user["role"] != "Supervisor":
        raise HTTPException(status_code=403, detail="Acceso no autorizado.")
    return user


async def _request_json(request):
    try:
        return await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Datos de solicitud inválidos.")


def _json_object(value):
    if not isinstance(value, dict):
        raise HTTPException(status_code=400, detail="Datos de solicitud inválidos.")
    return value


def _user_text(data, key, maximum, required=True):
    value = data.get(key)
    if not isinstance(value, str):
        if not required and value is None:
            return None
        raise HTTPException(status_code=400, detail="Datos de usuario inválidos.")
    value = value.strip()
    if (required and not value) or len(value) > maximum:
        raise HTTPException(status_code=400, detail="Datos de usuario inválidos.")
    return value or None


async def _read_limited_upload(upload, limit):
    content = bytearray()
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > limit:
            raise HTTPException(
                status_code=413, detail="El archivo supera el tamaño permitido."
            )
    if not content:
        raise HTTPException(status_code=400, detail="El archivo no puede estar vacío.")
    return bytes(content)


def _safe_upload_name(name, expected_extension):
    if not isinstance(name, str):
        raise HTTPException(status_code=400, detail="El nombre del archivo no es válido.")
    filename = os.path.basename(name.replace("\\", "/")).strip()
    if (
        not filename
        or len(filename) > 255
        or any(not char.isprintable() for char in filename)
        or not filename.lower().endswith(expected_extension)
    ):
        raise HTTPException(status_code=400, detail="El nombre del archivo no es válido.")
    return filename


def _is_valid_xlsx(content):
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            members = archive.infolist()
            if len(members) > 10_000:
                return False
            if sum(member.file_size for member in members) > 100 * 1024 * 1024:
                return False
            names = {member.filename for member in members}
            return (
                "[Content_Types].xml" in names
                and "xl/workbook.xml" in names
            )
    except (OSError, zipfile.BadZipFile, ValueError):
        return False


def _password_matches(password, stored_hash):
    try:
        return verify_password(password, stored_hash)
    except Exception:
        return False


def _generic_database_error():
    raise HTTPException(
        status_code=503, detail="Servicio temporalmente no disponible."
    )


@app.post("/api/auth/login")
async def login(request: Request, response: Response):
    _session_secret()
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Datos de acceso inválidos.")
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("username"), str)
        or not isinstance(data.get("password"), str)
    ):
        raise HTTPException(status_code=400, detail="Datos de acceso inválidos.")
    username = data["username"].strip()
    password = data["password"]
    if not username or len(username) > 50 or len(password) > 1024:
        raise HTTPException(status_code=401, detail="Usuario o contraseña inválidos.")
    login_error = None
    try:
        with database_connection() as connection:
            rows = connection.cursor().execute(
                """
                SELECT u.ID_Usuario, u.Nombre_Usuario, u.Email, u.Rol,
                       u.[Contraseña], a.ID_Agente, s.ID_Supervisor
                FROM dbo.Usuarios AS u WITH (UPDLOCK, HOLDLOCK)
                LEFT JOIN dbo.Agentes AS a
                  ON a.ID_Usuario = u.ID_Usuario AND a.Estado = 1
                LEFT JOIN dbo.Supervisores AS s
                  ON s.ID_Usuario = u.ID_Usuario AND s.Estado = 1
                WHERE u.Nombre_Usuario = ? AND u.Estado = 1
                """,
                username,
            ).fetchall()
            if len(rows) != 1:
                raise HTTPException(
                    status_code=401, detail="Usuario o contraseña inválidos."
                )
            row = rows[0]
            cursor = connection.cursor()
            cursor.execute(
                """
                IF NOT EXISTS (
                    SELECT 1
                    FROM dbo.Intentos_Acceso WITH (UPDLOCK, HOLDLOCK)
                    WHERE ID_Usuario = ?
                )
                INSERT INTO dbo.Intentos_Acceso
                    (ID_Usuario, Intentos_Fallidos, Bloqueado_Hasta, Fecha_Actualizacion)
                VALUES (?, 0, NULL, SYSDATETIME())
                """,
                row.ID_Usuario,
                row.ID_Usuario,
            )
            attempt_row = cursor.execute(
                """
                SELECT Intentos_Fallidos, Bloqueado_Hasta,
                       CASE WHEN Bloqueado_Hasta > SYSDATETIME()
                            THEN DATEDIFF(SECOND, SYSDATETIME(), Bloqueado_Hasta)
                            ELSE 0 END
                FROM dbo.Intentos_Acceso WITH (UPDLOCK, HOLDLOCK)
                WHERE ID_Usuario = ?
                """,
                row.ID_Usuario,
            ).fetchone()
            failed_attempts = int(attempt_row[0])
            locked_until = attempt_row[1]
            seconds_remaining = int(attempt_row[2] or 0)
            if seconds_remaining > 0:
                login_error = HTTPException(
                    status_code=423,
                    detail=(
                        "La cuenta está bloqueada durante 24 horas. "
                        "Solicita a tu supervisor actualizar la contraseña "
                        "desde Credenciales."
                    ),
                )
            else:
                if locked_until is not None:
                    failed_attempts = 0
                    cursor.execute(
                        """
                        UPDATE dbo.Intentos_Acceso
                        SET Intentos_Fallidos = 0, Bloqueado_Hasta = NULL,
                            Fecha_Actualizacion = SYSDATETIME()
                        WHERE ID_Usuario = ?
                        """,
                        row.ID_Usuario,
                    )
            if login_error is None:
                role = str(row.Rol)
                valid_role_record = (
                    role == "Agente"
                    and row.ID_Agente is not None
                    and row.ID_Supervisor is None
                ) or (
                    role == "Supervisor"
                    and row.ID_Supervisor is not None
                    and row.ID_Agente is None
                )
                password_valid, migrate_legacy_password = verify_password_or_legacy(
                    password, row[4]
                )
                if not valid_role_record:
                    login_error = HTTPException(
                        status_code=401, detail="Usuario o contraseña inválidos."
                    )
                elif not password_valid:
                    failed_attempts += 1
                    if failed_attempts >= 3:
                        cursor.execute(
                            """
                            UPDATE dbo.Intentos_Acceso
                            SET Intentos_Fallidos = 3,
                                Bloqueado_Hasta = DATEADD(HOUR, 24, SYSDATETIME()),
                                Fecha_Actualizacion = SYSDATETIME()
                            WHERE ID_Usuario = ?
                            """,
                            row.ID_Usuario,
                        )
                        login_error = HTTPException(
                            status_code=423,
                            detail=(
                                "Contraseña incorrecta. La cuenta quedó bloqueada "
                                "durante 24 horas. Contacta a tu supervisor para "
                                "actualizar la contraseña desde Credenciales."
                            ),
                        )
                    else:
                        cursor.execute(
                            """
                            UPDATE dbo.Intentos_Acceso
                            SET Intentos_Fallidos = ?,
                                Bloqueado_Hasta = NULL,
                                Fecha_Actualizacion = SYSDATETIME()
                            WHERE ID_Usuario = ?
                            """,
                            failed_attempts,
                            row.ID_Usuario,
                        )
                        login_error = HTTPException(
                            status_code=401,
                            detail=(
                                "Contraseña incorrecta te quedan "
                                f"{4 - failed_attempts} intentos"
                            ),
                        )
                else:
                    cursor.execute(
                        """
                        UPDATE dbo.Intentos_Acceso
                        SET Intentos_Fallidos = 0, Bloqueado_Hasta = NULL,
                            Fecha_Actualizacion = SYSDATETIME()
                        WHERE ID_Usuario = ?
                        """,
                        row.ID_Usuario,
                    )
                    if migrate_legacy_password:
                        cursor.execute(
                            """
                            UPDATE dbo.Usuarios
                            SET [Contraseña] = ?
                            WHERE ID_Usuario = ? AND [Contraseña] = ?
                            """,
                            make_password_hash(password),
                            row.ID_Usuario,
                            row[4],
                        )
                        if cursor.rowcount != 1:
                            login_error = HTTPException(
                                status_code=401,
                                detail="Usuario o contraseña inválidos.",
                            )
                    if login_error is None:
                        session_row = cursor.execute(
                            """
                            INSERT INTO dbo.Historial_Sesiones (ID_Usuario, Fecha_Inicio, IP_Address)
                            OUTPUT INSERTED.ID_Sesion
                            VALUES (?, GETDATE(), ?)
                            """,
                            row.ID_Usuario,
                            request.client.host if request.client else None,
                        ).fetchone()
                        session_id = int(session_row[0])
    except HTTPException:
        raise
    except Exception:
        _generic_database_error()

    if login_error is not None:
        raise login_error

    expires_at = int(time.time()) + SESSION_LIFETIME_SECONDS
    token = _create_session_token(session_id, expires_at)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_LIFETIME_SECONDS,
        httponly=True,
        secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower()
        in {"1", "true", "yes", "on"},
        samesite="lax",
        path="/",
    )
    return {
        "user": {
            "id": int(row.ID_Usuario),
            "username": row.Nombre_Usuario,
            "email": row.Email,
            "role": role,
        }
    }


def _public_user(user):
    return {
        "id": user["user_id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    }


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, user=Depends(require_session)):
    token = request.cookies.get(SESSION_COOKIE)
    decoded = _read_session_token(token or "")
    if decoded:
        try:
            _close_session(decoded[0])
        except Exception:
            _generic_database_error()
    response.delete_cookie(
        key=SESSION_COOKIE,
        httponly=True,
        secure=os.getenv("SESSION_COOKIE_SECURE", "false").lower()
        in {"1", "true", "yes", "on"},
        samesite="lax",
        path="/",
    )
    return {"message": "Sesión cerrada."}


@app.get("/api/users")
def listar_usuarios(user=Depends(require_supervisor)):
    try:
        with database_connection() as connection:
            rows = connection.cursor().execute(
                """
                SELECT u.ID_Usuario, u.Nombre_Usuario, u.Email, u.Rol,
                       CASE WHEN u.Rol = 'Agente' THEN a.Nombre_Completo
                            WHEN u.Rol = 'Supervisor' THEN s.Nombre_Completo END,
                       CASE WHEN u.Rol = 'Agente' THEN a.Departamento
                            WHEN u.Rol = 'Supervisor' THEN s.Departamento END
                FROM dbo.Usuarios AS u
                LEFT JOIN dbo.Agentes AS a ON a.ID_Usuario = u.ID_Usuario
                LEFT JOIN dbo.Supervisores AS s ON s.ID_Usuario = u.ID_Usuario
                WHERE u.Estado = 1
                  AND ((u.Rol = 'Agente' AND a.Estado = 1 AND s.ID_Supervisor IS NULL)
                    OR (u.Rol = 'Supervisor' AND s.Estado = 1 AND a.ID_Agente IS NULL))
                ORDER BY u.Nombre_Usuario, u.ID_Usuario
                """
            ).fetchall()
    except Exception:
        _generic_database_error()
    return {
        "users": [
            {
                "id": int(row.ID_Usuario),
                "username": row.Nombre_Usuario,
                "email": row.Email,
                "role": row.Rol,
                "full_name": row[4],
                "department": row[5],
            }
            for row in rows
        ]
    }


@app.post("/api/users")
async def crear_usuario(request: Request, user=Depends(require_supervisor)):
    data = _json_object(await _request_json(request))
    username = _user_text(data, "username", 50)
    email = _user_text(data, "email", 100)
    full_name = _user_text(data, "full_name", 100)
    role = _user_text(data, "role", 20)
    department = _user_text(data, "department", 50, required=False)
    password = data.get("password")
    if role not in {"Agente", "Supervisor"}:
        raise HTTPException(status_code=400, detail="El rol no es válido.")
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        raise HTTPException(
            status_code=400,
            detail="La contraseña debe tener al menos 12 caracteres.",
        )
    password_hash = make_password_hash(password)
    try:
        with database_connection() as connection:
            cursor = connection.cursor()
            exists = cursor.execute(
                """
                SELECT TOP (1) ID_Usuario
                FROM dbo.Usuarios WITH (UPDLOCK, HOLDLOCK)
                WHERE Nombre_Usuario = ? OR Email = ?
                """,
                username,
                email,
            ).fetchone()
            if exists:
                raise HTTPException(
                    status_code=409, detail="El usuario o correo ya está registrado."
                )
            row = cursor.execute(
                """
                INSERT INTO dbo.Usuarios
                    (Nombre_Usuario, Email, [Contraseña], Rol, Estado, Fecha_Creacion)
                OUTPUT INSERTED.ID_Usuario
                VALUES (?, ?, ?, ?, 1, GETDATE())
                """,
                username,
                email,
                password_hash,
                role,
            ).fetchone()
            user_id = int(row[0])
            if role == "Agente":
                cursor.execute(
                    """
                    INSERT INTO dbo.Agentes
                        (ID_Usuario, Email_Corporativo, Nombre_Completo,
                         Departamento, Fecha_Ingreso, Estado)
                    VALUES (?, ?, ?, ?, GETDATE(), 1)
                    """,
                    user_id,
                    email,
                    full_name,
                    department,
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO dbo.Supervisores
                        (ID_Usuario, Email_Corporativo, Nombre_Completo,
                         Departamento, Fecha_Ingreso, Estado)
                    VALUES (?, ?, ?, ?, GETDATE(), 1)
                    """,
                    user_id,
                    email,
                    full_name,
                    department,
                )
    except HTTPException:
        raise
    except Exception:
        _generic_database_error()
    return {
        "user": {
            "id": user_id,
            "username": username,
            "email": email,
            "role": role,
            "full_name": full_name,
            "department": department,
        }
    }


@app.post("/api/users/{user_id}/password")
async def actualizar_contrasena_usuario(
    user_id: int,
    request: Request,
    user=Depends(require_supervisor),
):
    data = _json_object(await _request_json(request))
    password = data.get("password")
    if not isinstance(password, str) or len(password) < 12 or len(password) > 1024:
        raise HTTPException(
            status_code=400,
            detail="La contraseña debe tener al menos 12 caracteres.",
        )
    password_hash = make_password_hash(password)
    try:
        with database_connection() as connection:
            cursor = connection.cursor()
            updated = cursor.execute(
                """
                UPDATE dbo.Usuarios
                SET [Contraseña] = ?
                WHERE ID_Usuario = ? AND Estado = 1
                """,
                password_hash,
                user_id,
            ).rowcount
            if updated != 1:
                raise HTTPException(status_code=404, detail="Usuario no encontrado.")
            cursor.execute(
                "DELETE FROM dbo.Intentos_Acceso WHERE ID_Usuario = ?",
                user_id,
            )
    except HTTPException:
        raise
    except Exception:
        _generic_database_error()
    return {"message": "Contraseña actualizada."}


@app.get("/api/auth/session")
def session_info(user=Depends(require_session)):
    return {"user": _public_user(user)}


def _image_mime(content):
    for mime, matches in IMAGE_MIME_SIGNATURES.items():
        if matches(content):
            return mime
    return None


def _validate_image(content, declared_mime):
    detected_mime = _image_mime(content)
    if not detected_mime or detected_mime != declared_mime:
        return False
    expected_format = {
        "image/jpeg": "JPEG",
        "image/png": "PNG",
        "image/gif": "GIF",
        "image/webp": "WEBP",
    }[detected_mime]
    try:
        with Image.open(io.BytesIO(content)) as image:
            if image.format != expected_format:
                return False
            if image.width <= 0 or image.height <= 0 or image.width * image.height > 40_000_000:
                return False
            image.verify()
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        return False
    return True


async def _read_valid_image(upload):
    if not upload:
        return None, None, None
    if not upload.filename:
        if not await upload.read(1):
            return None, None, None
        raise HTTPException(status_code=400, detail="El formato de imagen no es válido.")
    declared_mime = (upload.content_type or "").split(";", 1)[0].strip().lower()
    if declared_mime not in IMAGE_MIME_SIGNATURES:
        raise HTTPException(status_code=400, detail="El formato de imagen no es válido.")
    content = bytearray()
    while True:
        chunk = await upload.read(64 * 1024)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > MAX_IMAGE_BYTES:
            raise HTTPException(status_code=413, detail="La imagen supera el tamaño permitido.")
    if not _validate_image(content, declared_mime):
        raise HTTPException(status_code=400, detail="El formato de imagen no es válido.")
    detected_mime = declared_mime
    filename = os.path.basename((upload.filename or "imagen").replace("\\", "/"))
    filename = "".join(char for char in filename if char.isprintable())[:255] or "imagen"
    return bytes(content), filename, detected_mime


@app.post("/api/sugerencias")
@app.post("/api/suggestions", include_in_schema=False)
async def crear_sugerencia(
    title: str = Form(...),
    detail: str = Form(...),
    image: UploadFile | None = File(None),
    user=Depends(require_agent),
):
    title = title.strip()
    detail = detail.strip()
    if not title or len(title) > 255 or not detail:
        raise HTTPException(status_code=400, detail="El título y el detalle son obligatorios.")
    image_bytes, image_name, _ = await _read_valid_image(image)
    try:
        with database_connection() as connection:
            suggestion_id = connection.cursor().execute(
                """
                INSERT INTO dbo.Sugerencias
                    (ID_Agente, Email_Agente, Titulo_Reporte, Detalle_Explicativo,
                     Imagen_Adjunta, Nombre_Imagen, Fecha_Hora, Estado)
                OUTPUT INSERTED.ID_Sugerencia, INSERTED.Fecha_Hora
                VALUES (?, ?, ?, ?, ?, ?, GETDATE(), ?)
                """,
                user["agent_id"],
                user["email"],
                title,
                detail,
                image_bytes,
                image_name,
                "Pendiente",
            ).fetchone()
    except Exception:
        _generic_database_error()
    return {
        "id": int(suggestion_id[0]),
        "date": suggestion_id[1].isoformat() if suggestion_id[1] else None,
        "email": user["email"],
        "title": title,
        "detail": detail,
        "has_image": image_bytes is not None,
    }


def _load_suggestions():
    try:
        with database_connection() as connection:
            rows = connection.cursor().execute(
                """
                SELECT ID_Sugerencia, Email_Agente, Titulo_Reporte,
                       Detalle_Explicativo, Fecha_Hora,
                       CASE WHEN Imagen_Adjunta IS NULL THEN 0 ELSE 1 END
                FROM dbo.Sugerencias
                ORDER BY Fecha_Hora DESC, ID_Sugerencia DESC
                """
            ).fetchall()
    except Exception:
        _generic_database_error()
    return [
        {
            "id": int(row.ID_Sugerencia),
            "email": row.Email_Agente,
            "title": row.Titulo_Reporte,
            "detail": row.Detalle_Explicativo,
            "date": row.Fecha_Hora.isoformat() if row.Fecha_Hora else None,
            "has_image": bool(row[5]),
        }
        for row in rows
    ]


@app.get("/api/suggestions")
def listar_sugerencias(user=Depends(require_supervisor)):
    return {"suggestions": _load_suggestions()}


@app.get("/api/sugerencias")
def listar_sugerencias_es(user=Depends(require_supervisor)):
    return {"sugerencias": _load_suggestions()}


@app.get("/api/sugerencias/{suggestion_id}/imagen")
@app.get("/api/suggestions/{suggestion_id}/image", include_in_schema=False)
def ver_imagen_sugerencia(suggestion_id: int, user=Depends(require_supervisor)):
    try:
        with database_connection() as connection:
            row = connection.cursor().execute(
                "SELECT Imagen_Adjunta FROM dbo.Sugerencias WHERE ID_Sugerencia = ?",
                suggestion_id,
            ).fetchone()
    except Exception:
        _generic_database_error()
    if not row or row[0] is None:
        raise HTTPException(status_code=404, detail="Imagen no encontrada.")
    content = bytes(row[0])
    mime = _image_mime(content)
    if not mime:
        raise HTTPException(status_code=404, detail="Imagen no encontrada.")
    return Response(
        content=content,
        media_type=mime,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@app.post("/api/conversions")
async def guardar_conversion(
    original: UploadFile = File(...),
    converted: UploadFile = File(...),
    original_name: str = Form(...),
    converted_name: str = Form(...),
    user=Depends(require_agent),
):
    started_at = time.monotonic()
    safe_original_name = _safe_upload_name(original_name, ".csv")
    safe_converted_name = _safe_upload_name(converted_name, ".xlsx")
    original_contents = await _read_limited_upload(
        original, MAX_CONVERSION_FILE_BYTES
    )
    converted_contents = await _read_limited_upload(
        converted, MAX_CONVERSION_FILE_BYTES
    )
    if not _is_valid_xlsx(converted_contents):
        raise HTTPException(
            status_code=400, detail="El archivo XLSX convertido no es válido."
        )

    try:
        with database_connection() as connection:
            conversion_id = connection.cursor().execute(
                """
                INSERT INTO dbo.Conversion_CSV_XLSX
                    (ID_Agente, Nombre_Archivo_Original,
                     Contenido_Archivo_Original, Nombre_Archivo_Convertido,
                     Contenido_Archivo_Convertido, Fecha_Carga, Fecha_Conversion,
                     Tiempo_Procesamiento_Segundos, Estado)
                OUTPUT INSERTED.ID_Conversion
                VALUES (?, ?, ?, ?, ?, GETDATE(), GETDATE(), ?, ?)
                """,
                user["agent_id"],
                safe_original_name,
                original_contents,
                safe_converted_name,
                converted_contents,
                max(0, int(time.monotonic() - started_at)),
                "Completado",
            ).fetchone()[0]
    except Exception:
        _generic_database_error()
    return {"id": int(conversion_id)}


@app.post("/api/conversions/{conversion_id}/downloaded")
def registrar_descarga_conversion(
    conversion_id: int,
    user=Depends(require_agent),
):
    try:
        with database_connection() as connection:
            cursor = connection.cursor()
            cursor.execute(
                """
                UPDATE dbo.Conversion_CSV_XLSX
                SET Fecha_Descarga = GETDATE()
                WHERE ID_Conversion = ? AND ID_Agente = ?
                """,
                conversion_id,
                user["agent_id"],
            )
            if cursor.rowcount != 1:
                raise HTTPException(
                    status_code=404, detail="Conversión no encontrada."
                )
    except HTTPException:
        raise
    except Exception:
        _generic_database_error()
    return {"message": "Descarga registrada."}


@app.get("/api/dashboard/errors")
def listar_errores_dashboard(user=Depends(require_supervisor)):
    try:
        with database_connection() as connection:
            rows = connection.cursor().execute(
                """
                SELECT ID_Dashboard, ID_Codificacion, ID_Agente,
                       Archivo_Original, Numero_Fila, Tipo_Error,
                       Descripcion_Tecnica, Email_Agente, Fecha_Hora,
                       Estado_Error, Fecha_Resolucion
                FROM dbo.Dashboard_Errores
                ORDER BY Fecha_Hora DESC, ID_Dashboard DESC
                """
            ).fetchall()
    except Exception:
        _generic_database_error()
    return {
        "errors": [
            {
                "id": int(row.ID_Dashboard),
                "codification_id": int(row.ID_Codificacion),
                "agent_id": int(row.ID_Agente),
                "file_name": row.Archivo_Original,
                "row": row.Numero_Fila,
                "type": row.Tipo_Error,
                "description": row.Descripcion_Tecnica,
                "agent_email": row.Email_Agente,
                "date": row.Fecha_Hora.isoformat() if row.Fecha_Hora else None,
                "status": row.Estado_Error,
                "resolved_at": (
                    row.Fecha_Resolucion.isoformat()
                    if row.Fecha_Resolucion
                    else None
                ),
            }
            for row in rows
        ]
    }


def _persist_audit(
    user,
    upload_name,
    uploaded_contents,
    processed_contents,
    issue_records,
    processing_seconds,
):
    """Persist an authenticated agent audit without writing row values to logs."""
    try:
        with database_connection() as connection:
            cursor = connection.cursor()
            coding_id = cursor.execute(
                """
                INSERT INTO dbo.Codificacion
                    (ID_Agente, Nombre_Archivo_Original, Contenido_Archivo,
                     Fecha_Carga, Tiempo_Procesamiento_Segundos,
                     Nombre_Archivo_Procesado, Contenido_Archivo_Procesado, Estado)
                OUTPUT INSERTED.ID_Codificacion
                VALUES (?, ?, ?, GETDATE(), ?, ?, ?, ?)
                """,
                user["agent_id"],
                upload_name[:255],
                uploaded_contents,
                max(0, int(processing_seconds)),
                "productos_procesados.csv" if processed_contents is not None else None,
                processed_contents,
                "Completado" if processed_contents is not None else "Con errores",
            ).fetchone()[0]

            error_rows = cursor.execute(
                "SELECT ID_Error, Tipo_Error FROM dbo.Errores"
            ).fetchall()
            known_errors = {
                str(row.Tipo_Error).strip().casefold(): int(row.ID_Error)
                for row in error_rows
            }
            for issue in issue_records:
                error_id = known_errors.get(issue["type"].casefold())
                cursor.execute(
                    """
                    INSERT INTO dbo.Dashboard_Errores
                        (ID_Codificacion, ID_Agente, Archivo_Original, Numero_Fila,
                         Tipo_Error, Descripcion_Tecnica, Email_Agente, Fecha_Hora,
                         Estado_Error)
                    VALUES (?, ?, ?, ?, ?, ?, ?, GETDATE(), ?)
                    """,
                    coding_id,
                    user["agent_id"],
                    upload_name[:255],
                    issue["row"],
                    issue["type"],
                    issue["description"][:1000],
                    user["email"],
                    "Pendiente" if processed_contents is None else "Corregido",
                )
                # This existing table requires a foreign key into dbo.Errores.
                # Never invent or seed lookup values to bypass that requirement.
                if error_id is not None and issue["row"] is not None:
                    cursor.execute(
                        """
                        INSERT INTO dbo.Detalles_Errores_Codificacion
                            (ID_Codificacion, ID_Error, Numero_Fila, Descripcion_Detalle)
                        VALUES (?, ?, ?, ?)
                        """,
                        coding_id,
                        error_id,
                        issue["row"],
                        issue["description"][:1000],
                    )
    except Exception:
        raise


@app.post("/api/auditar-productos")
async def auditar_productos(
    request: Request,
    file: UploadFile = File(...),
    force_sku: bool = Form(False),
):
    started_at = time.monotonic()
    contents = await file.read()
    user = _optional_session_user(request)
    agent = user if user and user["role"] == "Agente" else None
    upload_name = os.path.basename((file.filename or "archivo.xlsx").replace("\\", "/"))
    issue_records = []
    try:
        df = pd.read_excel(io.BytesIO(contents))
    except Exception:
        if agent:
            try:
                _persist_audit(
                    agent, upload_name, contents, None,
                    [{"row": None, "type": "Archivo inválido",
                      "description": "El archivo Excel no es válido."}],
                    time.monotonic() - started_at,
                )
            except Exception:
                return JSONResponse(
                    status_code=503,
                    content={"error_type": "general", "error": "No fue posible guardar la auditoría."},
                )
        return JSONResponse(
            status_code=400,
            content={
                "error_type": "general",
                "error": "El archivo Excel está corrupto o no es válido.",
            },
        )

    columnas_a_eliminar = [
        "ID Sección", "ID", "GTIN", "Stock", "Global Catalog ID", "Indice"
    ]
    df = df.drop(columns=[col for col in columnas_a_eliminar if col in df.columns])

    # 1. VALIDACIÓN DE PRECIOS FALTANTES CON IA
    if "Nombre" in df.columns and "Precio" in df.columns:
        filas_sin_precio = df[df["Nombre"].notnull() & df["Precio"].isnull()]
        if not filas_sin_precio.empty:
            row_numbers = [int(i + 2) for i in filas_sin_precio.index]
            items_precio = [{"name": "", "row": row} for row in row_numbers]
            diagnostico_cognitivo = (
                "Validación cognitiva completada: Se requiere corrección de precios obligatorios."
            )
            if client:
                try:
                    prompt_ia = (
                        "Redacta una conclusión técnica breve sobre el impacto de precios "
                        f"faltantes en las filas {row_numbers}. No solicites ni incluyas "
                        "nombres de productos u otros valores del archivo."
                    )
                    response_ia = client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=prompt_ia,
                        config=types.GenerateContentConfig(temperature=0.1),
                    )
                    diagnostico_cognitivo = response_ia.text
                except Exception:
                    pass
            issue_records.extend(
                {
                    "row": row,
                    "type": "Precio faltante",
                    "description": "Precio faltante.",
                }
                for row in row_numbers
            )
            if agent:
                try:
                    _persist_audit(
                        agent, upload_name, contents, None, issue_records,
                        time.monotonic() - started_at,
                    )
                except Exception:
                    return JSONResponse(
                        status_code=503,
                        content={"error_type": "general", "error": "No fue posible guardar la auditoría."},
                    )
            return JSONResponse(
                status_code=400,
                content={
                    "error_type": "price",
                    "items": items_precio,
                    "ai_insight": diagnostico_cognitivo,
                },
            )

    sku_changes = []
    change_records = []

    # 2. VALIDACIÓN DE SKUS VACÍOS Y DUPLICADOS CON IA
    if "SKU" not in df.columns and "Nombre" in df.columns:
        df["SKU"] = ""

    if "SKU" in df.columns:
        df["SKU"] = (
            df["SKU"]
            .fillna("")
            .astype(str)
            .str.strip()
            .replace({"nan": "", "None": "", "<NA>": ""})
        )

        filas_sin_sku = df[df["Nombre"].notnull() & (df["SKU"].str.strip() == "")]

        if not filas_sin_sku.empty and not force_sku:
            row_numbers = [int(i + 2) for i in filas_sin_sku.index]
            items_sku = [{"name": "", "row": row} for row in row_numbers]
            insight_sku = "Se detectaron campos SKU vacíos que requieren atención operativa."
            if client:
                try:
                    prompt_sku_ia = (
                        "Redacta una conclusión técnica breve sobre la importancia de "
                        f"completar los SKU vacíos en las filas {row_numbers}. No solicites "
                        "ni incluyas nombres de productos u otros valores del archivo."
                    )
                    response_sku_ia = client.models.generate_content(
                        model="gemini-2.5-flash",
                        contents=prompt_sku_ia,
                        config=types.GenerateContentConfig(temperature=0.1),
                    )
                    insight_sku = response_sku_ia.text
                except Exception:
                    pass
            issue_records.extend(
                {
                    "row": row,
                    "type": "SKU faltante",
                    "description": "SKU faltante.",
                }
                for row in row_numbers
            )
            if agent:
                try:
                    _persist_audit(
                        agent, upload_name, contents, None, issue_records,
                        time.monotonic() - started_at,
                    )
                except Exception:
                    return JSONResponse(
                        status_code=503,
                        content={"error_type": "general", "error": "No fue posible guardar la auditoría."},
                    )
            return JSONResponse(
                status_code=400,
                content={
                    "error_type": "missing_sku",
                    "items": items_sku,
                    "ai_insight": insight_sku,
                },
            )

        if not filas_sin_sku.empty and force_sku:
            skus_existentes = {
                str(sku).strip().upper() for sku in df["SKU"] if str(sku).strip()
            }
            caracteres_sku = string.ascii_uppercase + string.digits
            for idx in filas_sin_sku.index:
                while True:
                    nuevo_sku = "".join(
                        secrets.choice(caracteres_sku) for _ in range(8)
                    )
                    if nuevo_sku.upper() not in skus_existentes:
                        break
                skus_existentes.add(nuevo_sku.upper())
                df.at[idx, "SKU"] = nuevo_sku
                row = int(idx + 2)
                sku_changes.append({"name": "", "new": nuevo_sku, "row": row})
                change_records.append(
                    {
                        "row": row,
                        "type": "SKU faltante",
                        "description": "SKU vacío corregido automáticamente.",
                    }
                )

        sku_counts = {}
        for idx in df.index:
            sku_val = df.at[idx, "SKU"]
            if not sku_val or str(sku_val).strip() == "":
                continue
            sku_val = str(sku_val).strip()
            if sku_val not in sku_counts:
                sku_counts[sku_val] = 0
            else:
                sku_counts[sku_val] += 1
                prefijo = chr(96 + sku_counts[sku_val])
                nuevo_sku = f"{prefijo}{sku_val}"
                df.at[idx, "SKU"] = nuevo_sku
                row = int(idx + 2)
                sku_changes.append({"name": "", "new": nuevo_sku, "row": row})
                change_records.append(
                    {
                        "row": row,
                        "type": "SKU duplicado",
                        "description": "SKU duplicado corregido automáticamente.",
                    }
                )

    # 3. EXPORTACIÓN DEL ARCHIVO PROCESADO: se conserva el formato existente.
    csv_buffer = io.BytesIO()
    df.to_csv(
        csv_buffer, index=False, header=False, sep=";", encoding="utf-8-sig"
    )
    csv_contents = csv_buffer.getvalue()
    csv_base64 = base64.b64encode(csv_contents).decode("utf-8")
    issue_records.extend(change_records)
    if agent:
        try:
            _persist_audit(
                agent, upload_name, contents, csv_contents, issue_records,
                time.monotonic() - started_at,
            )
        except Exception:
            return JSONResponse(
                status_code=503,
                content={"error_type": "general", "error": "No fue posible guardar la auditoría."},
            )
    return JSONResponse(
        content={"csv_base64": csv_base64, "sku_changes": sku_changes}
    )
