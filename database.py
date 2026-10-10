"""SQL Server connection and password-hash helpers for the Peya Tools backend."""

import base64
import hashlib
import hmac
import os
import re
import secrets
from contextlib import contextmanager

import pyodbc


PASSWORD_HASH_ITERATIONS = 600_000
PASSWORD_HASH_PREFIX = f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}$"
_HASH_RE = re.compile(
    rf"^{re.escape(PASSWORD_HASH_PREFIX)}([A-Za-z0-9_-]{{22}})\$([A-Za-z0-9_-]{{43}})$"
)


def _is_true(value):
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def connection_string():
    server = os.getenv("SQLSERVER_SERVER", "localhost").strip()
    database = os.getenv("SQLSERVER_DATABASE", "AuditoriaDatos").strip()
    driver = os.getenv("SQLSERVER_DRIVER", "ODBC Driver 18 for SQL Server").strip()
    # The locally verified SQL Server has an untrusted local certificate. Only
    # loopback defaults to trusting it; remote servers must present a trusted cert.
    local_server = server.lower() in {"localhost", "127.0.0.1", "."}
    trust_default = "yes" if local_server else "no"
    trust_certificate = os.getenv(
        "SQLSERVER_TRUST_SERVER_CERTIFICATE", trust_default
    ).strip().lower()
    if trust_certificate not in {"yes", "no", "true", "false", "1", "0"}:
        raise ValueError("Configuración SQL Server inválida.")
    trust_certificate = "yes" if _is_true(trust_certificate) else "no"
    if not server or not database or not driver or any(
        character in value for value in (server, database, driver) for character in ";{}"
    ):
        raise ValueError("Configuración SQL Server inválida.")
    return (
        f"DRIVER={{{driver}}};SERVER={server};DATABASE={database};"
        "Trusted_Connection=yes;Encrypt=yes;"
        f"TrustServerCertificate={trust_certificate};"
    )


@contextmanager
def database_connection():
    connection = pyodbc.connect(connection_string(), timeout=5)
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _b64url_encode(value):
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64url_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def make_password_hash(password):
    if not isinstance(password, str) or not password or len(password) > 1024:
        raise ValueError("La contraseña no es válida.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS, dklen=32
    )
    return f"{PASSWORD_HASH_PREFIX}{_b64url_encode(salt)}${_b64url_encode(digest)}"


def verify_password(password, encoded_hash):
    if not isinstance(password, str) or not isinstance(encoded_hash, str):
        return False
    match = _HASH_RE.fullmatch(encoded_hash)
    if not match:
        return False
    try:
        salt = _b64url_decode(match.group(1))
        expected = _b64url_decode(match.group(2))
    except (ValueError, TypeError):
        return False
    if len(salt) != 16 or len(expected) != 32:
        return False
    if _b64url_encode(salt) != match.group(1) or _b64url_encode(expected) != match.group(2):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_HASH_ITERATIONS, dklen=32
    )
    return hmac.compare_digest(actual, expected)


def verify_password_or_legacy(password, stored_value):
    """Verify a current PBKDF2 hash or exact legacy plaintext without logging it.

    A successful legacy comparison is reported separately so the caller can
    replace the stored value with a fresh hash in its existing transaction.
    Hash-looking but malformed values are never accepted as plaintext.
    """
    if not isinstance(password, str) or not isinstance(stored_value, str):
        return False, False
    if verify_password(password, stored_value):
        return True, False
    if stored_value.casefold().startswith(("pbkdf2_", "pbkdf2$")):
        return False, False
    try:
        matches = hmac.compare_digest(
            password.encode("utf-8"), stored_value.encode("utf-8")
        )
    except UnicodeError:
        return False, False
    return matches, matches
