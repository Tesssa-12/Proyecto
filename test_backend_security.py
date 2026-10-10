import asyncio
import base64
import contextlib
import io
import os
import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd
from fastapi import HTTPException
from fastapi.testclient import TestClient
from PIL import Image
from openpyxl import Workbook

import main
import server
from database import (
    PASSWORD_HASH_PREFIX,
    make_password_hash,
    verify_password,
    verify_password_or_legacy,
)
from database import connection_string


class PasswordHashTests(unittest.TestCase):
    def test_generated_hash_matches_strict_format_and_verifies(self):
        encoded = make_password_hash("test-only-password")
        self.assertTrue(encoded.startswith(PASSWORD_HASH_PREFIX))
        self.assertTrue(verify_password("test-only-password", encoded))
        self.assertFalse(verify_password("not-the-password", encoded))

    def test_noncanonical_or_other_hash_format_is_rejected(self):
        self.assertFalse(verify_password("password", "sha256$invalid"))
        encoded = make_password_hash("test-only-password")
        parts = encoded.split("$")
        parts[2] = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
        self.assertFalse(verify_password("test-only-password", "$".join(parts)))

    def test_legacy_value_requires_exact_match_and_is_marked_for_migration(self):
        self.assertEqual(
            verify_password_or_legacy("legacy-exact", "legacy-exact"),
            (True, True),
        )
        self.assertEqual(
            verify_password_or_legacy("legacy-exact ", "legacy-exact"),
            (False, False),
        )
        self.assertEqual(
            verify_password_or_legacy(
                "password", "pbkdf2_sha256$malformed"
            ),
            (False, False),
        )


class SqlConnectionConfigurationTests(unittest.TestCase):
    def test_local_defaults_encrypt_and_trust_loopback_certificate(self):
        with patch.dict(os.environ, {}, clear=True):
            result = connection_string()
        self.assertIn("SERVER=localhost;", result)
        self.assertIn("DATABASE=AuditoriaDatos;", result)
        self.assertIn("Trusted_Connection=yes;", result)
        self.assertIn("Encrypt=yes;", result)
        self.assertIn("TrustServerCertificate=yes;", result)

    def test_certificate_trust_is_configurable_and_remote_default_is_no(self):
        with patch.dict(
            os.environ,
            {
                "SQLSERVER_SERVER": "db.example.invalid",
                "SQLSERVER_TRUST_SERVER_CERTIFICATE": "yes",
            },
            clear=True,
        ):
            explicitly_trusting = connection_string()
        self.assertIn("TrustServerCertificate=yes;", explicitly_trusting)
        with patch.dict(
            os.environ,
            {"SQLSERVER_SERVER": "db.example.invalid"},
            clear=True,
        ):
            remote_default = connection_string()
        self.assertIn("TrustServerCertificate=no;", remote_default)
        self.assertIn("Encrypt=yes;", remote_default)


class SessionTokenTests(unittest.TestCase):
    def test_token_is_signed_and_tampering_is_rejected(self):
        with patch.dict(os.environ, {"SESSION_SECRET": "x" * 48}):
            token = server._create_session_token(23, 4_000_000_000)
            self.assertEqual(server._read_session_token(token), (23, 4_000_000_000))
            self.assertIsNone(server._read_session_token(token + "x"))

    def test_login_requires_configured_session_secret(self):
        with patch.dict(os.environ, {}, clear=True):
            response = TestClient(server.app).post(
                "/api/auth/login",
                json={"username": "nobody", "password": "not-a-real-password"},
            )
        self.assertEqual(response.status_code, 503)


class LegacyLoginMigrationTests(unittest.TestCase):
    class LoginCursor:
        def __init__(self, stored_value, update_rowcount=1):
            self.stored_value = stored_value
            self.update_rowcount = update_rowcount
            self.rowcount = -1
            self.calls = []

        def execute(self, sql, *params):
            self.calls.append((sql, params))
            if "UPDATE dbo.Usuarios" in sql:
                self.rowcount = self.update_rowcount
            return self

        def fetchall(self):
            return [
                SimpleNamespace(
                    ID_Usuario=23,
                    Nombre_Usuario="legacy-agent",
                    Email="agent@example.invalid",
                    Rol="Agente",
                    ID_Agente=45,
                    ID_Supervisor=None,
                    __getitem__=None,
                )
            ]

        def fetchone(self):
            return (88,)

    class Row:
        ID_Usuario = 23
        Nombre_Usuario = "legacy-agent"
        Email = "agent@example.invalid"
        Rol = "Agente"
        ID_Agente = 45
        ID_Supervisor = None

        def __getitem__(self, index):
            return "legacy-exact" if index == 4 else None

    class HashRow(Row):
        def __getitem__(self, index):
            return self.stored_value if index == 4 else None

        def __init__(self, stored_value):
            self.stored_value = stored_value

    class StatefulCursor:
        def __init__(self, row, update_rowcount=1):
            self.row = row
            self.update_rowcount = update_rowcount
            self.rowcount = -1
            self.calls = []
            self.current_sql = ""
            self.failed_attempts = 0
            self.lock_seconds = 0

        def execute(self, sql, *params):
            self.current_sql = sql
            self.calls.append((sql, params))
            if "UPDATE dbo.Usuarios" in sql:
                self.rowcount = self.update_rowcount
            elif "UPDATE dbo.Intentos_Acceso" in sql:
                if "SET Intentos_Fallidos = 3" in sql:
                    self.failed_attempts = 3
                    self.lock_seconds = 24 * 60 * 60
                elif "SET Intentos_Fallidos = ?" in sql:
                    self.failed_attempts = int(params[0])
                    self.lock_seconds = 0
                elif "SET Intentos_Fallidos = 0" in sql:
                    self.failed_attempts = 0
                    self.lock_seconds = 0
            return self

        def fetchall(self):
            return [self.row]

        def fetchone(self):
            if "SELECT Intentos_Fallidos" in self.current_sql:
                locked_until = datetime(2099, 1, 1) if self.lock_seconds else None
                return (self.failed_attempts, locked_until, self.lock_seconds)
            return (88,)

    class LoginConnection:
        def __init__(self, cursor):
            self.fake_cursor = cursor

        def cursor(self):
            return self.fake_cursor

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    @contextlib.contextmanager
    def fake_database(self, cursor):
        yield self.LoginConnection(cursor)

    def tearDown(self):
        server.app.dependency_overrides.clear()

    @patch.dict(os.environ, {"SESSION_SECRET": "test-session-secret-" * 3})
    def test_successful_legacy_login_migrates_in_transaction_before_session(self):
        cursor = self.StatefulCursor(self.Row())
        connection = self.LoginConnection(cursor)
        client = TestClient(server.app)
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = client.post(
                "/api/auth/login",
                json={"username": "legacy-agent", "password": "legacy-exact"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "user": {
                    "id": 23,
                    "username": "legacy-agent",
                    "email": "agent@example.invalid",
                    "role": "Agente",
                }
            },
        )
        update_calls = [
            call for call in cursor.calls if "UPDATE dbo.Usuarios" in call[0]
        ]
        self.assertEqual(len(update_calls), 1)
        new_hash = update_calls[0][1][0]
        self.assertTrue(verify_password("legacy-exact", new_hash))
        self.assertNotIn("legacy-exact", response.text)
        self.assertTrue(
            any("INSERT INTO dbo.Historial_Sesiones" in call[0] for call in cursor.calls)
        )
        self.assertLess(
            next(i for i, call in enumerate(cursor.calls) if "UPDATE dbo.Usuarios" in call[0]),
            next(i for i, call in enumerate(cursor.calls) if "INSERT INTO dbo.Historial_Sesiones" in call[0]),
        )

    @patch.dict(os.environ, {"SESSION_SECRET": "test-session-secret-" * 3})
    def test_wrong_legacy_password_is_not_migrated_or_logged_in(self):
        cursor = self.StatefulCursor(self.Row())
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/auth/login",
                json={"username": "legacy-agent", "password": "wrong-password"},
            )
        self.assertEqual(response.status_code, 401)
        self.assertFalse(any("UPDATE dbo.Usuarios" in call[0] for call in cursor.calls))
        self.assertFalse(any("INSERT INTO dbo.Historial_Sesiones" in call[0] for call in cursor.calls))

    @patch.dict(os.environ, {"SESSION_SECRET": "test-session-secret-" * 3})
    def test_existing_pbkdf2_login_does_not_rewrite_hash(self):
        current_hash = make_password_hash("current-password")
        cursor = self.StatefulCursor(self.HashRow(current_hash))
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/auth/login",
                json={"username": "legacy-agent", "password": "current-password"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(any("UPDATE dbo.Usuarios" in call[0] for call in cursor.calls))

    @patch.dict(os.environ, {"SESSION_SECRET": "test-session-secret-" * 3})
    def test_login_reports_three_tries_then_locks_for_24_hours(self):
        current_hash = make_password_hash("right-password")
        cursor = self.StatefulCursor(self.HashRow(current_hash))
        client = TestClient(server.app)
        responses = []
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            for _ in range(3):
                responses.append(
                    client.post(
                        "/api/auth/login",
                        json={"username": "legacy-agent", "password": "wrong-password"},
                    )
                )
            locked_correct_password = client.post(
                "/api/auth/login",
                json={"username": "legacy-agent", "password": "right-password"},
            )

        self.assertEqual(responses[0].status_code, 401)
        self.assertEqual(
            responses[0].json()["detail"],
            "Contraseña incorrecta te quedan 3 intentos",
        )
        self.assertEqual(
            responses[1].json()["detail"],
            "Contraseña incorrecta te quedan 2 intentos",
        )
        self.assertEqual(responses[2].status_code, 423)
        self.assertIn("bloqueada durante 24 horas", responses[2].json()["detail"])
        self.assertEqual(locked_correct_password.status_code, 423)
        self.assertEqual(cursor.failed_attempts, 3)
        self.assertEqual(cursor.lock_seconds, 24 * 60 * 60)
        self.assertFalse(
            any("INSERT INTO dbo.Historial_Sesiones" in call[0] for call in cursor.calls)
        )

    @patch.dict(os.environ, {"SESSION_SECRET": "test-session-secret-" * 3})
    def test_successful_login_clears_previous_failed_attempts(self):
        current_hash = make_password_hash("right-password")
        cursor = self.StatefulCursor(self.HashRow(current_hash))
        cursor.failed_attempts = 2
        client = TestClient(server.app)
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = client.post(
                "/api/auth/login",
                json={"username": "legacy-agent", "password": "right-password"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(cursor.failed_attempts, 0)
        self.assertTrue(
            any(
                "UPDATE dbo.Intentos_Acceso" in call[0]
                and "Intentos_Fallidos = 0" in call[0]
                for call in cursor.calls
            )
        )


class AuthorizationTests(unittest.TestCase):
    def test_supervisor_listing_requires_session(self):
        response = TestClient(server.app).get("/api/sugerencias")
        self.assertEqual(response.status_code, 401)

    def test_same_origin_static_files_are_served(self):
        client = TestClient(server.app)
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.get("/styles.css").status_code, 200)

    def test_session_response_uses_nested_user_contract(self):
        server.app.dependency_overrides[server.require_session] = lambda: {
            "user_id": 17,
            "username": "test-agent",
            "email": "agent@example.invalid",
            "role": "Agente",
            "agent_id": 42,
        }
        try:
            response = TestClient(server.app).get("/api/auth/session")
        finally:
            server.app.dependency_overrides.clear()
        self.assertEqual(
            response.json(),
            {
                "user": {
                    "id": 17,
                    "username": "test-agent",
                    "email": "agent@example.invalid",
                    "role": "Agente",
                }
            },
        )

    def test_suggestion_routes_require_agent_or_supervisor_session(self):
        client = TestClient(server.app)
        self.assertEqual(
            client.get("/api/suggestions").status_code,
            401,
        )
        self.assertEqual(
            client.post(
                "/api/suggestions",
                data={"title": "test", "detail": "test"},
            ).status_code,
            401,
        )

    def test_conversion_and_dashboard_endpoints_require_authentication(self):
        client = TestClient(server.app)
        self.assertEqual(client.post("/api/conversions").status_code, 401)
        self.assertEqual(client.get("/api/dashboard/errors").status_code, 401)

    def test_user_management_endpoints_require_supervisor(self):
        client = TestClient(server.app)
        self.assertEqual(client.get("/api/users").status_code, 401)
        self.assertEqual(
            client.post(
                "/api/users",
                json={
                    "username": "example",
                    "email": "example@example.invalid",
                    "full_name": "Example User",
                    "role": "Agente",
                    "password": "example-long-password",
                    "department": "",
                },
            ).status_code,
            401,
        )
        self.assertEqual(
            client.post(
                "/api/users/1/password",
                json={"password": "example-long-password"},
            ).status_code,
            401,
        )


class PersistenceRouteTests(unittest.TestCase):
    class FakeCursor:
        def __init__(self, fetch_one=None, fetch_all=None, fetch_one_results=None, rowcount=1):
            self.fetch_one = fetch_one or (991,)
            self.fetch_all = fetch_all or []
            self.fetch_one_results = list(fetch_one_results or [])
            self.sql = ""
            self.params = ()
            self.statements = []
            self.rowcount = rowcount

        def execute(self, sql, *params):
            self.sql = sql
            self.params = params
            self.statements.append((sql, params))
            if self.fetch_one_results:
                self.fetch_one = self.fetch_one_results.pop(0)
            return self

        def fetchone(self):
            return self.fetch_one

        def fetchall(self):
            return self.fetch_all

    class FakeConnection:
        def __init__(self, cursor):
            self.fake_cursor = cursor

        def cursor(self):
            return self.fake_cursor

        def commit(self):
            pass

        def rollback(self):
            pass

        def close(self):
            pass

    @contextlib.contextmanager
    def fake_database(self, cursor):
        yield self.FakeConnection(cursor)

    def tearDown(self):
        server.app.dependency_overrides.clear()

    @staticmethod
    def xlsx_bytes():
        workbook = Workbook()
        workbook.active["A1"] = "value"
        buffer = io.BytesIO()
        workbook.save(buffer)
        return buffer.getvalue()

    def test_conversion_endpoint_stores_blobs_and_names_for_agent(self):
        original_bytes = b"sku;name\n1;item\n"
        converted_bytes = self.xlsx_bytes()
        cursor = self.FakeCursor()
        server.app.dependency_overrides[server.require_agent] = lambda: {
            "agent_id": 44,
            "user_id": 9,
            "username": "agent-test",
            "email": "agent@example.invalid",
            "role": "Agente",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/conversions",
                files={
                    "original": ("source.csv", original_bytes, "text/csv"),
                    "converted": (
                        "converted.xlsx",
                        converted_bytes,
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ),
                },
                data={
                    "original_name": "source.csv",
                    "converted_name": "converted.xlsx",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"id": 991})
        self.assertIn("INSERT INTO dbo.Conversion_CSV_XLSX", cursor.sql)
        self.assertEqual(cursor.params[0:2], (44, "source.csv"))
        self.assertEqual(cursor.params[2:5], (original_bytes, "converted.xlsx", converted_bytes))

    def test_suggestion_create_returns_canonical_item_shape(self):
        suggestion_date = datetime(2026, 10, 8, 12, 30)
        cursor = self.FakeCursor(fetch_one=(771, suggestion_date))
        agent = {
            "agent_id": 44,
            "user_id": 9,
            "username": "agent-test",
            "email": "agent@example.invalid",
            "role": "Agente",
        }
        server.app.dependency_overrides[server.require_agent] = lambda: agent
        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), color="white").save(image_buffer, format="PNG")
        image_bytes = image_buffer.getvalue()
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/suggestions",
                data={"title": "Suggestion", "detail": "Details"},
                files={"image": ("capture.png", image_bytes, "image/png")},
            )
        expected = {
            "id": 771,
            "date": "2026-10-08T12:30:00",
            "email": "agent@example.invalid",
            "title": "Suggestion",
            "detail": "Details",
            "has_image": True,
        }
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)
        self.assertIn("INSERT INTO dbo.Sugerencias", cursor.sql)

    def test_suggestion_list_uses_same_canonical_item_shape(self):
        suggestion_date = datetime(2026, 10, 8, 12, 30)

        class SuggestionRow:
            ID_Sugerencia = 771
            Email_Agente = "agent@example.invalid"
            Titulo_Reporte = "Suggestion"
            Detalle_Explicativo = "Details"

            def __getitem__(self, index):
                if index == 5:
                    return 1
                raise IndexError(index)

        SuggestionRow.Fecha_Hora = suggestion_date
        cursor = self.FakeCursor(fetch_all=[SuggestionRow()])
        server.app.dependency_overrides[server.require_supervisor] = lambda: {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).get("/api/suggestions")
        item = response.json()["suggestions"][0]
        self.assertEqual(
            item,
            {
                "id": 771,
                "date": "2026-10-08T12:30:00",
                "email": "agent@example.invalid",
                "title": "Suggestion",
                "detail": "Details",
                "has_image": True,
            },
        )

    def test_suggestion_image_is_supervisor_only_and_returns_image_mime(self):
        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), color="white").save(image_buffer, format="PNG")
        image_bytes = image_buffer.getvalue()
        cursor = self.FakeCursor(fetch_one=(image_bytes,))
        client = TestClient(server.app)
        self.assertEqual(client.get("/api/suggestions/771/image").status_code, 401)
        supervisor = {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        server.app.dependency_overrides[server.require_supervisor] = lambda: supervisor
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = client.get("/api/suggestions/771/image")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "image/png")
        self.assertEqual(response.content, image_bytes)

    def test_users_list_contains_no_password_data(self):
        row = SimpleNamespace(
            ID_Usuario=34,
            Nombre_Usuario="agent-test",
            Email="agent@example.invalid",
            Rol="Agente",
        )

        class UserRow(SimpleNamespace):
            def __getitem__(self, index):
                return ("Full Name", "Operations")[index - 4]

        row = UserRow(**vars(row))
        cursor = self.FakeCursor(fetch_all=[row])
        server.app.dependency_overrides[server.require_supervisor] = lambda: {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).get("/api/users")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "users": [
                    {
                        "id": 34,
                        "username": "agent-test",
                        "email": "agent@example.invalid",
                        "role": "Agente",
                        "full_name": "Full Name",
                        "department": "Operations",
                    }
                ]
            },
        )
        self.assertNotIn("password", response.text.lower())
        self.assertNotIn("hash", response.text.lower())

    def test_user_create_hashes_password_and_returns_only_profile_fields(self):
        cursor = self.FakeCursor(fetch_one_results=[None, (314,)])
        server.app.dependency_overrides[server.require_supervisor] = lambda: {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/users",
                json={
                    "username": "new-agent",
                    "email": "new-agent@example.invalid",
                    "full_name": "New Agent",
                    "role": "Agente",
                    "password": "long-test-password",
                    "department": "Operations",
                },
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "user": {
                    "id": 314,
                    "username": "new-agent",
                    "email": "new-agent@example.invalid",
                    "role": "Agente",
                    "full_name": "New Agent",
                    "department": "Operations",
                }
            },
        )
        stored_hash = cursor.statements[1][1][2]
        self.assertTrue(stored_hash.startswith(PASSWORD_HASH_PREFIX))
        self.assertTrue(verify_password("long-test-password", stored_hash))
        self.assertNotIn("long-test-password", response.text)

    def test_password_update_stores_hash_not_cleartext(self):
        cursor = self.FakeCursor(rowcount=1)
        server.app.dependency_overrides[server.require_supervisor] = lambda: {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/users/314/password",
                json={"password": "new-long-password"},
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Contraseña actualizada."})
        password_update = next(
            params
            for sql, params in cursor.statements
            if "UPDATE dbo.Usuarios" in sql
        )
        stored_hash = password_update[0]
        self.assertTrue(verify_password("new-long-password", stored_hash))
        self.assertTrue(
            any(
                "DELETE FROM dbo.Intentos_Acceso" in sql
                for sql, _ in cursor.statements
            )
        )
        self.assertNotIn("new-long-password", response.text)

    def test_conversion_rejects_invalid_xlsx(self):
        server.app.dependency_overrides[server.require_agent] = lambda: {
            "agent_id": 44,
            "user_id": 9,
            "username": "agent-test",
            "email": "agent@example.invalid",
            "role": "Agente",
        }
        response = TestClient(server.app).post(
            "/api/conversions",
            files={
                "original": ("source.csv", b"a,b\n", "text/csv"),
                "converted": ("converted.xlsx", b"not-a-zip", "application/octet-stream"),
            },
            data={
                "original_name": "source.csv",
                "converted_name": "converted.xlsx",
            },
        )
        self.assertEqual(response.status_code, 400)

    def test_conversion_download_marks_only_agents_own_conversion(self):
        cursor = self.FakeCursor(rowcount=1)
        server.app.dependency_overrides[server.require_agent] = lambda: {
            "agent_id": 44,
            "user_id": 9,
            "username": "agent-test",
            "email": "agent@example.invalid",
            "role": "Agente",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/conversions/991/downloaded"
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"message": "Descarga registrada."})
        self.assertIn("SET Fecha_Descarga = GETDATE()", cursor.sql)
        self.assertIn("ID_Conversion = ? AND ID_Agente = ?", cursor.sql)
        self.assertEqual(cursor.params, (991, 44))

    def test_conversion_download_returns_404_for_other_agents_conversion(self):
        cursor = self.FakeCursor(rowcount=0)
        server.app.dependency_overrides[server.require_agent] = lambda: {
            "agent_id": 44,
            "user_id": 9,
            "username": "agent-test",
            "email": "agent@example.invalid",
            "role": "Agente",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).post(
                "/api/conversions/991/downloaded"
            )
        self.assertEqual(response.status_code, 404)

    def test_dashboard_errors_returns_existing_schema_fields_for_supervisor(self):
        row = SimpleNamespace(
            ID_Dashboard=3,
            ID_Codificacion=8,
            ID_Agente=44,
            Archivo_Original="audit.xlsx",
            Numero_Fila=2,
            Tipo_Error="Precio faltante",
            Descripcion_Tecnica="Precio faltante.",
            Email_Agente="agent@example.invalid",
            Fecha_Hora=None,
            Estado_Error="Pendiente",
            Fecha_Resolucion=None,
        )
        cursor = self.FakeCursor(fetch_all=[row])
        server.app.dependency_overrides[server.require_supervisor] = lambda: {
            "supervisor_id": 12,
            "user_id": 11,
            "username": "supervisor-test",
            "email": "supervisor@example.invalid",
            "role": "Supervisor",
        }
        with patch(
            "server.database_connection",
            side_effect=lambda: self.fake_database(cursor),
        ):
            response = TestClient(server.app).get("/api/dashboard/errors")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "errors": [
                    {
                        "id": 3,
                        "codification_id": 8,
                        "agent_id": 44,
                        "file_name": "audit.xlsx",
                        "row": 2,
                        "type": "Precio faltante",
                        "description": "Precio faltante.",
                        "agent_email": "agent@example.invalid",
                        "date": None,
                        "status": "Pendiente",
                        "resolved_at": None,
                    }
                ]
            },
        )


class ImageValidationTests(unittest.TestCase):
    def test_valid_png_is_accepted_and_mime_spoof_is_rejected(self):
        image_buffer = io.BytesIO()
        Image.new("RGB", (2, 2), color="white").save(image_buffer, format="PNG")
        png = image_buffer.getvalue()
        self.assertTrue(server._validate_image(png, "image/png"))
        self.assertFalse(server._validate_image(png, "image/jpeg"))
        self.assertFalse(
            server._validate_image(b"\x89PNG\r\n\x1a\nnot-an-image", "image/png")
        )

    def test_upload_size_is_limited_before_image_decoding(self):
        class FakeUpload:
            filename = "large.png"
            content_type = "image/png"

            def __init__(self):
                self.content = (
                    b"\x89PNG\r\n\x1a\n"
                    + b"x" * server.MAX_IMAGE_BYTES
                )
                self.offset = 0

            async def read(self, size):
                chunk = self.content[self.offset:self.offset + size]
                self.offset += len(chunk)
                return chunk

        with self.assertRaises(HTTPException) as raised:
            asyncio.run(server._read_valid_image(FakeUpload()))
        self.assertEqual(raised.exception.status_code, 413)


class AuditContractTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(server.app)

    @staticmethod
    def excel_bytes(dataframe):
        buffer = io.BytesIO()
        dataframe.to_excel(buffer, index=False)
        return buffer.getvalue()

    def test_audit_csv_and_sku_response_contract_without_session(self):
        content = self.excel_bytes(
            pd.DataFrame(
                {
                    "Nombre": ["item1", "item2"],
                    "SKU": ["DUP", "DUP"],
                    "Precio": [1, 2],
                    "ID": [9, 10],
                }
            )
        )
        response = self.client.post(
            "/api/auditar-productos",
            files={"file": ("sample.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(set(result), {"csv_base64", "sku_changes"})
        self.assertEqual(result["sku_changes"][0]["name"], "")
        self.assertEqual(result["sku_changes"][0]["row"], 3)
        exported = base64.b64decode(result["csv_base64"])
        self.assertTrue(exported.startswith(b"\xef\xbb\xbf"))
        self.assertNotIn(b"ID", exported)
        self.assertNotIn(b"Nombre;", exported)

    def test_validation_response_does_not_echo_product_names(self):
        content = self.excel_bytes(
            pd.DataFrame({"Nombre": ["private-item"], "Precio": [None], "SKU": ["x"]})
        )
        response = self.client.post(
            "/api/auditar-productos",
            files={"file": ("sample.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        )
        self.assertEqual(response.status_code, 400)
        result = response.json()
        self.assertEqual(result["error_type"], "price")
        self.assertEqual(result["items"], [{"name": "", "row": 2}])
        self.assertNotIn("private-item", response.text)


class LocalAuditAiConfigurationTests(unittest.TestCase):
    def test_import_and_startup_do_not_require_google_api_key(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNotNone(main.app)

    def test_inconsistent_local_audit_without_key_reports_actionable_error(self):
        dataframe = pd.DataFrame(
            {"Nombre": ["item"], "SKU": ["sku"], "Precio": [None]}
        )
        output = io.StringIO()
        with patch.dict(os.environ, {}, clear=True), patch(
            "main.pd.read_excel", return_value=dataframe
        ), patch("sys.stdout", new=output):
            result = main.procesar_archivo_productos("test-only.xlsx")
        self.assertFalse(result)
        self.assertIn("GOOGLE_API_KEY", output.getvalue())
        self.assertIn("Configure la variable de entorno", output.getvalue())

    def test_configured_key_keeps_ai_diagnostic_path_active(self):
        dataframe = pd.DataFrame(
            {"Nombre": ["item"], "SKU": ["sku"], "Precio": [None]}
        )

        class FakeModels:
            called = False

            def generate_content(self, **kwargs):
                self.called = True
                return SimpleNamespace(text="diagnóstico de prueba")

        fake_models = FakeModels()
        fake_client = SimpleNamespace(models=fake_models)
        output = io.StringIO()
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-only-key"}), patch(
            "main.pd.read_excel", return_value=dataframe
        ), patch("main.genai.Client", return_value=fake_client), patch(
            "sys.stdout", new=output
        ):
            result = main.procesar_archivo_productos("test-only.xlsx")
        self.assertFalse(result)
        self.assertTrue(fake_models.called)
        self.assertIn("diagnóstico de prueba", output.getvalue())


if __name__ == "__main__":
    unittest.main()
