"""Explicit, non-destructive provisioning for one dbo.Usuarios account."""

import argparse
import getpass
import sys

from database import database_connection, make_password_hash


def provision(username, email, full_name, role, password):
    username = username.strip()
    email = email.strip()
    full_name = full_name.strip()
    if (
        not username
        or len(username) > 50
        or not email
        or len(email) > 100
        or not full_name
        or len(full_name) > 100
        or role not in {"Agente", "Supervisor"}
    ):
        raise ValueError("Los datos del usuario no cumplen los límites del esquema.")

    password_hash = make_password_hash(password)
    with database_connection() as connection:
        cursor = connection.cursor()
        existing = cursor.execute(
            """
            SELECT TOP (1) ID_Usuario
            FROM dbo.Usuarios WITH (UPDLOCK, HOLDLOCK)
            WHERE Nombre_Usuario = ? OR Email = ?
            """,
            username,
            email,
        ).fetchone()
        if existing:
            raise ValueError("Ya existe una cuenta con ese usuario o correo.")

        user_id = cursor.execute(
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
        ).fetchone()[0]

        if role == "Agente":
            cursor.execute(
                """
                INSERT INTO dbo.Agentes
                    (ID_Usuario, Email_Corporativo, Nombre_Completo,
                     Fecha_Ingreso, Estado)
                VALUES (?, ?, ?, GETDATE(), 1)
                """,
                user_id,
                email,
                full_name,
            )
        else:
            cursor.execute(
                """
                INSERT INTO dbo.Supervisores
                    (ID_Usuario, Email_Corporativo, Nombre_Completo,
                     Fecha_Ingreso, Estado)
                VALUES (?, ?, ?, GETDATE(), 1)
                """,
                user_id,
                email,
                full_name,
            )


def main():
    parser = argparse.ArgumentParser(
        description="Crea explícitamente un usuario y su registro de rol en SQL Server."
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    parser.add_argument("--full-name", required=True)
    parser.add_argument("--role", choices=("Agente", "Supervisor"), required=True)
    args = parser.parse_args()

    password = getpass.getpass("Contraseña nueva: ")
    confirmation = getpass.getpass("Confirme la contraseña: ")
    if not password or password != confirmation:
        print("No se pudo validar la contraseña.", file=sys.stderr)
        return 2
    try:
        provision(
            args.username, args.email, args.full_name, args.role, password
        )
    except Exception:
        print(
            "No se pudo crear el usuario. Verifique la conexión y que los datos no existan.",
            file=sys.stderr,
        )
        return 1
    print("Usuario creado correctamente.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
