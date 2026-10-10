# Peya Tools: backend SQL Server

## Backend actual

El código FastAPI está en `server.py` y se exporta como `app` desde `main.py`
(`uvicorn main:app` o `uvicorn server:app`). `http://localhost:8000/` sirve
`index.html` y `/styles.css` sirve la hoja local, de modo que el cliente puede
usar cookies y rutas API same-origin. El procesador local original de `main.py`
solo se ejecuta al invocar directamente `python main.py`. El backend usa las
tablas existentes de `AuditoriaDatos`; el único agregado de esquema es la tabla
`dbo.Intentos_Acceso` para persistir bloqueos, y no crea usuarios automáticamente.

## Configuración

Se usa autenticación integrada de Windows (`Trusted_Connection=yes`), sin usuario
ni contraseña SQL:

| Variable | Valor predeterminado | Descripción |
| --- | --- | --- |
| `SQLSERVER_SERVER` | `localhost` | Instancia local verificada en el entorno actual |
| `SQLSERVER_DATABASE` | `AuditoriaDatos` | Base de datos |
| `SQLSERVER_DRIVER` | `ODBC Driver 18 for SQL Server` | Controlador instalado en el entorno actual |
| `SESSION_SECRET` | **obligatoria** para autenticar | Secreto aleatorio de al menos 32 bytes |
| `SESSION_COOKIE_SECURE` | `false` | Use `true` únicamente al servir por HTTPS |
| `SQLSERVER_TRUST_SERVER_CERTIFICATE` | `yes` para `localhost`, `127.0.0.1` y `.`; `no` para otros servidores | Configurable explícitamente con `yes`/`no`; el transporte siempre usa `Encrypt=yes` |
| `CORS_ORIGINS` | `http://localhost:8000,http://127.0.0.1:8000` | Orígenes del cliente web separados por coma |
| `GOOGLE_API_KEY` | sin valor | Opcional para iniciar; habilita los diagnósticos de IA en backend y `python main.py` |

En PowerShell, inicia la aplicación desde la carpeta del proyecto:

```powershell
.\start_app.ps1
```

El script usa el entorno `.venv` del proyecto y genera una clave aleatoria de
sesión para ese proceso. Mantén abierta la ventana y visita
`http://127.0.0.1:8000/`; no abras `index.html` directamente ni inicies Uvicorn
sin `SESSION_SECRET`. Al reiniciar, las sesiones existentes expirarán y se debe
iniciar sesión de nuevo. Para producción usa una clave estable y protegida, HTTPS
y `SESSION_COOKIE_SECURE=true`.

La aplicación puede iniciar sin `GOOGLE_API_KEY`. El procesador local `python
main.py` lo requiere cuando un archivo presenta inconsistencias y se solicita el
diagnóstico de IA; si falta, informa que debe configurarse esa variable y no
continúa con la generación del diagnóstico. Los endpoints de auditoría de la API
conservan su respuesta de diagnóstico estático cuando la variable no está
configurada o la llamada externa falla. No incluya la clave en el código ni en
el repositorio.

La autenticación integrada depende de la cuenta de Windows que ejecuta Uvicorn y
de sus permisos en SQL Server. El valor predeterminado local usa
`SQLSERVER_SERVER=localhost` y confía en el certificado autofirmado local
(`SQLSERVER_TRUST_SERVER_CERTIFICATE=yes`) con cifrado habilitado. La opción es
configurable; para un servidor remoto, configure un nombre de instancia
verificado, use un certificado confiable y mantenga
`SQLSERVER_TRUST_SERVER_CERTIFICATE=no`.

## Dependencias

```powershell
python -m pip install -r requirements.txt
```

## Cuentas y hashes de contraseña

El hash de contraseña tiene un formato estricto, sin formatos alternativos:

```text
pbkdf2_sha256$600000$<salt-base64url-sin-padding-de-16-bytes>$<digest-base64url-sin-padding-de-32-bytes>
```

El digest es PBKDF2-HMAC-SHA256 con exactamente 600.000 iteraciones. La sal se
genera aleatoriamente por contraseña. El backend rechaza hashes que no respeten
el prefijo, las iteraciones, la codificación canónica o las longitudes indicadas.
No almacene contraseñas en texto plano.

Para permitir el primer acceso de las cuentas ya insertadas con contraseña en
texto plano, el login compara exactamente el valor heredado y, si coincide,
lo sustituye por un hash PBKDF2 dentro de la transacción antes de abrir la
sesión. Un valor que parezca un hash pero no cumpla el formato estricto no se
acepta como texto plano. Las cuentas existentes no se reescriben hasta un
inicio de sesión correcto.

Para crear explícitamente un usuario, el provisionador solicita la contraseña
sin mostrarla, calcula este hash y, dentro de una transacción, crea `Usuarios` y
su registro correspondiente en `Agentes` o `Supervisores`. No modifica cuentas
existentes ni inicializa cuentas al arrancar:

```powershell
python provision_user.py --username USUARIO --email CORREO --full-name "Nombre Apellido" --role Agente
```

`--role` admite `Agente` o `Supervisor`. El provisionador solo guarda el hash; la
contraseña no se pasa como argumento ni se imprime.

## API

- `POST /api/auth/login`: JSON `{"username":"…","password":"…"}`; inicia un
  registro en `Historial_Sesiones`, establece una cookie `HttpOnly` firmada y
  devuelve `{"user":{"id":1,"username":"…","email":"…","role":"Agente"}}`.
  Una contraseña incorrecta devuelve el número de intentos restantes; al tercer
  fallo consecutivo bloquea esa cuenta durante 24 horas. Una contraseña correcta
  limpia el contador. Un supervisor puede quitar el bloqueo al actualizar la
  contraseña desde Credenciales.
- `GET /api/auth/session`: devuelve el mismo objeto `user`; sin sesión válida
  responde `401 {"detail":"Autenticación requerida."}`.
- `POST /api/auth/logout`: requiere sesión válida, cierra `Historial_Sesiones`,
  elimina la cookie y devuelve `{"message":"Sesión cerrada."}`.
- `GET /api/users`: solo supervisores; devuelve `{"users":[...]}` con `id`,
  `username`, `email`, `role`, `full_name` y `department`; nunca devuelve hashes
  ni contraseñas.
- `POST /api/users`: solo supervisores; acepta JSON con `username`, `email`,
  `full_name`, `role`, `password` y `department`; crea el registro en `Usuarios`
  y su perfil de `Agentes` o `Supervisores`, guarda únicamente el hash PBKDF2
  en SQL y responde `{"user":{"id":1,"username":"…","email":"…","role":"Agente","full_name":"…","department":"…"}}`.
- `POST /api/users/{id}/password`: solo supervisores; acepta
  `{"password":"…"}`, almacena el hash del servidor y devuelve
  `{"message":"Contraseña actualizada."}`. También restablece los intentos y el
  bloqueo. No genera contraseñas temporales ni devuelve el hash o la contraseña.
- `POST /api/suggestions`: solo agentes; formulario multipart `title`, `detail`
  y `image` opcional; devuelve el mismo objeto que GET:
  `{"id":1,"date":"…","email":"…","title":"…","detail":"…","has_image":true}`.
- `GET /api/suggestions`: solo supervisores; devuelve
  `{"suggestions":[{"id":1,"date":"…","email":"…","title":"…","detail":"…","has_image":true}]}`.
  `date` es ISO 8601 o `null`.
- `GET /api/suggestions/{id}/image`: solo supervisores; devuelve los bytes de
  imagen almacenada con su MIME verificado (`image/jpeg`, `image/png`,
  `image/gif` o `image/webp`).
- `POST /api/conversions`: solo agentes; recibe multipart `original` (CSV),
  `converted` (XLSX), `original_name` y `converted_name`. Valida extensiones,
  tamaño máximo de 25 MiB por archivo y que el XLSX sea un contenedor válido;
  guarda ambos blobs en `dbo.Conversion_CSV_XLSX` sin escribir archivos al
  directorio web y responde `{"id":1}`.
- `POST /api/conversions/{id}/downloaded`: solo el agente propietario; establece
  `Fecha_Descarga` en `dbo.Conversion_CSV_XLSX` y devuelve
  `{"message":"Descarga registrada."}`. Una conversión ajena o inexistente
  devuelve `404`.
- `GET /api/dashboard/errors`: solo supervisores; devuelve
  `{"errors":[{"id":1,"codification_id":1,"agent_id":1,"file_name":"…","row":2,"type":"…","description":"…","agent_email":"…","date":"…","status":"…","resolved_at":null}]}`.
  Los campos de fecha son ISO 8601 o `null`.
- Se conservan las rutas previas `/api/sugerencias` (GET/POST) y
  `/api/sugerencias/{id}/imagen` (GET); la ruta de listado española conserva
  la envoltura `{"sugerencias":[...]}` y comparte el formato de cada elemento.
- `POST /api/auditar-productos`: conserva el contrato y las reglas de validación
  y CSV actuales. Una sesión válida de agente hace que el envío se guarde en
  `Codificacion` y que sus incidencias/correcciones se agreguen a
  `Dashboard_Errores`; el archivo original y el CSV procesado se guardan en las
  columnas binarias ya existentes. Las solicitudes sin sesión conservan el
  comportamiento anterior, sin persistencia. Una sesión de supervisor no se
  trata como una sesión de agente para este guardado.

## Bloqueo por intentos fallidos

Ejecuta el script aditivo en `AuditoriaDatos` antes de iniciar el backend y
vuelve a ejecutarlo cuando se actualice para instalar sus cambios:

```powershell
sqlcmd -S localhost -d AuditoriaDatos -E -C -b -f 65001 -i .\sql\login_lockout.sql
```

El script crea `dbo.Intentos_Acceso` solo si aún no existe, relacionada con
`dbo.Usuarios`. Las cuentas permanecen bloqueadas hasta el vencimiento de las 24
horas o hasta que un supervisor actualiza la contraseña desde Credenciales.
El trigger `dbo.TR_Usuarios_ReiniciarIntentosAcceso` también borra el bloqueo
cuando cambia realmente `Usuarios.Contraseña`, incluso si la contraseña se
actualiza directamente en SQL Server. Cada inicio de sesión correcto borra los
fallos previos. El estado persiste aunque se reinicie la aplicación.

Las imágenes aceptadas son JPEG, PNG, GIF y WebP; se compara el MIME declarado
con la firma binaria, se valida el contenido, se limita el tamaño a 5 MiB y las
dimensiones a 40 megapíxeles. No se acepta SVG.
Los errores de conexión no exponen mensajes SQL ni datos cargados.

El esquema existente permite `Detalles_Errores_Codificacion` únicamente cuando
hay un `ID_Error` válido de `Errores`. Durante la inspección, `dbo.Errores` no
contenía tipos; por eso no se insertan detalles ni se inventan/siembran tipos.
`Dashboard_Errores` y `Codificacion` sí se guardan. Para activar los detalles,
deben existir previamente filas de catálogo con `Tipo_Error` igual a `Precio faltante`,
`SKU faltante` o `SKU duplicado` (la comparación no distingue mayúsculas). No se
realizaron cambios de esquema ni se agregaron esos datos.

## Integración de la interfaz

El frontend servido por FastAPI (`http://localhost:8000/`) usa las rutas
same-origin con cookie `HttpOnly`: el login valida credenciales contra SQL
Server; agentes pueden enviar sugerencias con imagen opcional y verán los
registros persistidos por supervisión; supervisores pueden ver sugerencias,
imágenes, errores de auditoría y usuarios activos, crear cuentas y cambiar
contraseñas. El formulario de alta almacena únicamente un hash generado por
el backend y ya no muestra ni genera contraseñas temporales. Las conversiones
CSV→XLSX registran los dos archivos en SQL Server y guardan la descarga.
Para acceder, usa el script de inicio descrito arriba; no abras `index.html`
directamente como `file://`, ya que las cookies y APIs requieren el servidor.
Los estilos personalizados viven en `styles.css`; el resto de clases visuales
usa utilidades Tailwind en el marcado. No hay estilos `style=""` en el HTML.
