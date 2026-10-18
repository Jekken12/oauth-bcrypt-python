# Práctica Integridad - OAuth + bcrypt

Aplicación de autenticación desarrollada con Python, Flask, MySQL, OAuth 2.0 y bcrypt.

## Funcionalidades

- Registro local de usuarios.
- Hash de contraseñas con bcrypt.
- Validación de credenciales mediante bcrypt.
- Inicio de sesión con Google OAuth 2.0.
- Persistencia de usuarios en MySQL.
- Sesión y cierre de sesión.

## Tecnologías

- Python
- Flask
- bcrypt
- Authlib
- MySQL
- HTML/CSS

## Instalación

1. Crear un entorno virtual:

```powershell
python -m venv venv
```

2. Activarlo:

```powershell
.\venv\Scripts\Activate.ps1
```

3. Instalar dependencias:

```powershell
pip install -r requirements.txt
```

4. Crear la base de datos ejecutando `database/schema.sql`.

5. Copiar `.env.example` a `.env` y completar las variables locales.

6. Ejecutar:

```powershell
python app.py
```

7. Abrir:

```text
http://127.0.0.1:5000
```

## Google OAuth

Agregar como URI de redireccionamiento autorizada:

```text
http://127.0.0.1:5000/auth/callback
```

## Seguridad

El archivo `.env` no debe subirse al repositorio. Las contraseñas locales se almacenan como hashes bcrypt y no en texto plano.
