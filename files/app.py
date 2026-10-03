from flask import Flask, render_template, request, jsonify, session, redirect, send_from_directory
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
from datetime import datetime

import atexit
import hashlib
import hmac
import threading
import pyotp
import paho.mqtt.client as mqtt
from flask_socketio import SocketIO, join_room, disconnect
import qrcode
import io
import base64
import json
import os
import re
import secrets
import time

# =========================================================
# CARGA DE VARIABLES DE ENTORNO
# =========================================================

load_dotenv()

app = Flask(__name__, template_folder='templates')

# La app NUNCA arranca sin SECRET_KEY definida en .env
SECRET_KEY = os.environ.get('SECRET_KEY')
if not SECRET_KEY:
    raise RuntimeError(
        'SECRET_KEY no está definida. Crea un archivo .env con SECRET_KEY=<valor generado>. '
        'Genera uno con: python -c "import secrets; print(secrets.token_hex(32))"'
    )
app.secret_key = SECRET_KEY

# Modo debug: SOLO si lo pides explícitamente en .env (FLASK_ENV=development).
# Para la demo déjalo apagado: con debug + host 0.0.0.0 el depurador de
# Werkzeug queda expuesto a toda tu red.
MODO_DEBUG = os.environ.get('FLASK_ENV') == 'development'

# Auto-reload al guardar app.py. Con True se reinicia el servidor (y se corta
# MQTT/WebSockets) cada vez que guardas; para la demo déjalo en False.
USAR_RELOADER = False

# Sesiones "recordarme" (7 días si el usuario lo activa)
app.config['PERMANENT_SESSION_LIFETIME'] = 60 * 60 * 24 * 7

# Cookies de sesión más seguras
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
# En producción con HTTPS activo, además poner:
# app.config['SESSION_COOKIE_SECURE'] = True

# =========================================================
# CSRF PROTECTION
# =========================================================

csrf = CSRFProtect(app)

@app.after_request
def set_csrf_cookie(response):
    # Exponemos el token en una cookie legible por JS para incluirlo en cada fetch()
    response.set_cookie('csrf_token', generate_csrf(), samesite='Strict')
    return response

# =========================================================
# RATE LIMITING
# =========================================================

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"   # en producción real con varios workers: storage_uri="redis://localhost:6379"
)

# =========================================================
# WEBSOCKETS (Flask-SocketIO) — empuje en tiempo real al navegador
# =========================================================
# async_mode="threading" funciona con el propio servidor de desarrollo de
# Flask (no necesita eventlet/gevent), siempre que esté instalado
# "simple-websocket" (ver requirements-mqtt.txt).
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

ROOM_ADMIN = 'admin_all'

@socketio.on('connect')
def _socket_connect():
    # Mismo control de acceso que las rutas HTTP: sin sesión, no hay conexión.
    if 'user_id' not in session:
        disconnect()
        return
    if session.get('rol') == 'admin':
        join_room(ROOM_ADMIN)
    else:
        usuario = buscar_usuario_por_id(session['user_id'])
        estacion_id = usuario.get('estacion_id') if usuario else None
        if estacion_id:
            join_room(f'estacion:{estacion_id}')

# =========================================================
# CONFIG DE REGISTRO Y RECUPERACIÓN DE CONTRASEÑA
# =========================================================

EMAIL_REGEX = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# Mínimo 8 caracteres, al menos una mayúscula y un número
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*[0-9]).{8,}$')
PASSWORD_MIN_LENGTH = 8

RESET_TOKEN_TTL_SEGUNDOS = 15 * 60

# Tokens de recuperación de contraseña en memoria
# Estructura: { token: { 'email': str, 'expira': timestamp } }
# NOTA: en producción real, esto debería vivir en la base de datos
# y el token debería enviarse por correo (ver sección "Fase 1 - correo real"
# en el plan de transformación), no mostrarse en la respuesta.
reset_tokens = {}

# =========================================================
# LOGO
# =========================================================

@app.route('/logo.png')
def logo():
    return send_from_directory('templates', 'logo.png')

# =========================================================
# ARCHIVO DE DATOS
# =========================================================

DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data.json')

# Protege `data` (hilo MQTT + hilos de Flask). Es RLock: se puede tomar
# de nuevo desde el mismo hilo sin bloquearse.
data_lock = threading.RLock()

# Las lecturas de sensores llegan cada ~2 s; guardar todo data.json en cada
# una es innecesario. Se guarda como máximo cada GUARDADO_MIN_SEG segundos.
GUARDADO_MIN_SEG = int(os.environ.get('GUARDADO_MIN_SEG', '10'))
_ultimo_guardado = 0.0

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_data():
    """Guarda data.json de forma atómica (archivo temporal + reemplazo):
    si el proceso muere a media escritura, el data.json anterior queda intacto."""
    global _ultimo_guardado
    tmp = DATA_FILE + '.tmp'
    with data_lock:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        # En Windows, OneDrive o el antivirus pueden retener el archivo un instante
        for _ in range(5):
            try:
                os.replace(tmp, DATA_FILE)
                _ultimo_guardado = time.time()
                return
            except PermissionError:
                time.sleep(0.1)
        print('[DATA] No se pudo reemplazar data.json (archivo bloqueado). '
              'Si el proyecto está en OneDrive, muévelo a una carpeta local.')

def save_data_limitado():
    """Igual que save_data() pero solo si pasaron GUARDADO_MIN_SEG desde el último guardado."""
    with data_lock:
        if time.time() - _ultimo_guardado >= GUARDADO_MIN_SEG:
            save_data()

data = load_data()

# Al cerrar el servidor con Ctrl+C se guarda lo último que estaba en memoria
atexit.register(save_data)

# =========================================================
# UTILIDADES DE USUARIOS
# =========================================================

def buscar_usuario_por_email(email):
    return next(
        (u for u in data['usuarios'] if u['email'].lower() == email.lower()),
        None
    )

def buscar_usuario_por_id(user_id):
    return next(
        (u for u in data['usuarios'] if u['id'] == user_id),
        None
    )

def generar_nuevo_id_usuario():
    ids_existentes = [
        int(u['id']) for u in data['usuarios']
        if str(u['id']).isdigit()
    ]
    siguiente = max(ids_existentes, default=0) + 1
    return str(siguiente)

# =========================================================
# DECORADORES DE ACCESO
# =========================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/')
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get('rol') != 'admin':
            return jsonify({'success': False, 'error': 'No autorizado'}), 403
        return f(*args, **kwargs)
    return decorated_function

# =========================================================
# RUTAS HTML
# =========================================================

@app.route('/')
def login_page():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('rol') != 'admin':
        return redirect('/agricultor')
    return render_template('MeteoX.html')

@app.route('/agricultor')
@login_required
def agricultor():
    if session.get('rol') != 'agricultor':
        return redirect('/dashboard')
    return render_template('Agricultor.html')

# =========================================================
# LOGIN API
# =========================================================

@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")   # máximo 5 intentos por minuto por IP - mitiga fuerza bruta
def login():

    req_data = request.get_json()
    email = req_data.get('email', '').strip()
    password = req_data.get('password', '').strip()
    recordarme = req_data.get('recordarme', False)

    usuario = buscar_usuario_por_email(email)

    # check_password_hash es seguro incluso si usuario es None (evaluación corta)
    password_valido = usuario and check_password_hash(usuario['password_hash'], password)

    if not usuario or not password_valido:
        # Mensaje idéntico en ambos casos: no revelar si falló el correo o la contraseña
        return jsonify({
            'success': False,
            'error': 'Correo o contraseña incorrectos'
        }), 401

    # Si el usuario tiene 2FA activo, el login se detiene aquí
    # y se completa en /api/2fa/verificar
    if usuario.get('totp_secret'):
        session['pre_2fa_user_id'] = usuario['id']
        return jsonify({'success': True, 'requiere_2fa': True})

    session.permanent = bool(recordarme)
    session['user_id'] = usuario['id']
    session['nombre'] = usuario['nombre']
    session['rol'] = usuario['rol']

    redirect_url = '/dashboard' if usuario['rol'] == 'admin' else '/agricultor'

    return jsonify({
        'success': True,
        'redirect': redirect_url,
        'user': {
            'nombre': usuario['nombre'],
            'rol': usuario['rol']
        }
    })

# =========================================================
# LOGOUT
# =========================================================

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

# =========================================================
# REGISTRO DE USUARIOS
# =========================================================

@app.route('/api/registro', methods=['POST'])
@limiter.limit("10 per hour")
def registro():

    req_data = request.get_json()
    nombre = req_data.get('nombre', '').strip()
    email = req_data.get('email', '').strip()
    password = req_data.get('password', '').strip()
    confirmar_password = req_data.get('confirmar_password', '').strip()

    if not nombre:
        return jsonify({'success': False, 'error': 'El nombre es obligatorio'}), 400

    if not email or not EMAIL_REGEX.match(email):
        return jsonify({'success': False, 'error': 'Correo electrónico inválido'}), 400

    if not PASSWORD_REGEX.match(password):
        return jsonify({
            'success': False,
            'error': 'La contraseña debe tener al menos 8 caracteres, una mayúscula y un número'
        }), 400

    if password != confirmar_password:
        return jsonify({'success': False, 'error': 'Las contraseñas no coinciden'}), 400

    if buscar_usuario_por_email(email):
        return jsonify({'success': False, 'error': 'Ya existe una cuenta con ese correo'}), 409

    nuevo_usuario = {
        'id': generar_nuevo_id_usuario(),
        'nombre': nombre,
        'email': email,
        'password_hash': generate_password_hash(password, method='pbkdf2:sha256', salt_length=16),
        'rol': 'agricultor',
        'estacion_id': None,
        'totp_secret': None
    }

    data['usuarios'].append(nuevo_usuario)
    save_data()

    return jsonify({
        'success': True,
        'mensaje': 'Cuenta creada correctamente. Un administrador debe asignarte una estación.',
        'user': {
            'id': nuevo_usuario['id'],
            'nombre': nuevo_usuario['nombre'],
            'email': nuevo_usuario['email'],
            'rol': nuevo_usuario['rol']
        }
    })

# =========================================================
# RECUPERACIÓN DE CONTRASEÑA - PASO 1: SOLICITAR TOKEN
# =========================================================

@app.route('/api/recuperar', methods=['POST'])
@limiter.limit("3 per hour")   # evita generación de tokens en cadena
def recuperar():

    req_data = request.get_json()
    email = req_data.get('email', '').strip()

    if not email or not EMAIL_REGEX.match(email):
        return jsonify({'success': False, 'error': 'Correo electrónico inválido'}), 400

    usuario = buscar_usuario_por_email(email)

    if not usuario:
        return jsonify({'success': False, 'error': 'No existe una cuenta con ese correo'}), 404

    token = secrets.token_hex(4).upper()

    reset_tokens[token] = {
        'email': usuario['email'],
        'expira': time.time() + RESET_TOKEN_TTL_SEGUNDOS
    }

    # NOTA IMPORTANTE: en esta versión de desarrollo el token se retorna
    # directamente en la respuesta para poder probar el flujo sin servidor
    # de correo configurado. En producción, este bloque debe eliminarse
    # y sustituirse por un envío real con Flask-Mail / SendGrid / Mailgun,
    # devolviendo únicamente el mensaje de éxito, nunca el token.
    return jsonify({
        'success': True,
        'mensaje': 'Código de recuperación generado. Válido por 15 minutos.',
        'token': token  # TODO: quitar antes de producción, ver nota arriba
    })

# =========================================================
# RECUPERACIÓN DE CONTRASEÑA - PASO 2: RESTABLECER
# =========================================================

@app.route('/api/restablecer', methods=['POST'])
@limiter.limit("5 per hour")
def restablecer():

    req_data = request.get_json()
    token = req_data.get('token', '').strip().upper()
    nueva_password = req_data.get('nueva_password', '').strip()
    confirmar_password = req_data.get('confirmar_password', '').strip()

    if not token or token not in reset_tokens:
        return jsonify({'success': False, 'error': 'Código de recuperación inválido'}), 400

    info_token = reset_tokens[token]

    if time.time() > info_token['expira']:
        del reset_tokens[token]
        return jsonify({
            'success': False,
            'error': 'El código de recuperación ha expirado, solicita uno nuevo'
        }), 400

    if not PASSWORD_REGEX.match(nueva_password):
        return jsonify({
            'success': False,
            'error': 'La contraseña debe tener al menos 8 caracteres, una mayúscula y un número'
        }), 400

    if nueva_password != confirmar_password:
        return jsonify({'success': False, 'error': 'Las contraseñas no coinciden'}), 400

    usuario = buscar_usuario_por_email(info_token['email'])

    if not usuario:
        return jsonify({'success': False, 'error': 'Usuario no encontrado'}), 404

    usuario['password_hash'] = generate_password_hash(
        nueva_password, method='pbkdf2:sha256', salt_length=16
    )
    save_data()

    del reset_tokens[token]

    return jsonify({'success': True, 'mensaje': 'Contraseña restablecida correctamente'})

# =========================================================
# 2FA — ACTIVACIÓN (usuario ya logueado la activa desde su perfil)
# =========================================================

@app.route('/api/2fa/activar', methods=['POST'])
@login_required
def activar_2fa():

    usuario = buscar_usuario_por_id(session['user_id'])

    secreto = pyotp.random_base32()
    usuario['totp_secret_temporal'] = secreto
    save_data()

    uri = pyotp.totp.TOTP(secreto).provisioning_uri(
        name=usuario['email'], issuer_name='MeteoX'
    )

    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return jsonify({
        'success': True,
        'qr_base64': qr_base64,
        'secreto_manual': secreto
    })

@app.route('/api/2fa/confirmar', methods=['POST'])
@login_required
def confirmar_2fa():

    codigo = request.get_json().get('codigo', '').strip()
    usuario = buscar_usuario_por_id(session['user_id'])

    secreto_temp = usuario.get('totp_secret_temporal')
    if not secreto_temp:
        return jsonify({'success': False, 'error': 'No hay activación de 2FA pendiente'}), 400

    totp = pyotp.TOTP(secreto_temp)
    if not totp.verify(codigo, valid_window=1):
        return jsonify({'success': False, 'error': 'Código incorrecto'}), 400

    usuario['totp_secret'] = secreto_temp
    del usuario['totp_secret_temporal']
    save_data()

    return jsonify({'success': True, 'mensaje': '2FA activado correctamente'})

@app.route('/api/2fa/desactivar', methods=['POST'])
@login_required
def desactivar_2fa():
    usuario = buscar_usuario_por_id(session['user_id'])
    usuario['totp_secret'] = None
    save_data()
    return jsonify({'success': True, 'mensaje': '2FA desactivado'})

# =========================================================
# 2FA — VERIFICACIÓN (segundo paso del login)
# =========================================================

@app.route('/api/2fa/verificar', methods=['POST'])
@limiter.limit("5 per minute")
def verificar_2fa():

    codigo = request.get_json().get('codigo', '').strip()
    user_id = session.get('pre_2fa_user_id')

    if not user_id:
        return jsonify({'success': False, 'error': 'Sesión de login expirada, intenta de nuevo'}), 400

    usuario = buscar_usuario_por_id(user_id)
    if not usuario or not usuario.get('totp_secret'):
        return jsonify({'success': False, 'error': 'Error de verificación'}), 400

    totp = pyotp.TOTP(usuario['totp_secret'])
    if not totp.verify(codigo, valid_window=1):
        return jsonify({'success': False, 'error': 'Código incorrecto'}), 400

    session.pop('pre_2fa_user_id', None)
    session['user_id'] = usuario['id']
    session['nombre'] = usuario['nombre']
    session['rol'] = usuario['rol']

    redirect_url = '/dashboard' if usuario['rol'] == 'admin' else '/agricultor'
    return jsonify({'success': True, 'redirect': redirect_url})

# =========================================================
# DATOS DEL USUARIO
# =========================================================

@app.route('/api/me')
@limiter.exempt  # ruta de solo lectura consultada por polling frecuente del dashboard
@login_required
def me():
    usuario = buscar_usuario_por_id(session['user_id'])
    # Nunca devolver el hash de contraseña ni secretos TOTP al frontend
    if usuario:
        usuario_publico = {k: v for k, v in usuario.items()
                            if k not in ('password_hash', 'totp_secret', 'totp_secret_temporal')}
        usuario_publico['tiene_2fa'] = bool(usuario.get('totp_secret'))
        return jsonify(usuario_publico)
    return jsonify(None), 404

# =========================================================
# ESTADO DE CONEXIÓN (heartbeat de 3 niveles)
# =========================================================
# El "heartbeat" no es un campo nuevo: ya existe como
# estacion['ultima_actualizacion'] (se actualiza en cada lectura aceptada,
# por HTTP o MQTT) y sensor['ultima_lectura']. Aquí solo se interpreta con
# umbrales, siempre calculado al vuelo — nunca se guarda en data.json, así
# no hay estado que se desincronice del dato real.

HEARTBEAT_WARN_SEG = int(os.environ.get('HEARTBEAT_WARN_SEG', '30'))
HEARTBEAT_OFFLINE_SEG = int(os.environ.get('HEARTBEAT_OFFLINE_SEG', '120'))


def _segundos_desde(iso_ts):
    """Segundos transcurridos desde un timestamp ISO, o None si no hay dato."""
    if not iso_ts:
        return None
    try:
        return (datetime.now() - datetime.fromisoformat(iso_ts)).total_seconds()
    except ValueError:
        return None


def estado_estacion(estacion):
    """'en_linea' | 'advertencia' | 'desconectada' según el último heartbeat."""
    segundos = _segundos_desde(estacion.get('ultima_actualizacion'))
    if segundos is None:
        return 'desconectada'
    if segundos <= HEARTBEAT_WARN_SEG:
        return 'en_linea'
    if segundos <= HEARTBEAT_OFFLINE_SEG:
        return 'advertencia'
    return 'desconectada'


def estado_sensor(sensor):
    """'funcionando' | 'sin_respuesta' | 'error' para un sensor individual.

    'error' tiene prioridad: significa que el sensor SÍ está comunicando,
    pero su valor está fuera del rango ideal (alerta automática activa).
    'sin_respuesta' es cuando el sensor dejó de mandar lecturas, independiente
    de si el resto de la estación sigue en línea.
    """
    alerta_activa = next(
        (a for a in data['alertas']
         if a.get('sensor_id') == sensor['id'] and a.get('estado') == 'activa'),
        None
    )
    if alerta_activa:
        return 'error'
    segundos = _segundos_desde(sensor.get('ultima_lectura'))
    if segundos is None or segundos > HEARTBEAT_WARN_SEG:
        return 'sin_respuesta'
    return 'funcionando'

# =========================================================
# API ESTACIONES
# =========================================================

@app.route('/api/estaciones')
@limiter.exempt  # ruta de solo lectura consultada por polling frecuente del dashboard
@login_required
def estaciones():
    # Todo dentro del lock: el hilo MQTT modifica `data` en paralelo
    with data_lock:
        if session.get('rol') == 'admin':
            estaciones_visibles = data['estaciones']
        else:
            usuario = buscar_usuario_por_id(session['user_id'])
            estacion_id = usuario.get('estacion_id') if usuario else None
            estaciones_visibles = [e for e in data['estaciones'] if e['id'] == estacion_id]

        # estado_estacion se calcula al vuelo (nunca se guarda) para no
        # desincronizarse del heartbeat real.
        return jsonify([
            {**e, 'estado_conexion': estado_estacion(e)}
            for e in estaciones_visibles
        ])

# =========================================================
# API SENSORES
# =========================================================

@app.route('/api/sensores')
@limiter.exempt  # ruta de solo lectura consultada por polling frecuente del dashboard
@login_required
def sensores():
    with data_lock:
        if session.get('rol') == 'admin':
            sensores_visibles = data['sensores']
        else:
            usuario = buscar_usuario_por_id(session['user_id'])
            estacion_id = usuario.get('estacion_id') if usuario else None
            sensores_visibles = [s for s in data['sensores'] if s['estacion_id'] == estacion_id]

        return jsonify([
            {**s, 'estado_sensor': estado_sensor(s)}
            for s in sensores_visibles
        ])

# =========================================================
# API ADMIN — TABLA DE USUARIOS/ESTACIONES (heartbeat)
# =========================================================

@app.route('/api/admin/usuarios')
@limiter.exempt  # ruta de solo lectura consultada por polling frecuente del dashboard
@login_required
@admin_required
def admin_usuarios():
    with data_lock:
        filas = []
        for usuario in data['usuarios']:
            if usuario['rol'] != 'agricultor':
                continue

            estacion = next(
                (e for e in data['estaciones'] if e['id'] == usuario.get('estacion_id')),
                None
            )
            sensores_estacion = [
                s for s in data['sensores'] if s['estacion_id'] == usuario.get('estacion_id')
            ]
            sensores_ok = sum(1 for s in sensores_estacion if estado_sensor(s) == 'funcionando')

            filas.append({
                'usuario_id': usuario['id'],
                'agricultor': usuario['nombre'],
                'estacion_id': estacion['id'] if estacion else None,
                'estacion_nombre': estacion['nombre'] if estacion else 'Sin estación asignada',
                'estado_conexion': estado_estacion(estacion) if estacion else 'desconectada',
                'ultima_actualizacion': estacion.get('ultima_actualizacion') if estacion else None,
                'sensores_ok': sensores_ok,
                'sensores_total': len(sensores_estacion),
            })

        return jsonify(filas)

# =========================================================
# API SENSORES - INGESTA DESDE HARDWARE (ESP32)
# =========================================================

DEVICE_API_KEY = os.environ.get('DEVICE_API_KEY')
if not DEVICE_API_KEY:
    raise RuntimeError(
        'DEVICE_API_KEY no está definida. Agrega DEVICE_API_KEY=<valor> a tu .env. '
        'Genera uno con: python -c "import secrets; print(secrets.token_hex(16))"'
    )
DEVICE_API_KEY = DEVICE_API_KEY.strip()

# Puntos de historial en memoria por sensor. El ESP32 publica cada 2 s:
# 900 puntos ≈ 30 min.
MAX_HISTORIAL = int(os.environ.get('MAX_HISTORIAL', '900'))


def aplicar_lectura(estacion_id, lecturas, gps=None):
    """Aplica una lectura (temperatura/humedad) a la estación. Compartida por HTTP y MQTT."""
    ahora = datetime.now().isoformat(timespec='seconds')
    actualizados = []

    with data_lock:
        for tipo, valor in lecturas.items():
            if valor is None:
                continue
            sensor = next(
                (s for s in data['sensores']
                 if s['estacion_id'] == estacion_id and s['tipo'] == tipo),
                None
            )
            if not sensor:
                print(f'[DATA] No hay sensor tipo "{tipo}" para la estación "{estacion_id}" en data.json')
                continue

            valor_redondeado = round(float(valor), 1)
            sensor['valor_actual'] = valor_redondeado
            sensor['ultima_lectura'] = ahora
            sensor['estado'] = 'activo'
            actualizados.append(sensor['id'])

            sensor.setdefault('historial', [])
            sensor['historial'].append({'valor': valor_redondeado, 'fecha': ahora})
            sensor['historial'] = sensor['historial'][-MAX_HISTORIAL:]

            # Alerta automática si el valor sale del rango_ideal
            rango = sensor.get('rango_ideal', '')
            if '-' in rango:
                try:
                    minimo, maximo = (float(x) for x in rango.split('-'))
                    fuera_de_rango = valor_redondeado < minimo or valor_redondeado > maximo
                    alerta_id = f"auto-{sensor['id']}"
                    alerta_existente = next(
                        (a for a in data['alertas'] if a['id'] == alerta_id), None
                    )
                    if fuera_de_rango:
                        descripcion = (
                            f"{sensor['nombre']}: {valor_redondeado}{sensor['unidad']} "
                            f"(ideal: {rango}{sensor['unidad']})"
                        )
                        if alerta_existente:
                            alerta_existente['descripcion'] = descripcion
                            alerta_existente['fecha'] = ahora
                            alerta_existente['estado'] = 'activa'
                        else:
                            data['alertas'].append({
                                'id': alerta_id,
                                'estacion_id': estacion_id,
                                'sensor_id': sensor['id'],
                                'titulo': f"{sensor['nombre']} fuera de rango",
                                'descripcion': descripcion,
                                'tipo': 'advertencia',
                                'estado': 'activa',
                                'fecha': ahora,
                                'prioridad': 'media'
                            })
                    elif alerta_existente:
                        alerta_existente['estado'] = 'resuelta'
                        alerta_existente['fecha'] = ahora
                except ValueError:
                    pass

        estacion = next((e for e in data['estaciones'] if e['id'] == estacion_id), None)
        if estacion:
            estacion['ultima_actualizacion'] = ahora
            if gps:
                estacion['gps'] = gps
                # Solo actualiza las coordenadas "oficiales" de la estación
                # cuando hay fix real; si se pierde la señal un momento, el
                # mapa se queda en la última ubicación buena conocida.
                if gps.get('fix') and gps.get('lat') is not None and gps.get('lon') is not None:
                    estacion['latitud'] = gps['lat']
                    estacion['longitud'] = gps['lon']
        else:
            print(f'[DATA] La estación "{estacion_id}" no existe en data.json')

        save_data_limitado()

    # Aviso en tiempo real: el navegador no necesita seguir preguntando,
    # el servidor le avisa apenas hay un dato nuevo (evento sin datos pesados;
    # el navegador vuelve a pedir /api/sensores, /api/estaciones y /api/alertas
    # como ya hacía, solo que ahora al instante en vez de cada 2 s).
    socketio.emit('datos_actualizados', {'estacion_id': estacion_id}, room=ROOM_ADMIN)
    socketio.emit('datos_actualizados', {'estacion_id': estacion_id}, room=f'estacion:{estacion_id}')

    return actualizados


@app.route('/api/sensores/actualizar', methods=['POST'])
@csrf.exempt  # el ESP32 no maneja tokens CSRF, se autentica con API key
@limiter.limit("60 per minute")
def actualizar_sensores():
    """Ruta HTTP de respaldo (el flujo principal ahora es MQTT)."""
    api_key = request.headers.get('X-API-Key', '')
    if not secrets.compare_digest(api_key, DEVICE_API_KEY):
        return jsonify({'success': False, 'error': 'No autorizado'}), 401

    req_data = request.get_json(silent=True) or {}
    estacion_id = req_data.get('estacion_id', '').strip()
    if not estacion_id:
        return jsonify({'success': False, 'error': 'Falta estacion_id'}), 400

    # Igual que en el canal MQTT: se reporta el estado del GPS aunque no
    # haya fix todavía, para que el dashboard pueda mostrar "buscando señal".
    gps = None
    if 'gps_fix' in req_data or 'lat' in req_data or 'lon' in req_data:
        gps = {
            'fix': bool(req_data.get('gps_fix')),
            'satelites': req_data.get('sat', 0),
        }
        if req_data.get('gps_fix') and req_data.get('lat') is not None and req_data.get('lon') is not None:
            gps['lat'] = float(req_data['lat'])
            gps['lon'] = float(req_data['lon'])
            if req_data.get('alt') is not None:
                gps['alt'] = req_data.get('alt')

    actualizados = aplicar_lectura(estacion_id, {
        'temperatura': req_data.get('temperatura'),
        'humedad': req_data.get('humedad'),
    }, gps)
    return jsonify({'success': True, 'actualizados': actualizados})

# =========================================================
# INGESTA POR MQTT (broker público)
# =========================================================
# El ESP32 publica en:  <MQTT_TOPIC_PREFIX>/<estacion_id>/telemetria
# Mensaje:              <json>|<firma_hmac_sha256_hex>
# La firma se calcula con DEVICE_API_KEY sobre el texto <json>.
# Este proceso se suscribe y actualiza `data`; los dashboards (admin y
# agricultor) siguen leyendo /api/* con su filtrado por rol.

MQTT_BROKER = os.environ.get('MQTT_BROKER', 'broker.hivemq.com').strip()
MQTT_PORT = int(os.environ.get('MQTT_PORT', '1883'))
MQTT_TOPIC_PREFIX = os.environ.get('MQTT_TOPIC_PREFIX', '').strip().strip('/')
if not MQTT_TOPIC_PREFIX:
    raise RuntimeError(
        'MQTT_TOPIC_PREFIX no está definida. En un broker público el prefijo es tu "contraseña" '
        'de tema. Genera uno con: python -c "import secrets; print(\'meteox-\' + secrets.token_hex(8))"'
    )
MQTT_TOPIC = f"{MQTT_TOPIC_PREFIX}/+/telemetria"

# MQTT_VERBOSE=1 imprime una línea por cada mensaje aceptado (útil para depurar;
# ponlo en 0 en el .env cuando ya todo funcione para no llenar la consola).
MQTT_VERBOSE = os.environ.get('MQTT_VERBOSE', '1') == '1'

mqtt_cliente = None
tick_estado_hilo = None


def _mqtt_on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        client.subscribe(MQTT_TOPIC, qos=0)
        print(f'[MQTT] Conectado a {MQTT_BROKER}:{MQTT_PORT}, suscrito a {MQTT_TOPIC}')
    else:
        print(f'[MQTT] Fallo de conexión: {reason_code}')


def _mqtt_on_disconnect(client, userdata, *args):
    # Firma distinta entre paho 1.x y 2.x: se aceptan ambas
    print(f'[MQTT] Desconectado del broker ({args}). Reconectando solo...')


def _mqtt_on_message(client, userdata, msg):
    try:
        texto = msg.payload.decode('utf-8')
        cuerpo, _, firma = texto.rpartition('|')
        esperada = hmac.new(DEVICE_API_KEY.encode(), cuerpo.encode(), hashlib.sha256).hexdigest()
        if not cuerpo or not hmac.compare_digest(firma.strip().lower(), esperada):
            print(f'[MQTT] Mensaje descartado: firma inválida (topic {msg.topic})')
            return

        d = json.loads(cuerpo)
        estacion_id = str(d.get('estacion_id', '')).strip()
        if not estacion_id:
            print('[MQTT] Mensaje descartado: falta estacion_id')
            return

        # Siempre se reporta el estado del GPS (con o sin señal), para que el
        # dashboard pueda mostrar "buscando señal" en vez de quedarse callado.
        gps = {
            'fix': bool(d.get('fix')),
            'satelites': d.get('sat', 0),
        }
        if d.get('fix') and d.get('lat') is not None and d.get('lon') is not None:
            gps['lat'] = float(d['lat'])
            gps['lon'] = float(d['lon'])
            if d.get('alt') is not None:
                gps['alt'] = d.get('alt')

        actualizados = aplicar_lectura(estacion_id, {
            'temperatura': d.get('temperatura'),
            'humedad': d.get('humedad'),
        }, gps)

        if MQTT_VERBOSE:
            print(f'[MQTT] {estacion_id}: T={d.get("temperatura")} H={d.get("humedad")} '
                  f'GPS fix={gps["fix"]} sat={gps["satelites"]} -> sensores={actualizados}')
    except Exception as e:
        print(f'[MQTT] Error procesando mensaje: {e}')


def iniciar_mqtt():
    client_id = f"meteox-server-{secrets.token_hex(4)}"   # único: en broker público un id repetido te expulsa
    try:
        # paho-mqtt 2.x
        cliente = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
    except AttributeError:
        # paho-mqtt 1.x (no tiene CallbackAPIVersion)
        cliente = mqtt.Client(client_id=client_id)
    cliente.on_connect = _mqtt_on_connect
    cliente.on_disconnect = _mqtt_on_disconnect
    cliente.on_message = _mqtt_on_message
    cliente.reconnect_delay_set(min_delay=1, max_delay=30)
    cliente.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=30)
    cliente.loop_start()   # hilo en segundo plano, reconecta solo
    return cliente


# =========================================================
# TICK DE ESTADO — refresca el Dashboard aunque una estación
# deje de enviar datos (una estación muerta nunca dispara
# 'datos_actualizados' por sí sola, así que el cambio a
# 🟡/🔴 necesita este latido periódico independiente).
# =========================================================

ESTADO_TICK_SEG = int(os.environ.get('ESTADO_TICK_SEG', '15'))


def _tick_estado():
    while True:
        time.sleep(ESTADO_TICK_SEG)
        with data_lock:
            socketio.emit('estado_actualizado', {}, room=ROOM_ADMIN)


def iniciar_tick_estado():
    hilo = threading.Thread(target=_tick_estado, daemon=True)
    hilo.start()
    return hilo


# Con el reloader activo Flask arranca dos procesos: solo el hijo
# (WERKZEUG_RUN_MAIN=true) debe suscribirse. Sin reloader, arranca siempre.
# (Antes esta condición dependía de FLASK_ENV y, con FLASK_ENV=development y
# use_reloader=False, el MQTT no arrancaba nunca.)
if not USAR_RELOADER or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    mqtt_cliente = iniciar_mqtt()
    tick_estado_hilo = iniciar_tick_estado()

# =========================================================
# API ALERTAS
# =========================================================

@app.route('/api/alertas')
@limiter.exempt  # ruta de solo lectura consultada por polling frecuente del dashboard
@login_required
def alertas():
    with data_lock:
        if session.get('rol') == 'admin':
            return jsonify(data['alertas'])

        usuario = buscar_usuario_por_id(session['user_id'])
        estacion_id = usuario.get('estacion_id') if usuario else None

        alertas_filtradas = [
            a for a in data['alertas']
            if a['estacion_id'] == estacion_id
        ]
        return jsonify(alertas_filtradas)

# =========================================================
# INICIAR SERVIDOR
# =========================================================

if __name__ == '__main__':

    print('MeteoX iniciado')
    print(f'Modo debug: {MODO_DEBUG}')
    print(f'MQTT: {"iniciado" if mqtt_cliente else "NO iniciado"} '
          f'({MQTT_BROKER}:{MQTT_PORT}, prefijo {MQTT_TOPIC_PREFIX})')
    print('http://127.0.0.1:5000')

    socketio.run(app, host='0.0.0.0', debug=MODO_DEBUG, use_reloader=USAR_RELOADER,
                 allow_unsafe_werkzeug=True)