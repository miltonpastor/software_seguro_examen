#app/jwt_utils.py
import jwt
import datetime
from flask import current_app
# Libreria para cargar variables de entorno
from dotenv import load_dotenv
import os

# Definir constantes para generar JWT
load_dotenv()
CLAVE_SECRETA = os.getenv("SECRET_KEY", "fallback_secret_key")
EXPIRACION_DEL_TOKEN = int(os.getenv("TOKEN_EXPIRATION_MINUTES", "30"))
JWT_ALGORITMO = 'HS256'

def generate_jwt_token(datos_usuario):
    payload = {
        'id_usuario': datos_usuario['id'],
        'nombre_usuario': datos_usuario['username'],
        'rol': datos_usuario['role'],
        'nombre_completo': datos_usuario['full_name'],
        'correo': datos_usuario['email'],
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=EXPIRACION_DEL_TOKEN),
        'iat': datetime.datetime.now(datetime.timezone.utc)
    }
    
    return jwt.encode(payload, CLAVE_SECRETA, algorithm=JWT_ALGORITMO)

def decodificar_jwt_token(token):
    return jwt.decode(token, CLAVE_SECRETA, algorithms=[JWT_ALGORITMO])

def extraer_token_de_header(header_autorizacion):
    if not header_autorizacion or not header_autorizacion.startswith("Bearer "):
        raise ValueError("Header de autorización faltante o inválido")
    
    return header_autorizacion.split(" ")[1]

def verificar_formato_token(token):
    try:
        # Los tokens JWT tienen 3 partes separadas por puntos
        partes = token.split('.')
        return len(partes) == 3
    except:
        return False

def obtener_tiempo_expiracion_token(token):
    try:
        payload = jwt.decode(token, CLAVE_SECRETA, algorithms=[JWT_ALGORITMO], options={"verify_exp": False})
        timestamp_exp = payload.get('exp')
        if timestamp_exp:
            return datetime.datetime.fromtimestamp(timestamp_exp, tz=datetime.timezone.utc)
        return None
    except:
        return None

def token_esta_expirado(token):
    tiempo_exp = obtener_tiempo_expiracion_token(token)
    if tiempo_exp is None:
        return None
    
    return datetime.datetime.now(datetime.timezone.utc) > tiempo_exp

def validar_token_jwt(token):
    try:
        # Verificar formato básico
        if not verificar_formato_token(token):
            return False, None, "Formato de token inválido"
        
        # Decodificar y verificar token
        payload = decodificar_jwt_token(token)
        
        # Verificar que el payload contenga los campos requeridos
        campos_requeridos = ['id_usuario', 'nombre_usuario', 'rol', 'exp', 'iat']
        for campo in campos_requeridos:
            if campo not in payload:
                return False, None, f"Campo requerido '{campo}' faltante en el token"
        
        return True, payload, None
        
    except jwt.ExpiredSignatureError:
        return False, None, "El token ha expirado"
    except jwt.InvalidTokenError:
        return False, None, "Token inválido"
    except Exception as e:
        return False, None, f"Error al validar token: {str(e)}"

def generar_token_refresco(payload_actual):
    nuevo_payload = {
        'id_usuario': payload_actual['id_usuario'],
        'nombre_usuario': payload_actual['nombre_usuario'],
        'rol': payload_actual['rol'],
        'nombre_completo': payload_actual.get('nombre_completo', ''),
        'correo': payload_actual.get('correo', ''),
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=EXPIRACION_DEL_TOKEN),
        'iat': datetime.datetime.now(datetime.timezone.utc)
    }
    
    return jwt.encode(nuevo_payload, CLAVE_SECRETA, algorithm=JWT_ALGORITMO)

def obtener_datos_usuario_de_token(token):
    es_valido, payload, _ = validar_token_jwt(token)
    
    if not es_valido:
        return None
    
    return {
        'id': payload['id_usuario'],
        'username': payload['nombre_usuario'],
        'role': payload['rol'],
        'full_name': payload.get('nombre_completo', ''),
        'email': payload.get('correo', '')
    }
