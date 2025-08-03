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

def generate_jwt_token(user_data):
    """
    Generate a JWT token for a user.
    
    Args:
        user_data (dict): Dictionary containing user information
        
    Returns:
        str: JWT token
    """
    payload = {
        'user_id': user_data['id'],
        'username': user_data['username'],
        'role': user_data['role'],
        'full_name': user_data['full_name'],
        'email': user_data['email'],
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=EXPIRACION_DEL_TOKEN),
        'iat': datetime.datetime.now(datetime.timezone.utc)
    }
    
    return jwt.encode(payload, CLAVE_SECRETA, algorithm=JWT_ALGORITMO)
