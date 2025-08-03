# app/otp_utils.py
import secrets
import string
import datetime
import re
from .db import get_connection

# Configuración OTP
OTP_LENGTH = 6
OTP_EXPIRATION_MINUTES = 5  # OTP válido por 5 minutos

def generar_otp():
    """Genera un código OTP de 6 dígitos"""
    return ''.join(secrets.choice(string.digits) for _ in range(OTP_LENGTH))

def validar_formato_username_cajero(username):
    """
    Valida que el username del cajero tenga combinación de letras y números
    Al menos una letra y al menos un número
    """
    if not username or len(username) < 3:
        return False, "El nombre de usuario debe tener al menos 3 caracteres"
    
    tiene_letra = any(c.isalpha() for c in username)
    tiene_numero = any(c.isdigit() for c in username)
    
    if not tiene_letra:
        return False, "El nombre de usuario debe contener al menos una letra"
    
    if not tiene_numero:
        return False, "El nombre de usuario debe contener al menos un número"
    
    # Solo permitir letras, números y algunos caracteres especiales básicos
    if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return False, "El nombre de usuario solo puede contener letras, números, guiones, puntos y guiones bajos"
    
    return True, "Username válido"

def validar_password_cajero(password):
    """
    Valida que la contraseña del cajero tenga al menos 10 caracteres
    y acepte letras, números y símbolos
    """
    if not password or len(password) < 10:
        return False, "La contraseña debe tener al menos 10 caracteres"
    
    tiene_letra = any(c.isalpha() for c in password)
    tiene_numero = any(c.isdigit() for c in password)
    
    if not tiene_letra:
        return False, "La contraseña debe contener al menos una letra"
    
    if not tiene_numero:
        return False, "La contraseña debe contener al menos un número"
    
    # Verificar que no tenga caracteres no permitidos (solo ASCII imprimible)
    if not all(32 <= ord(c) <= 126 for c in password):
        return False, "La contraseña contiene caracteres no válidos"
    
    return True, "Contraseña válida"

def generar_y_guardar_otp(cajero_id):
    """
    Genera un nuevo OTP para el cajero y lo guarda en la base de datos
    """
    otp_code = generar_otp()
    expires_at = datetime.datetime.now() + datetime.timedelta(minutes=OTP_EXPIRATION_MINUTES)
    
    conexion = get_connection()
    cursor = conexion.cursor()
    
    try:
        # Actualizar el OTP actual del cajero
        cursor.execute("""
            UPDATE bank.cajeros 
            SET current_otp = %s, otp_expires_at = %s 
            WHERE id = %s
        """, (otp_code, expires_at, cajero_id))
        
        # Guardar en historial de OTPs
        cursor.execute("""
            INSERT INTO bank.otp_history (cajero_id, otp_code, expires_at)
            VALUES (%s, %s, %s)
        """, (cajero_id, otp_code, expires_at))
        
        conexion.commit()
        return otp_code, expires_at
        
    except Exception as e:
        conexion.rollback()
        raise e
    finally:
        cursor.close()
        conexion.close()

def validar_otp(cajero_id, otp_provided):
    """
    Valida el OTP proporcionado para el cajero
    """
    conexion = get_connection()
    cursor = conexion.cursor()
    
    try:
        # Obtener el OTP actual del cajero
        cursor.execute("""
            SELECT current_otp, otp_expires_at 
            FROM bank.cajeros 
            WHERE id = %s
        """, (cajero_id,))
        
        resultado = cursor.fetchone()
        
        if not resultado:
            return False, "Cajero no encontrado"
        
        otp_actual, expires_at = resultado
        
        if not otp_actual:
            return False, "No hay OTP generado para este cajero"
        
        # Verificar si el OTP ha expirado
        if datetime.datetime.now() > expires_at:
            # Limpiar OTP expirado
            cursor.execute("""
                UPDATE bank.cajeros 
                SET current_otp = NULL, otp_expires_at = NULL 
                WHERE id = %s
            """, (cajero_id,))
            conexion.commit()
            return False, "OTP expirado"
        
        # Verificar si el OTP coincide
        if otp_actual != otp_provided:
            return False, "OTP incorrecto"
        
        # OTP válido - limpiar después del uso
        cursor.execute("""
            UPDATE bank.cajeros 
            SET current_otp = NULL, otp_expires_at = NULL, last_login = CURRENT_TIMESTAMP 
            WHERE id = %s
        """, (cajero_id,))
        
        conexion.commit()
        return True, "OTP válido"
        
    except Exception as e:
        conexion.rollback()
        return False, f"Error validando OTP: {str(e)}"
    finally:
        cursor.close()
        conexion.close()

def limpiar_otps_expirados():
    """
    Limpia OTPs expirados de la base de datos
    """
    conexion = get_connection()
    cursor = conexion.cursor()
    
    try:
        # Limpiar OTPs expirados de cajeros
        cursor.execute("""
            UPDATE bank.cajeros 
            SET current_otp = NULL, otp_expires_at = NULL 
            WHERE otp_expires_at < CURRENT_TIMESTAMP
        """)
        
        # Limpiar historial de OTPs antiguos (más de 24 horas)
        cursor.execute("""
            DELETE FROM bank.otp_history 
            WHERE expires_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'
        """)
        
        conexion.commit()
        
    except Exception as e:
        conexion.rollback()
        raise e
    finally:
        cursor.close()
        conexion.close()