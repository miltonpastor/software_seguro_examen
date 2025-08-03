import secrets
from flask import Flask, request, g
from flask_restx import Api, Resource, fields # type: ignore
from functools import wraps
from .db import get_connection, init_db
import logging
from .jwt_utils import *

# Define a simple in-memory token store
tokens = {}

#log = logging.getLogger(__name__)
logging.basicConfig(
     filename="app.log",
     level=logging.DEBUG,
     encoding="utf-8",
     filemode="a",
     format="{asctime} - {levelname} - {message}",
     style="{",
     datefmt="%Y-%m-%d %H:%M",
)

# Configure Swagger security scheme for Bearer tokens
authorizations = {
    'Bearer': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Enter your token in the format **Bearer <token>**"
    }
}

app = Flask(__name__)
api = Api(
    app,
    version='1.0',
    title='Core Bancario API',
    description='API para operaciones bancarias, incluyendo autenticación y operaciones de cuenta.',
    doc='/swagger',  # Swagger UI endpoint
    authorizations=authorizations,
    security='Bearer'
)

# Create namespaces for authentication and bank operations
auth_ns = api.namespace('auth', description='Operaciones de autenticación')
bank_ns = api.namespace('bank', description='Operaciones bancarias')

# Define the expected payload models for Swagger
login_model = auth_ns.model('Login', {
    'username': fields.String(required=True, description='Nombre de usuario', example='user1'),
    'password': fields.String(required=True, description='Contraseña', example='pass1')
})

deposit_model = bank_ns.model('Deposit', {
    'account_number': fields.Integer(required=True, description='Número de cuenta', example=123),
    'amount': fields.Float(required=True, description='Monto a depositar', example=100)
})

withdraw_model = bank_ns.model('Withdraw', {
    'amount': fields.Float(required=True, description='Monto a retirar', example=100)
})

transfer_model = bank_ns.model('Transfer', {
    'target_username': fields.String(required=True, description='Usuario destino', example='user2'),
    'amount': fields.Float(required=True, description='Monto a transferir', example=100)
})

credit_payment_model = bank_ns.model('CreditPayment', {
    'amount': fields.Float(required=True, description='Monto de la compra a crédito', example=100)
})

pay_credit_balance_model = bank_ns.model('PayCreditBalance', {
    'amount': fields.Float(required=True, description='Monto a abonar a la deuda de la tarjeta', example=50)
})

# ---------------- Authentication Endpoints ----------------

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model, validate=True)
    @auth_ns.doc('login')
    def post(self):
        """Inicia sesión y devuelve un token JWT de autenticación."""
        data = api.payload
        nombre_usuario = data.get("username")
        contrasena = data.get("password")
        
        # Registrar intento de login
        logging.info(f"Intento de login para usuario: {nombre_usuario}")
        
        conexion = get_connection()
        cursor = conexion.cursor()
        cursor.execute("SELECT id, username, password, role, full_name, email FROM bank.users WHERE username = %s", (nombre_usuario,))
        usuario = cursor.fetchone()
        
        if usuario and usuario[2] == contrasena:
            # Creamos el arreglo de datos del usuario
            datos_usuario = {
                "id": usuario[0],
                "username": usuario[1],
                "role": usuario[3],
                "full_name": usuario[4],
                "email": usuario[5]
            }
            
            # Generamos el JWT usando la función actualizada
            token_jwt = generate_jwt_token(datos_usuario)
            
            # Guardamos el token en la base de datos para manejo de blacklist
            cursor.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", (token_jwt, usuario[0]))
            conexion.commit()
            cursor.close()
            conexion.close()
            
            logging.info(f"Login exitoso para usuario: {nombre_usuario}")
            return {"message": "Login successful", "token": token_jwt}, 200
        else:
            cursor.close()
            conexion.close()
            logging.warning(f"Credenciales inválidas para usuario: {nombre_usuario}")
            api.abort(401, "Invalid credentials")

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc('logout')
    def post(self):
        """Invalida el token JWT añadiéndolo a la blacklist."""
        header_autorizacion = request.headers.get("Authorization", "")
        
        try:
            # Extraer token del header usando la función utilitaria
            token_jwt = extraer_token_de_header(header_autorizacion)
            
            # Validar el token antes de proceder
            es_valido, payload, mensaje_error = validar_token_jwt(token_jwt)
            
            if not es_valido:
                logging.warning(f"Intento de logout con token inválido: {mensaje_error}")
                api.abort(401, mensaje_error)
            
            # Eliminar token de la base de datos (blacklist)
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM bank.tokens WHERE token = %s", (token_jwt,))
            
            if cursor.rowcount == 0:
                conexion.commit()
                cursor.close()
                conexion.close()
                logging.warning("Intento de logout con token no encontrado en BD")
                api.abort(401, "Token no encontrado")
            
            conexion.commit()
            cursor.close()
            conexion.close()
            
            logging.info(f"Logout exitoso para usuario: {payload.get('nombre_usuario', 'desconocido')}")
            return {"message": "Logout successful"}, 200
            
        except ValueError as e:
            logging.warning(f"Error en header de autorización: {str(e)}")
            api.abort(401, str(e))

# ---------------- Decorador Token-Required ----------------

def token_required(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        header_autorizacion = request.headers.get("Authorization", "")
        
        try:
            # Extraer token del header
            token_jwt = extraer_token_de_header(header_autorizacion)
            logging.debug(f"Token recibido: {token_jwt[:20]}...")
            
            # Validar token JWT
            es_valido, payload, mensaje_error = validar_token_jwt(token_jwt)
            
            if not es_valido:
                logging.warning(f"Token inválido: {mensaje_error}")
                api.abort(401, mensaje_error)
            
            # Verificar que el token esté en la base de datos (no en blacklist)
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("SELECT COUNT(*) FROM bank.tokens WHERE token = %s", (token_jwt,))
            token_existe = cursor.fetchone()[0] > 0
            cursor.close()
            conexion.close()
            
            if not token_existe:
                logging.warning("Token no encontrado en BD o en blacklist")
                api.abort(401, "Token ha sido invalidado")
            
            # Establecer información del usuario en g usando los datos del token
            g.usuario = {
                "id": payload['id_usuario'],
                "username": payload['nombre_usuario'],
                "role": payload['rol'],
                "full_name": payload.get('nombre_completo', ''),
                "email": payload.get('correo', '')
            }
            
            logging.debug(f"Usuario autenticado: {g.usuario['username']}")
            return f(*args, **kwargs)
            
        except ValueError as e:
            logging.warning(f"Error en header de autorización: {str(e)}")
            api.abort(401, str(e))
        except Exception as e:
            logging.error(f"Error en validación de token: {str(e)}")
            api.abort(401, "Error de validación de token")
    
    return decorador

@auth_ns.route('/verificar')
class VerificarToken(Resource):
    @auth_ns.doc('verificar_token')
    @token_required
    def get(self):
        """Verifica si el token JWT es válido y devuelve información del usuario."""
        return {
            "message": "Token es válido",
            "usuario": {
                "id": g.usuario['id'],
                "username": g.usuario['username'],
                "role": g.usuario['role'],
                "full_name": g.usuario['full_name'],
                "email": g.usuario['email']
            }
        }, 200

@auth_ns.route('/refrescar')
class RefrescarToken(Resource):
    @auth_ns.doc('refrescar_token')
    @token_required
    def post(self):
        """Genera un nuevo token JWT para el usuario autenticado."""
        try:
            # Obtener token actual
            header_autorizacion = request.headers.get("Authorization", "")
            token_actual = extraer_token_de_header(header_autorizacion)
            
            # Validar token actual
            es_valido, payload_actual, mensaje_error = validar_token_jwt(token_actual)
            
            if not es_valido:
                api.abort(401, mensaje_error)
            
            # Generar nuevo token usando la función utilitaria
            nuevo_token = generar_token_refresco(payload_actual)
            
            # Actualizar token en base de datos
            conexion = get_connection()
            cursor = conexion.cursor()
            cursor.execute("DELETE FROM bank.tokens WHERE token = %s", (token_actual,))
            cursor.execute("INSERT INTO bank.tokens (token, user_id) VALUES (%s, %s)", 
                         (nuevo_token, g.usuario['id']))
            conexion.commit()
            cursor.close()
            conexion.close()
            
            logging.info(f"Token refrescado para usuario: {g.usuario['username']}")
            return {"message": "Token refrescado exitosamente", "token": nuevo_token}, 200
            
        except Exception as e:
            logging.error(f"Error al refrescar token: {str(e)}")
            api.abort(500, "Error interno al refrescar token")

# ---------------- Banking Operation Endpoints ----------------

@bank_ns.route('/deposit')
class Deposit(Resource):
    @bank_ns.expect(deposit_model, validate=True)
    @bank_ns.doc('deposit')
    @token_required
    def post(self):
        """
        Realiza un depósito en la cuenta especificada.
        Se requiere el número de cuenta y el monto a depositar.
        """
        logging.info(f"Operación de depósito iniciada por usuario: {g.usuario['username']}")
        
        datos = api.payload
        numero_cuenta = datos.get("account_number")
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            logging.warning(f"Monto de depósito inválido: {monto} por usuario: {g.usuario['username']}")
            api.abort(400, "El monto debe ser mayor que cero")
        
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Actualizar la cuenta especificada usando su número de cuenta (clave primaria)
        cursor.execute(
            "UPDATE bank.accounts SET balance = balance + %s WHERE id = %s RETURNING balance",
            (monto, numero_cuenta)
        )
        resultado = cursor.fetchone()
        
        if not resultado:
            conexion.rollback()
            cursor.close()
            conexion.close()
            logging.warning(f"Depósito fallido - Cuenta {numero_cuenta} no encontrada por usuario: {g.usuario['username']}")
            api.abort(404, "Cuenta no encontrada")
        
        nuevo_balance = float(resultado[0])
        conexion.commit()
        cursor.close()
        conexion.close()
        
        logging.info(f"Depósito exitoso: ${monto} a cuenta {numero_cuenta} por usuario: {g.usuario['username']}")
        return {"message": "Depósito exitoso", "new_balance": nuevo_balance}, 200

@bank_ns.route('/withdraw')
class Withdraw(Resource):
    @bank_ns.expect(withdraw_model, validate=True)
    @bank_ns.doc('withdraw')
    @token_required
    def post(self):
        """Realiza un retiro de la cuenta del usuario autenticado."""
        logging.info(f"Operación de retiro iniciada por usuario: {g.usuario['username']}")
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            logging.warning(f"Monto de retiro inválido: {monto} por usuario: {g.usuario['username']}")
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            logging.error(f"Cuenta no encontrada para usuario: {g.usuario['username']}")
            api.abort(404, "Cuenta no encontrada")
        
        balance_actual = float(fila[0])
        
        if balance_actual < monto:
            cursor.close()
            conexion.close()
            logging.warning(f"Fondos insuficientes para retiro: {monto} (balance: {balance_actual}) por usuario: {g.usuario['username']}")
            api.abort(400, "Fondos insuficientes")
        
        cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s RETURNING balance", 
                      (monto, id_usuario))
        nuevo_balance = float(cursor.fetchone()[0])
        conexion.commit()
        cursor.close()
        conexion.close()
        
        logging.info(f"Retiro exitoso: ${monto} por usuario: {g.usuario['username']}")
        return {"message": "Retiro exitoso", "new_balance": nuevo_balance}, 200

@bank_ns.route('/transfer')
class Transfer(Resource):
    @bank_ns.expect(transfer_model, validate=True)
    @bank_ns.doc('transfer')
    @token_required
    def post(self):
        """Transfiere fondos desde la cuenta del usuario autenticado a otra cuenta."""
        logging.info(f"Operación de transferencia iniciada por usuario: {g.usuario['username']}")
        
        datos = api.payload
        usuario_destino = datos.get("target_username")
        monto = datos.get("amount", 0)
        
        if not usuario_destino or monto <= 0:
            logging.warning(f"Datos de transferencia inválidos por usuario: {g.usuario['username']} - destino: {usuario_destino}, monto: {monto}")
            api.abort(400, "Datos inválidos")
        
        if usuario_destino == g.usuario['username']:
            logging.warning(f"Intento de auto-transferencia por usuario: {g.usuario['username']}")
            api.abort(400, "No se puede transferir a la misma cuenta")
        
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Verificar balance del remitente
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.usuario['id'],))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            logging.error(f"Cuenta del remitente no encontrada para usuario: {g.usuario['username']}")
            api.abort(404, "Cuenta del remitente no encontrada")
        
        balance_remitente = float(fila[0])
        
        if balance_remitente < monto:
            cursor.close()
            conexion.close()
            logging.warning(f"Fondos insuficientes para transferencia: {monto} (balance: {balance_remitente}) por usuario: {g.usuario['username']}")
            api.abort(400, "Fondos insuficientes")
        
        # Buscar usuario destino
        cursor.execute("SELECT id FROM bank.users WHERE username = %s", (usuario_destino,))
        usuario_objetivo = cursor.fetchone()
        
        if not usuario_objetivo:
            cursor.close()
            conexion.close()
            logging.warning(f"Usuario destino no encontrado: {usuario_destino} por usuario: {g.usuario['username']}")
            api.abort(404, "Usuario destino no encontrado")
        
        id_usuario_objetivo = usuario_objetivo[0]
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (monto, g.usuario['id']))
            cursor.execute("UPDATE bank.accounts SET balance = balance + %s WHERE user_id = %s", 
                         (monto, id_usuario_objetivo))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (g.usuario['id'],))
            nuevo_balance = float(cursor.fetchone()[0])
            conexion.commit()
            logging.info(f"Transferencia exitosa: ${monto} de {g.usuario['username']} a {usuario_destino}")
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            logging.error(f"Error en transferencia por usuario: {g.usuario['username']} - {str(e)}")
            api.abort(500, f"Error durante la transferencia: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {"message": "Transferencia exitosa", "new_balance": nuevo_balance}, 200

@bank_ns.route('/credit-payment')
class CreditPayment(Resource):
    @bank_ns.expect(credit_payment_model, validate=True)
    @bank_ns.doc('credit_payment')
    @token_required
    def post(self):
        """
        Realiza una compra a crédito:
        - Descuenta el monto de la cuenta.
        - Aumenta la deuda de la tarjeta de crédito.
        """
        logging.info(f"Operación de pago con crédito iniciada por usuario: {g.usuario['username']}")
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            logging.warning(f"Monto de pago con crédito inválido: {monto} por usuario: {g.usuario['username']}")
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            logging.error(f"Cuenta no encontrada para pago con crédito por usuario: {g.usuario['username']}")
            api.abort(404, "Cuenta no encontrada")
        
        balance_cuenta = float(fila[0])
        
        if balance_cuenta < monto:
            cursor.close()
            conexion.close()
            logging.warning(f"Fondos insuficientes para pago con crédito: {monto} (balance: {balance_cuenta}) por usuario: {g.usuario['username']}")
            api.abort(400, "Fondos insuficientes en cuenta")
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (monto, id_usuario))
            cursor.execute("UPDATE bank.credit_cards SET balance = balance + %s WHERE user_id = %s", 
                         (monto, id_usuario))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
            nuevo_balance_cuenta = float(cursor.fetchone()[0])
            cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
            nuevo_balance_credito = float(cursor.fetchone()[0])
            conexion.commit()
            logging.info(f"Pago con crédito exitoso: ${monto} por usuario: {g.usuario['username']}")
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            logging.error(f"Error en pago con crédito por usuario: {g.usuario['username']} - {str(e)}")
            api.abort(500, f"Error procesando compra con tarjeta de crédito: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {
            "message": "Compra con tarjeta de crédito exitosa",
            "account_balance": nuevo_balance_cuenta,
            "credit_card_debt": nuevo_balance_credito
        }, 200

@bank_ns.route('/pay-credit-balance')
class PayCreditBalance(Resource):
    @bank_ns.expect(pay_credit_balance_model, validate=True)
    @bank_ns.doc('pay_credit_balance')
    @token_required
    def post(self):
        """
        Realiza un abono a la deuda de la tarjeta:
        - Descuenta el monto (o el máximo posible) de la cuenta.
        - Reduce la deuda de la tarjeta de crédito.
        """
        logging.info(f"Operación de pago de deuda de crédito iniciada por usuario: {g.usuario['username']}")
        
        datos = api.payload
        monto = datos.get("amount", 0)
        
        if monto <= 0:
            logging.warning(f"Monto de pago de deuda inválido: {monto} por usuario: {g.usuario['username']}")
            api.abort(400, "El monto debe ser mayor que cero")
        
        id_usuario = g.usuario['id']
        conexion = get_connection()
        cursor = conexion.cursor()
        
        # Verificar fondos en cuenta
        cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            logging.error(f"Cuenta no encontrada para pago de deuda por usuario: {g.usuario['username']}")
            api.abort(404, "Cuenta no encontrada")
        
        balance_cuenta = float(fila[0])
        
        if balance_cuenta < monto:
            cursor.close()
            conexion.close()
            logging.warning(f"Fondos insuficientes para pago de deuda: {monto} (balance: {balance_cuenta}) por usuario: {g.usuario['username']}")
            api.abort(400, "Fondos insuficientes en cuenta")
        
        # Obtener deuda actual de tarjeta de crédito
        cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
        fila = cursor.fetchone()
        
        if not fila:
            cursor.close()
            conexion.close()
            logging.error(f"Tarjeta de crédito no encontrada para usuario: {g.usuario['username']}")
            api.abort(404, "Tarjeta de crédito no encontrada")
        
        deuda_credito = float(fila[0])
        pago = min(monto, deuda_credito)
        
        try:
            cursor.execute("UPDATE bank.accounts SET balance = balance - %s WHERE user_id = %s", 
                         (pago, id_usuario))
            cursor.execute("UPDATE bank.credit_cards SET balance = balance - %s WHERE user_id = %s", 
                         (pago, id_usuario))
            cursor.execute("SELECT balance FROM bank.accounts WHERE user_id = %s", (id_usuario,))
            nuevo_balance_cuenta = float(cursor.fetchone()[0])
            cursor.execute("SELECT balance FROM bank.credit_cards WHERE user_id = %s", (id_usuario,))
            nueva_deuda_credito = float(cursor.fetchone()[0])
            conexion.commit()
            logging.info(f"Pago de deuda exitoso: ${pago} por usuario: {g.usuario['username']}")
        except Exception as e:
            conexion.rollback()
            cursor.close()
            conexion.close()
            logging.error(f"Error en pago de deuda por usuario: {g.usuario['username']} - {str(e)}")
            api.abort(500, f"Error procesando pago de deuda de tarjeta: {str(e)}")
        
        cursor.close()
        conexion.close()
        return {
            "message": "Pago de deuda de tarjeta exitoso",
            "account_balance": nuevo_balance_cuenta,
            "credit_card_debt": nueva_deuda_credito
        }, 200

@app.before_first_request
def initialize_db():
    init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

